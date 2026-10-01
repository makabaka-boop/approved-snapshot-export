"""SQLite 存储层：建表、连接管理与事务工具。

并发与重启安全性的关键约定：

* 每个工作线程从 :func:`connect` 取自己的连接（线程内复用）；
* 开启 WAL，读不阻塞写、写不阻塞读；
* 所有"读-判断-写"的关键区都放在 ``BEGIN IMMEDIATE`` 事务里，
  该事务在第一时间获取 RESERVED 锁，使两个并发写事务在判断之前
  就被串行化，从根上消除 TOCTOU 竞争；
* 关键状态转换（approved/frozen、claim、revoke）在同一事务内
  完成并随事务一起 fsync，进程随时崩溃都不会留下半成品；
* 忙等待 ``busy_timeout`` 兜底锁竞争，避免偶发 ``database is locked``。
"""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

SCHEMA = """
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role        TEXT NOT NULL CHECK (role IN ('applicant', 'approver', 'admin'))
);

CREATE TABLE IF NOT EXISTS customers (
    id        TEXT PRIMARY KEY,
    name      TEXT NOT NULL,
    email     TEXT NOT NULL,
    phone     TEXT NOT NULL,
    id_card   TEXT NOT NULL,
    region    TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- 列级遮蔽规则，一行一列；审批时按当时内容冻结。
CREATE TABLE IF NOT EXISTS masking_rules (
    column_name TEXT PRIMARY KEY,
    strategy    TEXT NOT NULL
                CHECK (strategy IN ('plain', 'all_stars', 'name',
                                    'email', 'phone', 'id_card')),
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS export_requests (
    id              TEXT PRIMARY KEY,
    applicant_id    TEXT NOT NULL REFERENCES users(id),
    filter_region   TEXT,
    status          TEXT NOT NULL
                    CHECK (status IN ('pending', 'approved', 'revoked',
                                      'expired')),
    created_at      TEXT NOT NULL,
    approved_at     TEXT,
    approver_id     TEXT REFERENCES users(id),
    -- 冻结的遮蔽规则 JSON：{"email": "email", ...}
    frozen_rules    TEXT,
    -- 审批时完整客户快照 JSON
    frozen_snapshot TEXT,
    total_chunks    INTEGER,
    -- 全部块内容按序拼接后的整体摘要，审批时写入
    full_sha256     TEXT
);

CREATE TABLE IF NOT EXISTS export_chunks (
    id          TEXT PRIMARY KEY,
    request_id  TEXT NOT NULL REFERENCES export_requests(id),
    chunk_index INTEGER NOT NULL,
    content     TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    state       TEXT NOT NULL
                CHECK (state IN ('available', 'claimed', 'revoked')),
    claimed_by  TEXT REFERENCES users(id),
    claimed_at  TEXT,
    UNIQUE (request_id, chunk_index)
);

CREATE TABLE IF NOT EXISTS audit_log (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    TEXT NOT NULL UNIQUE,
    at          TEXT NOT NULL,
    actor_id    TEXT,
    action      TEXT NOT NULL,
    request_id  TEXT,
    chunk_index INTEGER,
    result      TEXT NOT NULL CHECK (result IN ('success', 'denied', 'error')),
    details     TEXT NOT NULL,
    prev_hash   TEXT NOT NULL,
    entry_hash  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_chunks_request ON export_chunks(request_id);
CREATE INDEX IF NOT EXISTS idx_audit_request ON audit_log(request_id);
"""


_local = threading.local()


def _in_txn() -> bool:
    return getattr(_local, "in_txn", False)


def _set_in_txn(value: bool) -> None:
    _local.in_txn = value


def connect(db_path: str | Path) -> sqlite3.Connection:
    """返回当前线程自己的连接（同一线程内复用）。"""
    path = str(db_path)
    conn = getattr(_local, "conn", None)
    if conn is None or getattr(_local, "path", None) != path:
        conn = sqlite3.connect(
            path,
            timeout=30.0,
            isolation_level=None,  # 手动管理事务边界
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = FULL")
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 30000")
        _local.conn = conn
        _local.path = path
    return conn


def reset_thread_connection() -> None:
    """测试辅助：丢弃线程本地连接（例如删除数据库文件后）。"""
    conn = getattr(_local, "conn", None)
    if conn is not None:
        conn.close()
    _local.conn = None
    _local.path = None
    _local.in_txn = False


def transaction(conn: sqlite3.Connection, immediate: bool = True):
    """事务上下文管理器（装饰器形式使用：``with transaction(conn):``）。

    ``immediate=True`` 时发 ``BEGIN IMMEDIATE``，进入事务即拿写锁，
    保证"读取状态→判定→写入"整个关键区对其他写者是原子的。
    正常退出提交；异常默认回滚。

    若异常对象带有 ``persist_audit=True`` 属性（拒绝类业务错误，
    事务内只追加了一条拒绝留痕、未做任何业务变更），则改为提交，
    使"被拒绝的操作"也能在审计中保留下来。
    """
    return _Txn(conn, immediate)


class _Txn:
    def __init__(self, conn: sqlite3.Connection, immediate: bool):
        self.conn = conn
        self.immediate = immediate

    def __enter__(self) -> sqlite3.Connection:
        if _in_txn():
            self._nested = True
            return self.conn
        self._nested = False
        self.conn.execute("BEGIN IMMEDIATE" if self.immediate else "BEGIN")
        _set_in_txn(True)
        return self.conn

    def __exit__(self, exc_type, exc, tb) -> bool:
        if self._nested:
            return False
        try:
            if exc_type is None:
                self.conn.execute("COMMIT")
            elif getattr(exc, "persist_audit", False):
                # 拒绝留痕：事务中只有审计插入，提交后把原异常继续抛出
                self.conn.execute("COMMIT")
            else:
                self.conn.execute("ROLLBACK")
        finally:
            # 无论提交/回滚/还是提交本身又抛异常，都必须复位，
            # 否则线程复用的连接会永远以为自己处在事务中。
            _set_in_txn(False)
        return False


def init_db(db_path: str | Path) -> None:
    """创建表结构（幂等）。"""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=30.0)
    try:
        conn.executescript(SCHEMA)
    finally:
        conn.close()
