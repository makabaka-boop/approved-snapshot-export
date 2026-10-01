"""SQLite 持久化结构、连接管理与初始种子数据。"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
    username    TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS user_permissions (
    username TEXT NOT NULL REFERENCES users(username),
    permission TEXT NOT NULL,
    PRIMARY KEY (username, permission)
);

CREATE TABLE IF NOT EXISTS customers (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    email      TEXT,
    phone      TEXT,
    id_card    TEXT,
    address    TEXT,
    version    INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS masking_rules (
    column_name TEXT PRIMARY KEY,
    mask_mode   TEXT NOT NULL,
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS export_applications (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    applicant    TEXT NOT NULL REFERENCES users(username),
    reason       TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending','approved','revoked')),
    chunk_size   INTEGER NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    decided_at   TEXT
);

CREATE TABLE IF NOT EXISTS approvals (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    application_id INTEGER NOT NULL REFERENCES export_applications(id),
    approver       TEXT NOT NULL REFERENCES users(username),
    decided_at     TEXT NOT NULL,
    decision       TEXT NOT NULL CHECK (decision IN ('approved','revoked')),
    -- 同一申请同一决策只允许一条
    UNIQUE (application_id, decision)
);

-- 一次审批冻结一份快照
CREATE TABLE IF NOT EXISTS snapshots (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    application_id        INTEGER NOT NULL UNIQUE
                          REFERENCES export_applications(id),
    frozen_at             TEXT NOT NULL,
    -- 快照内容与规则的整体指纹，便于核对
    rows_hash             TEXT NOT NULL,
    rules_hash            TEXT NOT NULL,
    header_json           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshot_rows (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id),
    position    INTEGER NOT NULL,
    customer_id INTEGER NOT NULL,
    data_json   TEXT NOT NULL,           -- 冻结时的原始行 JSON
    PRIMARY KEY (snapshot_id, position)
);

CREATE TABLE IF NOT EXISTS snapshot_rules (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id),
    column_name TEXT NOT NULL,
    mask_mode   TEXT NOT NULL,
    position    INTEGER NOT NULL,        -- 列在 CSV 中的固定顺序
    PRIMARY KEY (snapshot_id, column_name)
);

CREATE TABLE IF NOT EXISTS chunks (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    application_id INTEGER NOT NULL REFERENCES export_applications(id),
    chunk_index   INTEGER NOT NULL,
    content       BLOB NOT NULL,         -- 审批时一次性渲染冻结
    content_sha256 TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'available'
                  CHECK (status IN ('available','delivered')),
    claimed_by    TEXT REFERENCES users(username),
    claimed_at    TEXT,
    audit_seq     INTEGER,
    UNIQUE (application_id, chunk_index)
);

CREATE TABLE IF NOT EXISTS audit_log (
    seq        INTEGER PRIMARY KEY,
    ts         TEXT NOT NULL,
    actor      TEXT,
    action     TEXT NOT NULL,
    entity     TEXT,
    result     TEXT NOT NULL,
    details    TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_chunks_app ON chunks(application_id, chunk_index);
"""

# 权限常量
PERM_APPLY = "export.apply"
PERM_APPROVE = "export.approve"
PERM_REVOKE = "export.revoke"
PERM_READ_AUDIT = "audit.read"
PERM_MANAGE_CUSTOMERS = "customers.manage"
PERM_MANAGE_RULES = "rules.manage"
PERM_MANAGE_USERS = "users.manage"

ALL_PERMISSIONS = [
    PERM_APPLY,
    PERM_APPROVE,
    PERM_REVOKE,
    PERM_READ_AUDIT,
    PERM_MANAGE_CUSTOMERS,
    PERM_MANAGE_RULES,
    PERM_MANAGE_USERS,
]


def connect(db_path: str) -> sqlite3.Connection:
    """每个调用拿到独立连接：线程局部、WAL、外键开启、自动提交由我们显式控制。"""
    conn = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA synchronous=FULL")
    return conn


def init_db(db_path: str) -> None:
    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA)
        seed(conn)
    finally:
        conn.close()


@contextmanager
def write_tx(conn):
    """BEGIN IMMEDIATE：立刻获取写锁，把“读-判断-写”变成可串行化的临界区。"""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


# CSV 固定列顺序
CSV_COLUMNS = ["id", "name", "email", "phone", "id_card", "address"]

# 默认遮蔽规则（模拟企业合规策略）
DEFAULT_RULES = {
    "id": "none",
    "name": "full",
    "email": "email",
    "phone": "phone",
    "id_card": "tail4",
    "address": "full",
}

# 演示账号
SEED_USERS = {
    # 申请人：只能申请、领自己的导出
    "alice": ["申请人 Alice", [PERM_APPLY]],
    # 审批人（同时也有申请权，用来验证自审被身份规则挡住）
    "bob": ["审批人 Bob", [PERM_APPLY, PERM_APPROVE]],
    # 合规管理员：可撤销、可看审计
    "carol": ["合规 Carol", [PERM_REVOKE, PERM_READ_AUDIT]],
    # 超级管理员
    "root": ["超级管理员", ALL_PERMISSIONS],
    # 无任何权限的账号，用于越权测试
    "dave": ["普通员工 Dave", []],
}


def seed(conn: sqlite3.Connection) -> None:
    """写入默认遮蔽规则；演示账号在幂等前提下创建。"""
    for col, mode in DEFAULT_RULES.items():
        conn.execute(
            "INSERT INTO masking_rules(column_name, mask_mode) VALUES (?, ?) "
            "ON CONFLICT(column_name) DO NOTHING",
            (col, mode),
        )
    for username, (display_name, perms) in SEED_USERS.items():
        conn.execute(
            "INSERT INTO users(username, display_name) VALUES (?, ?) "
            "ON CONFLICT(username) DO NOTHING",
            (username, display_name),
        )
        for perm in perms:
            conn.execute(
                "INSERT INTO user_permissions(username, permission) VALUES (?, ?) "
                "ON CONFLICT(username, permission) DO NOTHING",
                (username, perm),
            )
