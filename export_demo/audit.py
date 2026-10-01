"""哈希链审计日志。

每条审计记录保存前一条记录的 SHA-256，形成只可追加的链：
任何对历史记录的插入、删除或篡改都会让 ``verify_chain`` 失败。
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

GENESIS_HASH = "0" * 64


def canonical_json(value: Any) -> str:
    """确定性的 JSON 编码：键排序、紧凑分隔、不转义非 ASCII。"""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def hash_entry(
    seq: int,
    ts: str,
    actor: str | None,
    action: str,
    entity: str | None,
    result: str,
    details: Any,
    prev_hash: str,
) -> str:
    payload = canonical_json(
        {
            "seq": seq,
            "ts": ts,
            "actor": actor,
            "action": action,
            "entity": entity,
            "result": result,
            "details": details or {},
            "prev_hash": prev_hash,
        }
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_entry(
    conn,
    *,
    actor: str | None,
    action: str,
    entity: str | None = None,
    result: str = "success",
    details: Any = None,
) -> int:
    """追加一条审计记录。

    调用方必须已经持有写事务（BEGIN IMMEDIATE），
    以保证取 prev_hash 与插入在同一事务内完成，链不会分叉。
    返回新记录的序号。
    """
    row = conn.execute(
        "SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    if row is None:
        seq, prev_hash = 1, GENESIS_HASH
    else:
        seq, prev_hash = row[0] + 1, row[1]

    # 时间戳使用数据库时钟，保证单一真源。
    ts = conn.execute("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')").fetchone()[0]
    entry_hash = hash_entry(
        seq, ts, actor, action, entity, result, details or {}, prev_hash
    )
    conn.execute(
        """
        INSERT INTO audit_log
            (seq, ts, actor, action, entity, result, details, prev_hash, entry_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            seq,
            ts,
            actor,
            action,
            entity,
            result,
            canonical_json(details or {}),
            prev_hash,
            entry_hash,
        ),
    )
    return seq


def verify_chain(conn) -> list[int]:
    """重算整条链，返回第一个断裂点之后的全部异常序号；空列表表示完好。"""
    broken: list[int] = []
    expected_prev = GENESIS_HASH
    rows = conn.execute(
        "SELECT seq, ts, actor, action, entity, result, details, prev_hash, entry_hash "
        "FROM audit_log ORDER BY seq"
    ).fetchall()
    for row in rows:
        seq, ts, actor, action, entity, result, details, prev_hash, entry_hash = row
        if prev_hash != expected_prev:
            broken.append(seq)
            continue
        try:
            detail_value = json.loads(details) if details else {}
        except json.JSONDecodeError:
            broken.append(seq)
            continue
        recomputed = hash_entry(
            seq, ts, actor, action, entity, result, detail_value, prev_hash
        )
        if recomputed != entry_hash:
            broken.append(seq)
        else:
            expected_prev = entry_hash
    return broken


def list_entries(conn, limit: int = 200) -> list[dict]:
    rows = conn.execute(
        "SELECT seq, ts, actor, action, entity, result, details, prev_hash, entry_hash "
        "FROM audit_log ORDER BY seq DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [
        {
            "seq": r[0],
            "ts": r[1],
            "actor": r[2],
            "action": r[3],
            "entity": r[4],
            "result": r[5],
            "details": json.loads(r[6]) if r[6] else {},
            "prev_hash": r[7],
            "entry_hash": r[8],
        }
        for r in rows
    ]
