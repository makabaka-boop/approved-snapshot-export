"""审计日志：追加写入、哈希链与完整性核对。

每条记录包含严格递增的 ``seq`` 与一条哈希链::

    entry_hash = SHA256(seq | at | actor | action | request_id |
                        chunk_index | result | details_json | prev_hash)

链尾的 ``prev_hash`` 取链头记录的哈希；创世记录的前驱为 64 个 0。
因此任何一条记录被插入、删除或篡改，都会在 :func:`verify_chain`
中表现为链断裂。seq 的单调分配与业务写操作放在同一个
``BEGIN IMMEDIATE`` 事务里，崩溃时同生共死，不会出现"业务成功但
无审计"或"审计悬空"。
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone

GENESIS_PREV = "0" * 64


def now_iso() -> str:
    """UTC ISO-8601 时间戳（微秒精度，显式 Z 后缀）。"""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def compute_entry_hash(*, seq: int, at: str, actor_id: str | None, action: str,
                       request_id: str | None, chunk_index: int | None,
                       result: str, details_json: str, prev_hash: str) -> str:
    """计算单条审计记录的哈希。

    字段以 ``\\x1f``（单元分隔符）拼接，避免字段内容伪造分隔边界；
    details 采用规范 JSON（键排序、无多余空格），保证可复算。
    """
    parts = [
        str(seq),
        at,
        actor_id or "",
        action,
        request_id or "",
        "" if chunk_index is None else str(chunk_index),
        result,
        details_json,
        prev_hash,
    ]
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


def canonical_details(details: dict) -> str:
    return json.dumps(details, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def append_audit(conn: sqlite3.Connection, *, action: str,
                 actor_id: str | None = None, request_id: str | None = None,
                 chunk_index: int | None = None, result: str = "success",
                 details: dict | None = None) -> dict:
    """在**当前事务内**追加一条审计记录并返回其内容。

    调用方必须已经开启事务（本函数不自开事务，以保证审计与业务
    状态原子提交）。
    """
    at = now_iso()
    event_id = uuid.uuid4().hex
    details_json = canonical_details(details or {})

    row = conn.execute(
        "SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    prev_hash = row["entry_hash"] if row else GENESIS_PREV

    cur = conn.execute(
        "SELECT COALESCE(MAX(seq), 0) + 1 AS next_seq FROM audit_log"
    )
    seq = cur.fetchone()["next_seq"]

    entry_hash = compute_entry_hash(
        seq=seq, at=at, actor_id=actor_id, action=action,
        request_id=request_id, chunk_index=chunk_index, result=result,
        details_json=details_json, prev_hash=prev_hash,
    )
    conn.execute(
        """INSERT INTO audit_log
           (seq, event_id, at, actor_id, action, request_id, chunk_index,
            result, details, prev_hash, entry_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (seq, event_id, at, actor_id, action, request_id, chunk_index,
         result, details_json, prev_hash, entry_hash),
    )
    return {
        "seq": seq, "event_id": event_id, "at": at, "actor_id": actor_id,
        "action": action, "request_id": request_id,
        "chunk_index": chunk_index, "result": result, "details": details_json,
        "prev_hash": prev_hash, "entry_hash": entry_hash,
    }


def verify_chain(conn: sqlite3.Connection) -> dict:
    """核对审计链，返回 ``{ok, count, broken_at, reason}``。

    检查项：seq 连续且从 1 开始、prev_hash 依次衔接、entry_hash
    全部可按内容复算、event_id 无重复。
    """
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY seq ASC"
    ).fetchall()
    prev = GENESIS_PREV
    seen_event_ids: set[str] = set()
    for expected_seq, row in enumerate(rows, start=1):
        if row["seq"] != expected_seq:
            return {"ok": False, "count": len(rows), "broken_at": expected_seq,
                    "reason": f"seq gap: expected {expected_seq}, got {row['seq']}"}
        if row["prev_hash"] != prev:
            return {"ok": False, "count": len(rows), "broken_at": row["seq"],
                    "reason": "prev_hash mismatch"}
        if row["event_id"] in seen_event_ids:
            return {"ok": False, "count": len(rows), "broken_at": row["seq"],
                    "reason": "duplicate event_id"}
        seen_event_ids.add(row["event_id"])
        recomputed = compute_entry_hash(
            seq=row["seq"], at=row["at"], actor_id=row["actor_id"],
            action=row["action"], request_id=row["request_id"],
            chunk_index=row["chunk_index"], result=row["result"],
            details_json=row["details"], prev_hash=row["prev_hash"],
        )
        if recomputed != row["entry_hash"]:
            return {"ok": False, "count": len(rows), "broken_at": row["seq"],
                    "reason": "entry_hash mismatch (tampered or corrupted)"}
        prev = row["entry_hash"]
    return {"ok": True, "count": len(rows), "broken_at": None, "reason": None}
