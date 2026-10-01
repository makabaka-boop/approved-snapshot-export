"""业务服务层：申请、审批冻结、分块领取、撤销与审计。

所有关键状态转换都遵循同一模式：

    with transaction(conn):          # BEGIN IMMEDIATE，先拿写锁
        重读状态 -> 权限/状态判定 -> 写入 -> append_audit(...)
    # 退出 with 时 COMMIT（含 fsync）

因此：

* **自审检查与状态翻转为原子操作**——两个审批并发时，后来者必须
  在前者提交之后才能读到 status，不可能双双通过；
* **快照、遮蔽规则、块内容与 approved 状态在同一事务落盘**——
  崩溃不会出现"已批准但没有块"或"块已写但仍 pending"；
* **领取与撤销互斥**——同一把写锁使二者严格串行：撤销先到则
  未领块全部置 revoked（领取得到 410），领取先到则该块永久
  claimed（撤销保留其 claimed 状态，不收回已交付内容）；
* 审计与业务写入同事务，每次操作必有可核对记录（含被拒绝的操作）。
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from typing import Callable, Optional

from . import audit as audit_mod
from .db import connect, init_db, transaction
from .errors import ExportError, forbidden, not_found, unauthorized
from .masking import split_into_chunks

DEFAULT_ROWS_PER_CHUNK = 3


class ExportService:
    def __init__(self, db_path: str, rows_per_chunk: int = DEFAULT_ROWS_PER_CHUNK):
        self.db_path = db_path
        self.rows_per_chunk = rows_per_chunk
        init_db(db_path)

    # -- 基础工具 ---------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        return connect(self.db_path)

    def authenticate(self, user_id: str | None) -> sqlite3.Row:
        """根据 X-User-Id 解析当前用户；失败抛 401。"""
        if not user_id:
            raise unauthorized()
        row = self._conn().execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if row is None:
            raise unauthorized(f"unknown user: {user_id}")
        return row

    @staticmethod
    def _require_role(user: sqlite3.Row, roles: tuple[str, ...], message: str) -> None:
        if user["role"] not in roles:
            raise forbidden(message)

    def _denial(self, conn, *, action: str, actor_id: str, code: str,
                message: str, http_status: int, request_id: str | None = None,
                chunk_index: int | None = None, reason: str = "",
                extra: dict | None = None) -> None:
        """记录拒绝审计并抛出会*提交审计*的业务错误。

        约定：调用点在拒绝之前不得做任何业务写；因此该事务提交后只
        多出一条 ``denied`` 审计记录，业务状态原样不变。
        """
        details = {"reason": reason} if reason else {}
        if extra:
            details.update(extra)
        audit_mod.append_audit(
            conn, action=action, actor_id=actor_id, request_id=request_id,
            chunk_index=chunk_index, result="denied", details=details,
        )
        raise ExportError(code, message, http_status, persist_audit=True)

    @staticmethod
    def _request_to_dict(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "applicant_id": row["applicant_id"],
            "filter_region": row["filter_region"],
            "status": row["status"],
            "created_at": row["created_at"],
            "approved_at": row["approved_at"],
            "approver_id": row["approver_id"],
            "frozen_rules": json.loads(row["frozen_rules"]) if row["frozen_rules"] else None,
            "total_chunks": row["total_chunks"],
            "full_sha256": row["full_sha256"],
            # 快照可能很大，列表/详情默认不回传，需要时走专门方法
            "has_frozen_snapshot": row["frozen_snapshot"] is not None,
        }

    # -- 客户记录与遮蔽规则管理（演示"审批后修改不影响已冻结导出"）-------

    def update_customer(self, actor_id: str, customer_id: str, fields: dict) -> dict:
        user = self.authenticate(actor_id)
        self._require_role(user, ("admin",), "only admin can modify customer records")
        allowed = {"name", "email", "phone", "id_card", "region"}
        sets = {k: v for k, v in fields.items() if k in allowed}
        if not sets:
            raise ExportError("VALIDATION", "no updatable fields supplied", 400)
        conn = self._conn()
        with transaction(conn):
            old = conn.execute(
                "SELECT * FROM customers WHERE id = ?", (customer_id,)
            ).fetchone()
            if old is None:
                raise not_found("customer", customer_id)
            sets["updated_at"] = audit_mod.now_iso()
            assignments = ", ".join(f"{k} = ?" for k in sets)
            params = [*sets.values(), customer_id]
            conn.execute(
                f"UPDATE customers SET {assignments} WHERE id = ?", params
            )
            changes = {k: {"old": old[k], "new": sets[k]} for k in sets if k != "updated_at"}
            audit_mod.append_audit(
                conn, action="customer_updated", actor_id=user["id"],
                result="success",
                details={"customer_id": customer_id, "changes": changes},
            )
        return {"customer_id": customer_id, "updated": sorted(sets.keys())}

    def set_masking_rule(self, actor_id: str, column_name: str, strategy: str) -> dict:
        user = self.authenticate(actor_id)
        self._require_role(user, ("admin",), "only admin can change masking rules")
        valid = {"plain", "all_stars", "name", "email", "phone", "id_card"}
        if column_name not in {"name", "email", "phone", "id_card", "region", "id"}:
            raise ExportError("VALIDATION", f"unknown column: {column_name}", 400)
        if strategy not in valid:
            raise ExportError("VALIDATION", f"unknown strategy: {strategy}", 400)
        conn = self._conn()
        with transaction(conn):
            old = conn.execute(
                "SELECT strategy FROM masking_rules WHERE column_name = ?",
                (column_name,),
            ).fetchone()
            old_strategy = old["strategy"] if old else "plain"
            at = audit_mod.now_iso()
            conn.execute(
                """INSERT INTO masking_rules (column_name, strategy, updated_at)
                   VALUES (?, ?, ?)
                   ON CONFLICT(column_name) DO UPDATE SET
                       strategy = excluded.strategy,
                       updated_at = excluded.updated_at""",
                (column_name, strategy, at),
            )
            audit_mod.append_audit(
                conn, action="masking_rule_updated", actor_id=user["id"],
                result="success",
                details={"column": column_name,
                         "old": old_strategy, "new": strategy},
            )
        return {"column": column_name, "old": old_strategy, "new": strategy}

    # -- 申请 -------------------------------------------------------------

    def create_request(self, actor_id: str, filter_region: str | None = None) -> dict:
        user = self.authenticate(actor_id)
        request_id = "REQ-" + uuid.uuid4().hex[:16]
        conn = self._conn()
        with transaction(conn):
            if filter_region is not None:
                exists = conn.execute(
                    "SELECT 1 FROM customers WHERE region = ? LIMIT 1",
                    (filter_region,),
                ).fetchone()
                if exists is None:
                    raise ExportError(
                        "VALIDATION",
                        f"no customers in region: {filter_region}", 400,
                    )
            at = audit_mod.now_iso()
            conn.execute(
                """INSERT INTO export_requests
                   (id, applicant_id, filter_region, status, created_at)
                   VALUES (?, ?, ?, 'pending', ?)""",
                (request_id, user["id"], filter_region, at),
            )
            audit_mod.append_audit(
                conn, action="request_created", actor_id=user["id"],
                request_id=request_id, result="success",
                details={"filter_region": filter_region},
            )
        return self.get_request(actor_id, request_id)

    def get_request(self, actor_id: str, request_id: str) -> dict:
        user = self.authenticate(actor_id)
        row = self._conn().execute(
            "SELECT * FROM export_requests WHERE id = ?", (request_id,)
        ).fetchone()
        if row is None:
            raise not_found("export request", request_id)
        if user["role"] not in ("admin", "approver") and user["id"] != row["applicant_id"]:
            # 不向无权者泄露存在性
            raise not_found("export request", request_id)
        return self._request_to_dict(row)

    def list_chunks(self, actor_id: str, request_id: str) -> dict:
        """块状态清单（不含内容），供客户端断点续传时核对进度。"""
        user = self.authenticate(actor_id)
        conn = self._conn()
        req = conn.execute(
            "SELECT * FROM export_requests WHERE id = ?", (request_id,)
        ).fetchone()
        if req is None or (
            user["role"] not in ("admin", "approver")
            and user["id"] != req["applicant_id"]
        ):
            raise not_found("export request", request_id)
        rows = conn.execute(
            """SELECT chunk_index, state, claimed_by, claimed_at, sha256
               FROM export_chunks WHERE request_id = ?
               ORDER BY chunk_index ASC""",
            (request_id,),
        ).fetchall()
        return {
            "request_id": request_id,
            "status": req["status"],
            "total_chunks": req["total_chunks"],
            "full_sha256": req["full_sha256"],
            "chunks": [dict(r) for r in rows],
        }

    # -- 审批与冻结 -------------------------------------------------------

    def approve_request(self, actor_id: str, request_id: str,
                        freeze_hook: Optional[Callable[[], None]] = None) -> dict:
        """审批通过：冻结快照与遮蔽规则，生成全部 CSV 块。

        ``freeze_hook`` 仅用于测试：在快照已读、冻结写入未完成、
        且写锁仍持有时被调用，可用来驱动并发修改并观察其被阻塞，
        直到本事务提交。生产代码不传此参数。
        """
        user = self.authenticate(actor_id)
        conn = self._conn()
        with transaction(conn):
            req = conn.execute(
                "SELECT * FROM export_requests WHERE id = ?", (request_id,)
            ).fetchone()
            if req is None:
                raise not_found("export request", request_id)

            # 自审：申请人不能审批自己的申请（优先于一般角色检查，
            # 因为这是更具体的禁令；与状态翻转同事务，无法绕过）
            if req["applicant_id"] == user["id"]:
                self._denial(
                    conn, action="request_approval_denied", actor_id=user["id"],
                    code="SELF_APPROVAL",
                    message="applicant cannot approve their own request",
                    http_status=403, request_id=request_id,
                    reason="self_approval",
                    extra={"applicant_id": req["applicant_id"]},
                )

            # 权限：仅审批人/管理员
            if user["role"] not in ("approver", "admin"):
                self._denial(
                    conn, action="request_approval_denied", actor_id=user["id"],
                    code="FORBIDDEN",
                    message="only approver/admin can approve", http_status=403,
                    request_id=request_id, reason="insufficient_role",
                    extra={"role": user["role"]},
                )

            # 状态判定（并发下第二个审批在此被拒）
            if req["status"] != "pending":
                self._denial(
                    conn, action="request_approval_denied", actor_id=user["id"],
                    code="BAD_STATE",
                    message=f"request is {req['status']}, not pending",
                    http_status=409, request_id=request_id, reason="not_pending",
                    extra={"status": req["status"]},
                )

            # 冻结：读取此刻的遮蔽规则与客户快照。写锁在握，任何并发
            # 修改都被阻塞到本事务提交之后。
            rules = {
                r["column_name"]: r["strategy"]
                for r in conn.execute("SELECT column_name, strategy FROM masking_rules")
            }
            if req["filter_region"] is not None:
                cust_rows = conn.execute(
                    "SELECT * FROM customers WHERE region = ? ORDER BY id ASC",
                    (req["filter_region"],),
                ).fetchall()
            else:
                cust_rows = conn.execute(
                    "SELECT * FROM customers ORDER BY id ASC"
                ).fetchall()
            snapshot = [dict(r) for r in cust_rows]

            if freeze_hook is not None:
                freeze_hook()

            chunks = split_into_chunks(snapshot, rules, self.rows_per_chunk)
            full_sha = hashlib.sha256()
            now = audit_mod.now_iso()
            for index, content in enumerate(chunks):
                chunk_id = f"{request_id}:{index}"
                sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
                full_sha.update(content.encode("utf-8"))
                conn.execute(
                    """INSERT INTO export_chunks
                       (id, request_id, chunk_index, content, sha256, state)
                       VALUES (?, ?, ?, ?, ?, 'available')""",
                    (chunk_id, request_id, index, content, sha),
                )
            full_sha256 = full_sha.hexdigest()
            conn.execute(
                """UPDATE export_requests SET
                       status = 'approved', approver_id = ?, approved_at = ?,
                       frozen_rules = ?, frozen_snapshot = ?,
                       total_chunks = ?, full_sha256 = ?
                   WHERE id = ?""",
                (user["id"], now,
                 json.dumps(rules, ensure_ascii=False, sort_keys=True),
                 json.dumps(snapshot, ensure_ascii=False, sort_keys=True),
                 len(chunks), full_sha256, request_id),
            )
            audit_mod.append_audit(
                conn, action="request_approved", actor_id=user["id"],
                request_id=request_id, result="success",
                details={"approver_id": user["id"],
                         "total_chunks": len(chunks),
                         "rows": len(snapshot),
                         "frozen_rules": rules,
                         "full_sha256": full_sha256},
            )
        return self.get_request(actor_id, request_id)

    # -- 领取 -------------------------------------------------------------

    def claim_chunk(self, actor_id: str, request_id: str, chunk_index: int) -> dict:
        """领取一个块。对同一块的重复领取是幂等的：返回冻结的同一批
        字节与同一个摘要，并如实记录重复领取审计。"""
        user = self.authenticate(actor_id)
        conn = self._conn()
        with transaction(conn):
            req = conn.execute(
                "SELECT * FROM export_requests WHERE id = ?", (request_id,)
            ).fetchone()
            if req is None:
                raise not_found("export request", request_id)
            if user["id"] != req["applicant_id"] and user["role"] != "admin":
                self._denial(
                    conn, action="chunk_claim_denied", actor_id=user["id"],
                    code="FORBIDDEN", message="only the applicant can claim chunks",
                    http_status=403, request_id=request_id,
                    chunk_index=chunk_index, reason="not_owner",
                )

            chunk = conn.execute(
                "SELECT * FROM export_chunks WHERE request_id = ? AND chunk_index = ?",
                (request_id, chunk_index),
            ).fetchone()
            if chunk is None:
                if req["status"] in ("pending", "expired"):
                    self._denial(
                        conn, action="chunk_claim_denied", actor_id=user["id"],
                        code="BAD_STATE",
                        message=f"request is {req['status']}", http_status=409,
                        request_id=request_id, chunk_index=chunk_index,
                        reason="request_not_approved",
                        extra={"status": req["status"]},
                    )
                raise not_found("chunk", f"{request_id}:{chunk_index}")

            # 状态机：available -> claimed；revoked 终态；claimed 幂等
            if chunk["state"] == "revoked":
                self._denial(
                    conn, action="chunk_claim_denied", actor_id=user["id"],
                    code="CHUNK_REVOKED",
                    message="chunk was revoked before delivery", http_status=410,
                    request_id=request_id, chunk_index=chunk_index,
                    reason="chunk_revoked",
                )

            repeated = chunk["state"] == "claimed"
            if repeated:
                if chunk["claimed_by"] != user["id"] and user["role"] != "admin":
                    self._denial(
                        conn, action="chunk_claim_denied", actor_id=user["id"],
                        code="FORBIDDEN",
                        message="chunk already claimed by another user",
                        http_status=403, request_id=request_id,
                        chunk_index=chunk_index, reason="claimed_by_other",
                        extra={"claimed_by": chunk["claimed_by"]},
                    )
                # 幂等重取：返回冻结内容，绝不重新渲染
                audit_mod.append_audit(
                    conn, action="chunk_reclaimed", actor_id=user["id"],
                    request_id=request_id, chunk_index=chunk_index,
                    result="success",
                    details={"repeat": True,
                             "first_claimed_at": chunk["claimed_at"],
                             "first_claimed_by": chunk["claimed_by"]},
                )
                delivered = False
            else:
                at = audit_mod.now_iso()
                conn.execute(
                    """UPDATE export_chunks
                       SET state = 'claimed', claimed_by = ?, claimed_at = ?
                       WHERE id = ? AND state = 'available'""",
                    (user["id"], at, chunk["id"]),
                )
                audit_mod.append_audit(
                    conn, action="chunk_claimed", actor_id=user["id"],
                    request_id=request_id, chunk_index=chunk_index,
                    result="success",
                    details={"sha256": chunk["sha256"]},
                )
                delivered = True

            return {
                "request_id": request_id,
                "chunk_index": chunk_index,
                "state": "claimed",
                "content": chunk["content"],
                "sha256": chunk["sha256"],
                "repeated": repeated,
                "delivered_now": delivered,
                "total_chunks": req["total_chunks"],
            }

    # -- 撤销 -------------------------------------------------------------

    def revoke_approval(self, actor_id: str, request_id: str) -> dict:
        """撤销审批：只阻止尚未领取的块。

        原子完成两件事：request -> revoked；所有 available 块 ->
        revoked。已 claimed 的块状态与冻结内容原样保留（系统不声称
        收回已交付内容），申请人仍可凭幂等领取重新下载同一字节。
        """
        user = self.authenticate(actor_id)
        conn = self._conn()
        with transaction(conn):
            req = conn.execute(
                "SELECT * FROM export_requests WHERE id = ?", (request_id,)
            ).fetchone()
            if req is None:
                raise not_found("export request", request_id)
            if user["id"] == req["applicant_id"]:
                self._denial(
                    conn, action="approval_revoke_denied", actor_id=user["id"],
                    code="FORBIDDEN", message="applicant cannot revoke approval",
                    http_status=403, request_id=request_id,
                    reason="applicant_revoke_own",
                )
            if user["role"] not in ("admin", "approver"):
                self._denial(
                    conn, action="approval_revoke_denied", actor_id=user["id"],
                    code="FORBIDDEN", message="only approver/admin can revoke",
                    http_status=403, request_id=request_id,
                    reason="insufficient_role", extra={"role": user["role"]},
                )
            if req["status"] == "pending":
                self._denial(
                    conn, action="approval_revoke_denied", actor_id=user["id"],
                    code="BAD_STATE", message="request is not approved",
                    http_status=409, request_id=request_id, reason="not_approved",
                )
            if req["status"] == "revoked":
                self._denial(
                    conn, action="approval_revoke_denied", actor_id=user["id"],
                    code="BAD_STATE", message="request already revoked",
                    http_status=409, request_id=request_id,
                    reason="already_revoked",
                )

            # 与领取事务竞争同一把 IMMEDIATE 写锁：在我们拿到锁之后、
            # 提交之前，任何领取都不可能插进来。
            cur = conn.execute(
                """UPDATE export_chunks SET state = 'revoked'
                   WHERE request_id = ? AND state = 'available'""",
                (request_id,),
            )
            blocked = cur.rowcount
            claimed = conn.execute(
                "SELECT COUNT(*) AS c FROM export_chunks WHERE request_id = ? AND state = 'claimed'",
                (request_id,),
            ).fetchone()["c"]
            conn.execute(
                "UPDATE export_requests SET status = 'revoked' WHERE id = ?",
                (request_id,),
            )
            audit_mod.append_audit(
                conn, action="approval_revoked", actor_id=user["id"],
                request_id=request_id, result="success",
                details={"chunks_blocked": blocked,
                         "chunks_already_claimed": claimed,
                         "note": "delivered chunks are not reclaimed"},
            )
        return {"request_id": request_id, "status": "revoked",
                "chunks_blocked": blocked,
                "chunks_already_claimed": claimed}

    # -- 审计 -------------------------------------------------------------

    def list_audit(self, actor_id: str, request_id: str | None = None) -> list[dict]:
        user = self.authenticate(actor_id)
        self._require_role(user, ("admin", "approver"),
                           "only approver/admin can read audit log")
        conn = self._conn()
        if request_id:
            rows = conn.execute(
                "SELECT * FROM audit_log WHERE request_id = ? ORDER BY seq ASC",
                (request_id,),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM audit_log ORDER BY seq ASC").fetchall()
        return [
            {
                "seq": r["seq"], "event_id": r["event_id"], "at": r["at"],
                "actor_id": r["actor_id"], "action": r["action"],
                "request_id": r["request_id"], "chunk_index": r["chunk_index"],
                "result": r["result"], "details": json.loads(r["details"]),
                "entry_hash": r["entry_hash"],
            }
            for r in rows
        ]

    def verify_audit(self, actor_id: str) -> dict:
        user = self.authenticate(actor_id)
        self._require_role(user, ("admin",), "only admin can verify audit chain")
        return audit_mod.verify_chain(self._conn())
