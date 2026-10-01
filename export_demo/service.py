"""导出领域服务：申请、审批冻结、分块领取、撤销，全部走 SQLite 事务。

并发正确性完全建立在 ``BEGIN IMMEDIATE`` 写事务之上：每个状态转换都是
数据库级的原子比较与设置，不依赖进程内锁，因此多个工作进程以及服务重启
都不会破坏不变量。
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from . import audit as audit_mod
from .errors import (
    ApiError,
    AuthError,
    ForbiddenError,
    InvalidStateError,
    NotFoundError,
    PermissionError_,
    ValidationError,
)
from .masking import ALL_MODES
from .render import content_fingerprint, render_chunk, sha256_hex, split_ordered
from .schema import (
    CSV_COLUMNS,
    PERM_APPLY,
    PERM_APPROVE,
    PERM_MANAGE_CUSTOMERS,
    PERM_MANAGE_RULES,
    PERM_MANAGE_USERS,
    PERM_READ_AUDIT,
    PERM_REVOKE,
    connect,
    init_db,
    write_tx,
)

# 写冲突时的有限重试（SQLITE_BUSY 在串行写场景下理论上极少出现）
_MAX_WRITE_ATTEMPTS = 50


@dataclass(frozen=True)
class ChunkDelivery:
    application_id: int
    chunk_index: int
    chunk_count: int
    content: bytes
    content_sha256: str
    status: str  # delivered（本次或此前已交付）
    repeated: bool  # True 表示这是一次重复领取


class _RollbackDeny(Exception):
    """事务内发现必须拒绝的情况：先回滚，再在事务外补审计。"""

    def __init__(self, reason: str, message: str, exc_cls: type[ApiError]):
        self.reason = reason
        self.message = message
        self.exc_cls = exc_cls


class ExportService:
    def __init__(self, db_path: str):
        self.db_path = db_path
        init_db(db_path)

    # ---------------------------------------------------------------- 内部工具

    def _conn(self) -> sqlite3.Connection:
        return connect(self.db_path)

    def _load_actor(self, username: str | None) -> sqlite3.Row:
        if not username:
            raise AuthError("缺少调用方身份")
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT username FROM users WHERE username = ?", (username,)
            ).fetchone()
            if row is None:
                raise AuthError(f"未知用户: {username}")
            return row
        finally:
            conn.close()

    def _permissions(self, conn: sqlite3.Connection, username: str) -> set[str]:
        return {
            r[0]
            for r in conn.execute(
                "SELECT permission FROM user_permissions WHERE username = ?",
                (username,),
            )
        }

    def _require(self, actor: str, perm: str, action: str, entity: str | None = None):
        """权限闸：失败也留下审计记录（可核对的越权尝试）。"""
        self._load_actor(actor)
        conn = self._conn()
        try:
            perms = self._permissions(conn, actor)
        finally:
            conn.close()
        if perm not in perms:
            self._deny(actor, action, entity, "missing_permission",
                       f"缺少权限 {perm}", PermissionError_)

    def _deny(self, actor, action, entity, reason, message, exc_cls):
        conn = self._conn()
        try:
            with write_tx(conn):
                audit_mod.append_entry(
                    conn,
                    actor=actor,
                    action=action,
                    entity=entity,
                    result="denied",
                    details={"reason": reason, "message": message},
                )
        finally:
            conn.close()
        raise exc_cls(message)

    def _run_write_tx(self, work):
        """执行一个写事务回调，遇到 SQLITE_BUSY/锁冲突时重试。"""
        last_error: Exception | None = None
        for _ in range(_MAX_WRITE_ATTEMPTS):
            conn = self._conn()
            try:
                with write_tx(conn):
                    return work(conn)
            except sqlite3.OperationalError as exc:  # database is locked
                last_error = exc
                continue
            finally:
                conn.close()
        raise InvalidStateError(f"写冲突，稍后重试: {last_error}")

    # ---------------------------------------------------------------- 用户/权限

    def create_user(self, actor: str, username: str, display_name: str) -> None:
        self._require(actor, PERM_MANAGE_USERS, "USER_CREATE", username)
        username = (username or "").strip()
        if not username:
            raise ValidationError("用户名不能为空")

        def work(conn):
            exists = conn.execute(
                "SELECT 1 FROM users WHERE username = ?", (username,)
            ).fetchone()
            if exists:
                raise ValidationError(f"用户已存在: {username}")
            conn.execute(
                "INSERT INTO users(username, display_name) VALUES (?, ?)",
                (username, display_name),
            )
            audit_mod.append_entry(
                conn, actor=actor, action="USER_CREATED",
                entity=username, details={"display_name": display_name},
            )

        self._run_write_tx(work)

    def grant_permission(self, actor: str, username: str, permission: str) -> None:
        self._require(actor, PERM_MANAGE_USERS, "PERMISSION_GRANT", username)

        def work(conn):
            if not conn.execute(
                "SELECT 1 FROM users WHERE username = ?", (username,)
            ).fetchone():
                raise NotFoundError(f"未知用户: {username}")
            conn.execute(
                "INSERT INTO user_permissions(username, permission) VALUES (?, ?) "
                "ON CONFLICT(username, permission) DO NOTHING",
                (username, permission),
            )
            audit_mod.append_entry(
                conn, actor=actor, action="PERMISSION_GRANTED",
                entity=username, details={"permission": permission},
            )

        self._run_write_tx(work)

    # ---------------------------------------------------------------- 客户数据 / 规则

    def upsert_customer(
        self,
        actor: str,
        *,
        customer_id: int | None,
        name: str,
        email: str | None = None,
        phone: str | None = None,
        id_card: str | None = None,
        address: str | None = None,
    ) -> int:
        self._require(actor, PERM_MANAGE_CUSTOMERS, "CUSTOMER_UPSERT",
                      str(customer_id) if customer_id is not None else None)
        if not name:
            raise ValidationError("客户姓名不能为空")

        def work(conn):
            if customer_id is None:
                cur = conn.execute(
                    "INSERT INTO customers(name, email, phone, id_card, address) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (name, email, phone, id_card, address),
                )
                new_id = cur.lastrowid
                audit_mod.append_entry(
                    conn, actor=actor, action="CUSTOMER_CREATED",
                    entity=f"customer:{new_id}",
                    details={"name": name},
                )
            else:
                row = conn.execute(
                    "SELECT id, version FROM customers WHERE id = ?", (customer_id,)
                ).fetchone()
                if row is None:
                    raise NotFoundError(f"客户不存在: {customer_id}")
                conn.execute(
                    "UPDATE customers SET name=?, email=?, phone=?, id_card=?, "
                    "address=?, version=version+1, "
                    "updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?",
                    (name, email, phone, id_card, address, customer_id),
                )
                new_id = customer_id
                audit_mod.append_entry(
                    conn, actor=actor, action="CUSTOMER_UPDATED",
                    entity=f"customer:{new_id}",
                    details={"version_after": row["version"] + 1},
                )
            return new_id

        return self._run_write_tx(work)

    def set_masking_rule(self, actor: str, column_name: str, mask_mode: str) -> None:
        self._require(actor, PERM_MANAGE_RULES, "RULE_CHANGE", column_name)
        if column_name not in CSV_COLUMNS:
            raise ValidationError(f"未知列: {column_name}")
        if mask_mode not in ALL_MODES:
            raise ValidationError(f"未知遮蔽方式: {mask_mode}")

        def work(conn):
            conn.execute(
                "INSERT INTO masking_rules(column_name, mask_mode, updated_at) "
                "VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now')) "
                "ON CONFLICT(column_name) DO UPDATE SET "
                "mask_mode=excluded.mask_mode, updated_at=excluded.updated_at",
                (column_name, mask_mode),
            )
            audit_mod.append_entry(
                conn, actor=actor, action="RULE_CHANGED",
                entity=f"rule:{column_name}",
                details={"column": column_name, "mask_mode": mask_mode},
            )

        self._run_write_tx(work)

    # ---------------------------------------------------------------- 申请

    def apply_export(self, actor: str, reason: str, chunk_size: int = 2) -> int:
        self._require(actor, PERM_APPLY, "EXPORT_APPLY")
        reason = (reason or "").strip()
        if not reason:
            raise ValidationError("申请理由不能为空")
        if not isinstance(chunk_size, int) or chunk_size <= 0:
            raise ValidationError("chunk_size 必须为正整数")
        if chunk_size > 10_000:
            raise ValidationError("chunk_size 过大")

        def work(conn):
            cur = conn.execute(
                "INSERT INTO export_applications(applicant, reason, chunk_size) "
                "VALUES (?, ?, ?)",
                (actor, reason, chunk_size),
            )
            app_id = cur.lastrowid
            audit_mod.append_entry(
                conn, actor=actor, action="EXPORT_APPLIED",
                entity=f"export:{app_id}",
                details={"reason": reason, "chunk_size": chunk_size},
            )
            return app_id

        return self._run_write_tx(work)

    # ---------------------------------------------------------------- 审批（冻结快照）

    def approve_export(self, actor: str, application_id: int) -> dict:
        self._require(actor, PERM_APPROVE, "EXPORT_APPROVE", f"export:{application_id}")

        def work(conn):
            app = conn.execute(
                "SELECT id, applicant, status, chunk_size FROM export_applications "
                "WHERE id = ?",
                (application_id,),
            ).fetchone()
            if app is None:
                raise _RollbackDeny(
                    "not_found", f"导出申请不存在: {application_id}", NotFoundError
                )
            # 身份规则：申请人永远不能审批自己的申请，即便同时拥有审批权限
            if app["applicant"] == actor:
                raise _RollbackDeny(
                    "self_approval",
                    "申请人不能审批自己的申请",
                    ForbiddenError,
                )
            if app["status"] != "pending":
                raise _RollbackDeny(
                    f"already_{app['status']}",
                    f"申请当前状态为 {app['status']}，无法审批",
                    InvalidStateError,
                )

            frozen_at = conn.execute(
                "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')"
            ).fetchone()[0]

            # —— 在同一写事务内冻结数据行与规则 ——
            customer_rows = conn.execute(
                "SELECT id, name, email, phone, id_card, address, version "
                "FROM customers ORDER BY id"
            ).fetchall()
            rule_rows = conn.execute(
                "SELECT column_name, mask_mode FROM masking_rules ORDER BY column_name"
            ).fetchall()

            cur = conn.execute(
                "INSERT INTO snapshots(application_id, frozen_at, rows_hash, "
                "rules_hash, header_json) VALUES (?, ?, ?, ?, ?)",
                (
                    application_id,
                    frozen_at,
                    "",  # 占位，拿到 snapshot id 后回填
                    "",
                    json.dumps(CSV_COLUMNS, ensure_ascii=False),
                ),
            )
            snapshot_id = cur.lastrowid

            frozen_rows: list[dict] = []
            for pos, r in enumerate(customer_rows):
                data = {
                    "id": r["id"],
                    "name": r["name"],
                    "email": r["email"],
                    "phone": r["phone"],
                    "id_card": r["id_card"],
                    "address": r["address"],
                    "version": r["version"],
                }
                frozen_rows.append(data)
                conn.execute(
                    "INSERT INTO snapshot_rows(snapshot_id, position, customer_id, "
                    "data_json) VALUES (?, ?, ?, ?)",
                    (
                        snapshot_id,
                        pos,
                        r["id"],
                        audit_mod.canonical_json(data),
                    ),
                )

            rules: dict[str, str] = {}
            for pos, r in enumerate(rule_rows):
                rules[r["column_name"]] = r["mask_mode"]
                conn.execute(
                    "INSERT INTO snapshot_rules(snapshot_id, column_name, mask_mode, "
                    "position) VALUES (?, ?, ?, ?)",
                    (snapshot_id, r["column_name"], r["mask_mode"], pos),
                )
            # 快照里没有规则的列按最保守方式遮蔽
            effective_rules = {col: rules.get(col, "full") for col in CSV_COLUMNS}

            rows_hash = content_fingerprint(
                audit_mod.canonical_json(row).encode("utf-8") for row in frozen_rows
            )
            rules_fingerprint = content_fingerprint(
                audit_mod.canonical_json(
                    {"column": c, "mask_mode": effective_rules[c]}
                ).encode("utf-8")
                for c in CSV_COLUMNS
            )
            conn.execute(
                "UPDATE snapshots SET rows_hash=?, rules_hash=? WHERE id=?",
                (rows_hash, rules_fingerprint, snapshot_id),
            )

            # —— 审批时一次性渲染全部 CSV 块并冻结字节 ——
            groups = split_ordered(frozen_rows, app["chunk_size"])
            if not groups:
                groups = [[]]  # 空数据也至少交付一个只含表头的第 0 块
            blobs: list[bytes] = []
            for index, group in enumerate(groups):
                content = render_chunk(
                    group,
                    CSV_COLUMNS,
                    effective_rules,
                    include_header=(index == 0),
                )
                blobs.append(content)
                conn.execute(
                    "INSERT INTO chunks(application_id, chunk_index, content, "
                    "content_sha256, status) VALUES (?, ?, ?, ?, 'available')",
                    (application_id, index, content, sha256_hex(content)),
                )

            conn.execute(
                "UPDATE export_applications SET status='approved', decided_at=? "
                "WHERE id=? AND status='pending'",
                (frozen_at, application_id),
            )
            conn.execute(
                "INSERT INTO approvals(application_id, approver, decided_at, decision) "
                "VALUES (?, ?, ?, 'approved')",
                (application_id, actor, frozen_at),
            )
            audit_mod.append_entry(
                conn, actor=actor, action="EXPORT_APPROVED",
                entity=f"export:{application_id}",
                details={
                    "snapshot_id": snapshot_id,
                    "frozen_at": frozen_at,
                    "row_count": len(frozen_rows),
                    "chunk_count": len(blobs),
                    "rows_hash": rows_hash,
                    "rules_hash": rules_fingerprint,
                },
            )
            return {
                "application_id": application_id,
                "snapshot_id": snapshot_id,
                "frozen_at": frozen_at,
                "chunk_count": len(blobs),
                "rows_hash": rows_hash,
                "rules_hash": rules_fingerprint,
            }

        try:
            return self._run_write_tx(work)
        except _RollbackDeny as deny:
            self._deny(
                actor, "EXPORT_APPROVE", f"export:{application_id}",
                deny.reason, deny.message, deny.exc_cls,
            )

    # ---------------------------------------------------------------- 撤销

    def revoke_export(self, actor: str, application_id: int) -> dict:
        self._require(actor, PERM_REVOKE, "EXPORT_REVOKE", f"export:{application_id}")

        def work(conn):
            app = conn.execute(
                "SELECT id, status FROM export_applications WHERE id=?",
                (application_id,),
            ).fetchone()
            if app is None:
                raise _RollbackDeny(
                    "not_found", f"导出申请不存在: {application_id}", NotFoundError
                )
            if app["status"] == "pending":
                raise _RollbackDeny(
                    "not_approved",
                    "申请尚未审批通过，无需撤销（请走驳回流程）",
                    InvalidStateError,
                )
            if app["status"] == "revoked":
                raise _RollbackDeny(
                    "already_revoked", "该导出已处于撤销状态", InvalidStateError
                )

            decided_at = conn.execute(
                "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')"
            ).fetchone()[0]
            # 只翻转尚未领取的块的可领取性：已交付的块保持 delivered，
            # 申请人仍可重复领取完全相同的内容（不声称收回）。
            blocked = conn.execute(
                "SELECT COUNT(*) FROM chunks WHERE application_id=? AND status='available'",
                (application_id,),
            ).fetchone()[0]
            delivered = conn.execute(
                "SELECT COUNT(*) FROM chunks WHERE application_id=? AND status='delivered'",
                (application_id,),
            ).fetchone()[0]
            conn.execute(
                "UPDATE export_applications SET status='revoked', decided_at=? "
                "WHERE id=? AND status='approved'",
                (decided_at, application_id),
            )
            conn.execute(
                "INSERT INTO approvals(application_id, approver, decided_at, decision) "
                "VALUES (?, ?, ?, 'revoked')",
                (application_id, actor, decided_at),
            )
            audit_mod.append_entry(
                conn, actor=actor, action="EXPORT_REVOKED",
                entity=f"export:{application_id}",
                details={
                    "blocked_undelivered": blocked,
                    "already_delivered": delivered,
                },
            )
            return {
                "application_id": application_id,
                "blocked_undelivered": blocked,
                "already_delivered": delivered,
            }

        try:
            return self._run_write_tx(work)
        except _RollbackDeny as deny:
            self._deny(
                actor, "EXPORT_REVOKE", f"export:{application_id}",
                deny.reason, deny.message, deny.exc_cls,
            )

    # ---------------------------------------------------------------- 查询 / 领取

    def get_application(self, actor: str, application_id: int) -> dict:
        self._load_actor(actor)
        conn = self._conn()
        try:
            perms = self._permissions(conn, actor)
            app = conn.execute(
                "SELECT * FROM export_applications WHERE id=?", (application_id,)
            ).fetchone()
            if app is None:
                raise NotFoundError(f"导出申请不存在: {application_id}")
            privileged = bool(
                perms
                & {PERM_APPROVE, PERM_REVOKE, PERM_READ_AUDIT}
            )
            if app["applicant"] != actor and not privileged:
                self._deny(
                    actor, "EXPORT_VIEW", f"export:{application_id}",
                    "not_owner", "只能查看自己的导出申请", ForbiddenError,
                )
            chunks = conn.execute(
                "SELECT chunk_index, status, content_sha256, claimed_by, claimed_at "
                "FROM chunks WHERE application_id=? ORDER BY chunk_index",
                (application_id,),
            ).fetchall()
            snapshot = conn.execute(
                "SELECT id, frozen_at, rows_hash, rules_hash FROM snapshots "
                "WHERE application_id=?",
                (application_id,),
            ).fetchone()
            return {
                "id": app["id"],
                "applicant": app["applicant"],
                "reason": app["reason"],
                "status": app["status"],
                "chunk_size": app["chunk_size"],
                "created_at": app["created_at"],
                "decided_at": app["decided_at"],
                "snapshot": dict(snapshot) if snapshot else None,
                "chunks": [dict(c) for c in chunks],
            }
        finally:
            conn.close()

    def list_applications(self, actor: str) -> list[dict]:
        self._load_actor(actor)
        conn = self._conn()
        try:
            perms = self._permissions(conn, actor)
            privileged = bool(
                perms & {PERM_APPROVE, PERM_REVOKE, PERM_READ_AUDIT}
            )
            if privileged:
                rows = conn.execute(
                    "SELECT id, applicant, reason, status, created_at, decided_at "
                    "FROM export_applications ORDER BY id"
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT id, applicant, reason, status, created_at, decided_at "
                    "FROM export_applications WHERE applicant=? ORDER BY id",
                    (actor,),
                ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def claim_chunk(
        self, actor: str, application_id: int, chunk_index: int
    ) -> ChunkDelivery:
        self._load_actor(actor)

        def work(conn):
            app = conn.execute(
                "SELECT id, applicant, status FROM export_applications WHERE id=?",
                (application_id,),
            ).fetchone()
            if app is None:
                raise _RollbackDeny(
                    "not_found", f"导出申请不存在: {application_id}", NotFoundError
                )
            if app["applicant"] != actor:
                raise _RollbackDeny(
                    "not_owner",
                    "只能领取自己申请的导出块",
                    ForbiddenError,
                )
            chunk = conn.execute(
                "SELECT chunk_index, content, content_sha256, status FROM chunks "
                "WHERE application_id=? AND chunk_index=?",
                (application_id, chunk_index),
            ).fetchone()
            if chunk is None:
                raise _RollbackDeny(
                    "bad_chunk",
                    f"块序号不存在: {chunk_index}",
                    NotFoundError,
                )

            total = conn.execute(
                "SELECT COUNT(*) FROM chunks WHERE application_id=?",
                (application_id,),
            ).fetchone()[0]

            # 已交付的块在撤销后依旧可重复领取：已交付内容不收回
            if chunk["status"] == "delivered":
                seq = audit_mod.append_entry(
                    conn, actor=actor, action="CHUNK_CLAIMED",
                    entity=f"export:{application_id}/chunk:{chunk_index}",
                    result="success",
                    details={
                        "chunk_index": chunk_index,
                        "repeated": True,
                        "sha256": chunk["content_sha256"],
                        "application_status": app["status"],
                    },
                )
                conn.execute(
                    "UPDATE chunks SET audit_seq=? WHERE application_id=? "
                    "AND chunk_index=?",
                    (seq, application_id, chunk_index),
                )
                return ChunkDelivery(
                    application_id, chunk_index, total,
                    chunk["content"], chunk["content_sha256"],
                    "delivered", True,
                )

            # 未交付的块遇到撤销：只阻止，不修改内容
            if app["status"] == "revoked":
                raise _RollbackDeny(
                    "revoked",
                    "导出已被撤销，该块尚未领取，无法再交付",
                    InvalidStateError,
                )

            claimed_at = conn.execute(
                "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')"
            ).fetchone()[0]
            # 原子的 available -> delivered 状态转换（WHERE status='available' 兜底）
            cur = conn.execute(
                "UPDATE chunks SET status='delivered', claimed_by=?, claimed_at=? "
                "WHERE application_id=? AND chunk_index=? AND status='available'",
                (actor, claimed_at, application_id, chunk_index),
            )
            if cur.rowcount != 1:
                # 被并发的另一个请求抢先交付
                raise _RollbackDeny(
                    "contended", "块状态刚被并发请求改变，请重试", InvalidStateError
                )
            seq = audit_mod.append_entry(
                conn, actor=actor, action="CHUNK_CLAIMED",
                entity=f"export:{application_id}/chunk:{chunk_index}",
                result="success",
                details={
                    "chunk_index": chunk_index,
                    "repeated": False,
                    "sha256": chunk["content_sha256"],
                },
            )
            conn.execute(
                "UPDATE chunks SET audit_seq=? WHERE application_id=? "
                "AND chunk_index=?",
                (seq, application_id, chunk_index),
            )
            return ChunkDelivery(
                application_id, chunk_index, total,
                chunk["content"], chunk["content_sha256"],
                "delivered", False,
            )

        try:
            return self._run_write_tx(work)
        except _RollbackDeny as deny:
            self._deny(
                actor, "CHUNK_CLAIM", f"export:{application_id}/chunk:{chunk_index}",
                deny.reason, deny.message, deny.exc_cls,
            )

    # ---------------------------------------------------------------- 审计

    def list_audit(self, actor: str, limit: int = 200) -> list[dict]:
        self._require(actor, PERM_READ_AUDIT, "AUDIT_READ")
        conn = self._conn()
        try:
            return audit_mod.list_entries(conn, limit=limit)
        finally:
            conn.close()

    def verify_audit(self, actor: str) -> dict:
        self._require(actor, PERM_READ_AUDIT, "AUDIT_VERIFY")
        conn = self._conn()
        try:
            broken = audit_mod.verify_chain(conn)
            return {"ok": not broken, "broken_seq": broken}
        finally:
            conn.close()
