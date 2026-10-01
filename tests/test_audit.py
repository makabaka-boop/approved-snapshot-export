"""审计记录与哈希链测试。

* 申请、审批、领取（含重复领取）、撤销、被拒绝操作全部有记录；
* 哈希链连续可验；任何篡改/删除都会被发现。
"""
from __future__ import annotations

import json
import sqlite3

from exportsvc.audit import compute_entry_hash

from .base import ServiceCase


class TestAudit(ServiceCase):

    def test_full_lifecycle_is_audited(self):
        req = self.svc.create_request("u_applicant")
        rid = req["id"]
        self.svc.approve_request("u_approver", rid)
        self.svc.claim_chunk("u_applicant", rid, 0)
        self.svc.claim_chunk("u_applicant", rid, 0)  # 重复
        self.svc.revoke_approval("u_clerk", rid)

        actions = [
            (e["action"], e["result"])
            for e in self.svc.list_audit("u_admin", rid)
        ]
        self.assertIn(("request_created", "success"), actions)
        self.assertIn(("request_approved", "success"), actions)
        self.assertIn(("chunk_claimed", "success"), actions)
        self.assertIn(("chunk_reclaimed", "success"), actions)
        self.assertIn(("approval_revoked", "success"), actions)

        approved = [e for e in self.svc.list_audit("u_admin", rid)
                    if e["action"] == "request_approved"][0]
        self.assertEqual(approved["actor_id"], "u_approver")
        self.assertEqual(approved["details"]["total_chunks"], 3)
        self.assertIn("full_sha256", approved["details"])

        revoked = [e for e in self.svc.list_audit("u_admin", rid)
                   if e["action"] == "approval_revoked"][0]
        # 0 号已领，其余两块被阻止
        self.assertEqual(revoked["details"]["chunks_already_claimed"], 1)
        self.assertEqual(revoked["details"]["chunks_blocked"], 2)

    def test_seq_monotonic_and_chain_valid(self):
        self.svc.create_request("u_applicant")
        r2 = self.svc.create_request("u_applicant")
        self.svc.approve_request("u_approver", r2["id"])
        events = self.svc.list_audit("u_admin")
        seqs = [e["seq"] for e in events]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))
        report = self.svc.verify_audit("u_admin")
        self.assertTrue(report["ok"])
        self.assertEqual(report["count"], len(events))

    def test_tampered_details_detected(self):
        req = self.svc.create_request("u_applicant")
        rid = req["id"]
        self.svc.approve_request("u_approver", rid)

        # 直接在库中篡改某条审计的 details（绕过服务）
        conn = sqlite3.connect(self.db_path)
        row = conn.execute(
            "SELECT seq, details FROM audit_log WHERE action = 'request_approved'"
        ).fetchone()
        tampered = json.loads(row[1])
        tampered["actor_fake"] = "intruder"
        conn.execute(
            "UPDATE audit_log SET details = ? WHERE seq = ?",
            (json.dumps(tampered, sort_keys=True), row[0]),
        )
        conn.commit()
        conn.close()

        report = self.svc.verify_audit("u_admin")
        self.assertFalse(report["ok"])
        self.assertEqual(report["broken_at"], row[0])
        self.assertIn("entry_hash mismatch", report["reason"])

    def test_deleted_entry_breaks_chain(self):
        req = self.svc.create_request("u_applicant")
        rid = req["id"]
        self.svc.approve_request("u_approver", rid)
        self.svc.claim_chunk("u_applicant", rid, 0)

        conn = sqlite3.connect(self.db_path)
        conn.execute("DELETE FROM audit_log WHERE action = 'request_approved'")
        conn.commit()
        conn.close()

        report = self.svc.verify_audit("u_admin")
        self.assertFalse(report["ok"])

    def test_recomputed_hash_matches_algorithm(self):
        self.svc.create_request("u_applicant")
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM audit_log WHERE seq = 1").fetchone()
        expect = compute_entry_hash(
            seq=row["seq"], at=row["at"], actor_id=row["actor_id"],
            action=row["action"], request_id=row["request_id"],
            chunk_index=row["chunk_index"], result=row["result"],
            details_json=row["details"], prev_hash=row["prev_hash"],
        )
        self.assertEqual(expect, row["entry_hash"])
        conn.close()

    def test_admin_actions_audited(self):
        self.svc.set_masking_rule("u_admin", "email", "plain")
        self.svc.update_customer("u_admin", "C001", {"name": "新名字"})
        actions = [e["action"] for e in self.svc.list_audit("u_admin")]
        self.assertIn("masking_rule_updated", actions)
        self.assertIn("customer_updated", actions)
        self.assertTrue(self.svc.verify_audit("u_admin")["ok"])

    def test_denied_attempts_are_audited_without_state_change(self):
        req = self.svc.create_request("u_applicant")
        rid = req["id"]
        # 自审
        try:
            self.svc.approve_request("u_applicant", rid)
        except Exception:
            pass
        # 越权领取（尚未审批，别人也看不见——先走审批再越权）
        self.svc.approve_request("u_approver", rid)
        try:
            self.svc.claim_chunk("u_other", rid, 0)
        except Exception:
            pass
        # 越权撤销
        try:
            self.svc.revoke_approval("u_applicant", rid)
        except Exception:
            pass

        denied = [e for e in self.svc.list_audit("u_admin", rid)
                  if e["result"] == "denied"]
        reasons = {e["details"].get("reason") for e in denied}
        self.assertIn("self_approval", reasons)
        self.assertIn("not_owner", reasons)
        self.assertIn("applicant_revoke_own", reasons)
