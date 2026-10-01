"""审计哈希链：完整性、篡改检测、拒绝事件留痕。"""

import sqlite3

from export_demo.tests.base import ServiceCase


class TestAuditChain(ServiceCase):
    def test_full_lifecycle_is_audited(self):
        app_id = self.svc.apply_export("alice", "审计全流程")
        self.svc.approve_export("bob", app_id)
        self.svc.claim_chunk("alice", app_id, 0)
        self.svc.revoke_export("carol", app_id)

        entries = self.svc.list_audit("root")
        actions = [e["action"] for e in entries]
        self.assertIn("EXPORT_APPLIED", actions)
        self.assertIn("EXPORT_APPROVED", actions)
        self.assertIn("CHUNK_CLAIMED", actions)
        self.assertIn("EXPORT_REVOKED", actions)

        # 链序号连续
        seqs = [e["seq"] for e in entries]
        self.assertEqual(sorted(seqs), list(range(1, len(seqs) + 1)))

        verdict = self.svc.verify_audit("root")
        self.assertTrue(verdict["ok"], verdict)

    def test_denied_attempts_are_audited(self):
        app_id = self.svc.apply_export("bob", "自审测试")
        try:
            self.svc.approve_export("bob", app_id)
        except Exception:
            pass
        try:
            self.svc.apply_export("dave", "越权")
        except Exception:
            pass

        entries = self.svc.list_audit("root")
        denied = [e for e in entries if e["result"] == "denied"]
        reasons = {e["details"].get("reason") for e in denied}
        self.assertIn("self_approval", reasons)
        self.assertIn("missing_permission", reasons)
        self.assertTrue(self.svc.verify_audit("root")["ok"])

    def test_tampering_is_detected(self):
        app_id = self._apply_approve()
        self.svc.claim_chunk("alice", app_id, 0)

        conn = sqlite3.connect(self.db_path)
        # 篡改一条历史审计的内容
        conn.execute(
            "UPDATE audit_log SET details=? WHERE seq=1",
            ('{"reason":"hacked"}',),
        )
        conn.commit()
        conn.close()

        verdict = self.svc.verify_audit("root")
        self.assertFalse(verdict["ok"])
        self.assertIn(1, verdict["broken_seq"])

    def test_delete_is_detected(self):
        self._apply_approve()
        conn = sqlite3.connect(self.db_path)
        conn.execute("DELETE FROM audit_log WHERE seq=1")
        conn.commit()
        conn.close()
        verdict = self.svc.verify_audit("root")
        self.assertFalse(verdict["ok"])

    def test_audit_requires_permission(self):
        from export_demo.errors import PermissionError_

        with self.assertRaises(PermissionError_):
            self.svc.list_audit("alice")
