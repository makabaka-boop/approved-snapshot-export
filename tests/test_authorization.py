"""权限与越权测试：未认证、角色不足、自审、跨用户领取/查看。"""
from __future__ import annotations

from exportsvc.errors import ExportError

from .base import ServiceCase


class TestAuthorization(ServiceCase):

    def test_request_without_identity_is_rejected(self):
        with self.assertRaises(ExportError) as cm:
            self.svc.create_request(None)
        self.assertEqual(cm.exception.http_status, 401)

    def test_request_with_unknown_identity_is_rejected(self):
        with self.assertRaises(ExportError) as cm:
            self.svc.create_request("ghost")
        self.assertEqual(cm.exception.http_status, 401)

    def test_applicant_cannot_approve(self):
        req = self.svc.create_request("u_applicant")
        with self.assertRaises(ExportError) as cm:
            self.svc.approve_request("u_applicant", req["id"])
        self.assertEqual(cm.exception.code, "SELF_APPROVAL")
        self.assertEqual(cm.exception.http_status, 403)

        # 自审不得改变状态
        again = self.svc.get_request("u_applicant", req["id"])
        self.assertEqual(again["status"], "pending")

        # 自审尝试必须留下 denied 审计
        events = self.svc.list_audit("u_admin", req["id"])
        denied = [e for e in events if e["action"] == "request_approval_denied"]
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0]["result"], "denied")
        self.assertEqual(denied[0]["details"]["reason"], "self_approval")

    def test_applicant_role_cannot_approve_others(self):
        req = self.svc.create_request("u_applicant")
        with self.assertRaises(ExportError) as cm:
            self.svc.approve_request("u_other", req["id"])  # 另一个申请人
        self.assertEqual(cm.exception.http_status, 403)
        events = self.svc.list_audit("u_admin", req["id"])
        self.assertTrue(any(
            e["action"] == "request_approval_denied"
            and e["details"]["reason"] == "insufficient_role"
            for e in events
        ))

    def test_other_applicant_cannot_see_or_claim(self):
        req = self.create_approved()
        # 无权查看：以 404 隐藏存在性
        with self.assertRaises(ExportError) as cm:
            self.svc.get_request("u_other", req["id"])
        self.assertEqual(cm.exception.http_status, 404)

        with self.assertRaises(ExportError) as cm:
            self.svc.list_chunks("u_other", req["id"])
        self.assertEqual(cm.exception.http_status, 404)

        # 无权领取
        with self.assertRaises(ExportError) as cm:
            self.svc.claim_chunk("u_other", req["id"], 0)
        self.assertEqual(cm.exception.http_status, 403)

        # 拒绝领取也有审计
        events = self.svc.list_audit("u_admin", req["id"])
        self.assertTrue(any(
            e["action"] == "chunk_claim_denied"
            and e["details"]["reason"] == "not_owner"
            for e in events
        ))

    def test_approver_cannot_claim_someone_elses_chunk(self):
        req = self.create_approved()
        with self.assertRaises(ExportError) as cm:
            self.svc.claim_chunk("u_approver", req["id"], 0)
        self.assertEqual(cm.exception.http_status, 403)

    def test_only_admin_can_modify_customers_or_rules(self):
        with self.assertRaises(ExportError) as cm:
            self.svc.update_customer("u_applicant", "C001", {"name": "黑客"})
        self.assertEqual(cm.exception.http_status, 403)

        with self.assertRaises(ExportError) as cm:
            self.svc.set_masking_rule("u_approver", "email", "plain")
        self.assertEqual(cm.exception.http_status, 403)

    def test_only_privileged_roles_read_audit(self):
        with self.assertRaises(ExportError) as cm:
            self.svc.list_audit("u_applicant")
        self.assertEqual(cm.exception.http_status, 403)

        with self.assertRaises(ExportError) as cm:
            self.svc.verify_audit("u_approver")
        self.assertEqual(cm.exception.http_status, 403)

        # 审批人可读审计，但不能做链校验（仅管理员）
        self.assertIsInstance(self.svc.list_audit("u_approver"), list)
        self.assertTrue(self.svc.verify_audit("u_admin")["ok"])

    def test_approver_other_than_applicant_may_approve(self):
        # u_clerk 是另一个审批人，不是申请人，可以审批
        req = self.svc.create_request("u_applicant")
        out = self.svc.approve_request("u_clerk", req["id"])
        self.assertEqual(out["status"], "approved")
        self.assertEqual(out["approver_id"], "u_clerk")

    def test_double_approval_second_is_rejected(self):
        req = self.create_approved()
        with self.assertRaises(ExportError) as cm:
            self.svc.approve_request("u_clerk", req["id"])
        self.assertEqual(cm.exception.code, "BAD_STATE")
        self.assertEqual(cm.exception.http_status, 409)
        events = self.svc.list_audit("u_admin", req["id"])
        self.assertTrue(any(
            e["details"].get("reason") == "not_pending" for e in events
        ))

    def test_claim_before_approval_rejected(self):
        req = self.svc.create_request("u_applicant")
        with self.assertRaises(ExportError) as cm:
            self.svc.claim_chunk("u_applicant", req["id"], 0)
        self.assertEqual(cm.exception.code, "BAD_STATE")
