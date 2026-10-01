"""权限越权、自审、重复审批/撤销等访问控制测试。"""

from export_demo.errors import (
    ForbiddenError,
    InvalidStateError,
    NotFoundError,
    PermissionError_,
    ValidationError,
)
from export_demo.tests.base import ServiceCase


class TestAccessControl(ServiceCase):
    def test_apply_requires_permission(self):
        # dave 没有任何权限
        with self.assertRaises(PermissionError_):
            self.svc.apply_export("dave", "想看数据")
        denied = [
            e for e in self.svc.list_audit("root")
            if e["action"] == "EXPORT_APPLY" and e["result"] == "denied"
        ]
        self.assertTrue(denied, "越权申请必须留下 denied 审计")
        self.assertEqual(denied[0]["details"]["reason"], "missing_permission")

    def test_unknown_user_rejected(self):
        from export_demo.errors import AuthError

        with self.assertRaises(AuthError):
            self.svc.apply_export("ghost", "x")

    def test_apply_validation(self):
        with self.assertRaises(ValidationError):
            self.svc.apply_export("alice", "  ")
        with self.assertRaises(ValidationError):
            self.svc.apply_export("alice", "合理理由", chunk_size=0)

    def test_approve_requires_permission(self):
        app_id = self.svc.apply_export("alice", "审计")
        # alice 只有申请权
        with self.assertRaises(PermissionError_):
            self.svc.approve_export("alice", app_id)

    def test_self_approval_is_forbidden_even_with_permission(self):
        # bob 同时拥有申请权与审批权，但不能审批自己的申请（身份规则优先）
        app_id = self.svc.apply_export("bob", "我自己申请的")
        with self.assertRaises(ForbiddenError) as ctx:
            self.svc.approve_export("bob", app_id)
        self.assertIn("自己", str(ctx.exception))

        info = self.svc.get_application("bob", app_id)
        self.assertEqual(info["status"], "pending", "自审失败后申请仍须保持 pending")

        # 换一个审批人可以正常通过
        self.svc.approve_export("root", app_id)
        info = self.svc.get_application("bob", app_id)
        self.assertEqual(info["status"], "approved")

    def test_double_approval_conflicts(self):
        app_id = self.svc.apply_export("alice", "审计")
        self.svc.approve_export("bob", app_id)
        with self.assertRaises(InvalidStateError):
            self.svc.approve_export("root", app_id)

    def test_approve_missing_application(self):
        with self.assertRaises(NotFoundError):
            self.svc.approve_export("bob", 99999)

    def test_claim_requires_owner(self):
        app_id = self._apply_approve()
        # bob 是审批人，不能领取 alice 的导出
        with self.assertRaises(ForbiddenError):
            self.svc.claim_chunk("bob", app_id, 0)
        # dave 不是申请人也不是特权角色，连查看都不行
        with self.assertRaises(ForbiddenError):
            self.svc.get_application("dave", app_id)

    def test_revoke_requires_permission(self):
        app_id = self._apply_approve()
        with self.assertRaises(PermissionError_):
            self.svc.revoke_export("bob", app_id)  # bob 无 revoke 权限
        self.svc.revoke_export("carol", app_id)

    def test_double_revoke_and_revoke_pending(self):
        app_id = self.svc.apply_export("alice", "审计")
        with self.assertRaises(InvalidStateError):
            self.svc.revoke_export("carol", app_id)  # 还没批
        self.svc.approve_export("bob", app_id)
        self.svc.revoke_export("carol", app_id)
        with self.assertRaises(InvalidStateError):
            self.svc.revoke_export("root", app_id)

    def test_list_applications_is_scoped(self):
        self.svc.apply_export("bob", "bob 的申请")
        self._apply_approve(applicant="alice")
        alice_rows = self.svc.list_applications("alice")
        self.assertTrue(all(r["applicant"] == "alice" for r in alice_rows))
        bob_rows = self.svc.list_applications("bob")
        # bob 是审批人，可看到全部
        applicants = {r["applicant"] for r in bob_rows}
        self.assertIn("alice", applicants)
        self.assertIn("bob", applicants)
