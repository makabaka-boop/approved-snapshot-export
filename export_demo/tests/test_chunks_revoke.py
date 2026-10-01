"""分块顺序、重复领取幂等、断点重试与撤销语义。"""

from export_demo.errors import InvalidStateError
from export_demo.service import ExportService
from export_demo.tests.base import ServiceCase


class TestChunkingAndRevoke(ServiceCase):
    def test_fixed_order_and_assembly(self):
        app_id = self._apply_approve(chunk_size=2)
        info = self.svc.get_application("alice", app_id)
        indexes = [c["chunk_index"] for c in info["chunks"]]
        self.assertEqual(indexes, [0, 1, 2])
        # 固定顺序：0、1、2 必须按序存在（领取顺序无关，块顺序固定）
        deliveries = [self.svc.claim_chunk("alice", app_id, i) for i in (2, 0, 1)]
        assembled = b"".join(
            sorted(deliveries, key=lambda d: d.chunk_index)[i].content for i in range(3)
        )
        # 乱序领取后按 chunk_index 拼接仍等于按序拼接
        ordered = b"".join(
            self.svc.claim_chunk("alice", app_id, i).content for i in range(3)
        )
        self.assertEqual(assembled, ordered)

    def test_repeated_claim_returns_identical_bytes_and_digest(self):
        app_id = self._apply_approve(chunk_size=2)
        first = self.svc.claim_chunk("alice", app_id, 1)
        self.assertFalse(first.repeated, "首次领取不是重复")
        for _ in range(5):
            d = self.svc.claim_chunk("alice", app_id, 1)
            self.assertTrue(d.repeated)
            self.assertEqual(d.status, "delivered")
            self.assertEqual(d.content, first.content)
            self.assertEqual(d.content_sha256, first.content_sha256)
        d0 = self.svc.claim_chunk("alice", app_id, 0)
        self.assertFalse(d0.repeated)
        again = self.svc.claim_chunk("alice", app_id, 0)
        self.assertTrue(again.repeated, "再次领取是重复")
        self.assertEqual(d0.content, again.content)
        self.assertEqual(d0.content_sha256, again.content_sha256)

    def test_breakpoint_resume_after_partial_delivery(self):
        """模拟客户端领了前两块后崩溃：重启前已 available 的块不能重复交付语义，
        但 delivered 的块仍可重放拿同样字节；未领的块照常领。"""
        app_id = self._apply_approve(chunk_size=2)
        d0 = self.svc.claim_chunk("alice", app_id, 0)
        d1 = self.svc.claim_chunk("alice", app_id, 1)
        # —— 客户端在这里崩溃，块 2 从未领取 ——
        # 重启后（新 service 实例 = 新进程）
        svc2 = ExportService(self.db_path)
        replay0 = svc2.claim_chunk("alice", app_id, 0)
        self.assertEqual(replay0.content, d0.content)
        self.assertTrue(replay0.repeated)
        d2 = svc2.claim_chunk("alice", app_id, 2)
        self.assertFalse(d2.repeated)
        # 全量重放拼接结果不变
        all_bytes = b"".join(
            svc2.claim_chunk("alice", app_id, i).content for i in range(3)
        )
        self.assertEqual(all_bytes, d0.content + d1.content + d2.content)

    def test_revoke_blocks_undelivered_but_keeps_delivered(self):
        app_id = self._apply_approve(chunk_size=2)
        d0 = self.svc.claim_chunk("alice", app_id, 0)  # 块 0 已交付

        result = self.svc.revoke_export("carol", app_id)
        self.assertEqual(result["already_delivered"], 1)
        self.assertEqual(result["blocked_undelivered"], 2)

        # 未领取的块 1、2 被阻止
        with self.assertRaises(InvalidStateError):
            self.svc.claim_chunk("alice", app_id, 1)
        with self.assertRaises(InvalidStateError):
            self.svc.claim_chunk("alice", app_id, 2)

        # 已交付的块 0 仍可重复领取，内容/摘要完全相同，系统不声称收回
        replay = self.svc.claim_chunk("alice", app_id, 0)
        self.assertEqual(replay.content, d0.content)
        self.assertEqual(replay.content_sha256, d0.content_sha256)

        info = self.svc.get_application("alice", app_id)
        self.assertEqual(info["status"], "revoked")
        statuses = {c["chunk_index"]: c["status"] for c in info["chunks"]}
        self.assertEqual(statuses[0], "delivered")
        self.assertEqual(statuses[1], "available", "未交付块保留在可用列表但被状态闸拦住")

    def test_revoke_then_all_delivered_replay(self):
        app_id = self._apply_approve(chunk_size=2)
        delivered = [self.svc.claim_chunk("alice", app_id, i) for i in range(3)]
        self.svc.revoke_export("carol", app_id)
        # 全部已交付：撤销后整份导出仍可重放
        for i, d in enumerate(delivered):
            again = self.svc.claim_chunk("alice", app_id, i)
            self.assertEqual(again.content, d.content)

    def test_bad_chunk_index(self):
        app_id = self._apply_approve(chunk_size=2)
        from export_demo.errors import NotFoundError

        with self.assertRaises(NotFoundError):
            self.svc.claim_chunk("alice", app_id, 99)

    def test_claim_before_approval(self):
        app_id = self.svc.apply_export("alice", "还在等审批", chunk_size=2)
        from export_demo.errors import NotFoundError

        # 审批前根本不存在块
        with self.assertRaises(NotFoundError):
            self.svc.claim_chunk("alice", app_id, 0)
