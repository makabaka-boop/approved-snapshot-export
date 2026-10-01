"""断点重试与服务重启测试。

* 重复领取同一块必须得到完全相同的内容与摘要；
* 领取进度持久化，重启后可按 ``list_chunks`` 续传；
* 整体摘要可在领取完成后由各块重算核对。
"""
from __future__ import annotations

import hashlib

from exportsvc.db import reset_thread_connection
from exportsvc.errors import ExportError
from exportsvc.service import ExportService

from .base import ServiceCase


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class TestRetryAndRestart(ServiceCase):

    def test_repeat_claim_is_byte_identical_and_idempotent(self):
        req = self.create_approved()
        first = self.svc.claim_chunk("u_applicant", req["id"], 1)
        for _ in range(5):
            again = self.svc.claim_chunk("u_applicant", req["id"], 1)
            self.assertEqual(again["content"], first["content"])
            self.assertEqual(again["sha256"], first["sha256"])
            self.assertTrue(again["repeated"])
            self.assertFalse(again["delivered_now"])

        # 块状态仍是 claimed，且只记录一个 claimed_by
        listing = self.svc.list_chunks("u_applicant", req["id"])
        c1 = listing["chunks"][1]
        self.assertEqual(c1["state"], "claimed")
        self.assertEqual(c1["claimed_by"], "u_applicant")

        # 首次 claimed 一次 + 重取 5 次
        events = self.svc.list_audit("u_admin", req["id"])
        self.assertEqual(
            sum(1 for e in events if e["action"] == "chunk_claimed"), 1
        )
        self.assertEqual(
            sum(1 for e in events if e["action"] == "chunk_reclaimed"), 5
        )

    def test_resume_after_restart(self):
        req = self.create_approved()
        total = req["total_chunks"]

        # 领取前两块（模拟中途崩溃）
        self.svc.claim_chunk("u_applicant", req["id"], 0)
        self.svc.claim_chunk("u_applicant", req["id"], 1)
        received = {0: None, 1: None}
        received[0] = self.svc.claim_chunk("u_applicant", req["id"], 0)["content"]
        received[1] = self.svc.claim_chunk("u_applicant", req["id"], 1)["content"]

        # 服务重启：丢弃线程连接并重新构造服务（文件就是全部状态）
        reset_thread_connection()
        svc2 = ExportService(self.db_path, rows_per_chunk=self.ROWS_PER_CHUNK)

        listing = svc2.list_chunks("u_applicant", req["id"])
        states = [c["state"] for c in listing["chunks"]]
        self.assertEqual(states[:2], ["claimed", "claimed"])
        self.assertEqual(states[2], "available")

        # 已领块重取字节不变；未领块继续领取
        again0 = svc2.claim_chunk("u_applicant", req["id"], 0)
        self.assertEqual(again0["content"], received[0])
        last = svc2.claim_chunk("u_applicant", req["id"], 2)

        all_bytes = received[0] + received[1] + last["content"]
        self.assertEqual(sha(all_bytes), req["full_sha256"])

        # 全部领取完毕
        listing = svc2.list_chunks("u_applicant", req["id"])
        self.assertTrue(all(c["state"] == "claimed" for c in listing["chunks"]))

        # 重启不破坏审计链
        self.assertTrue(svc2.verify_audit("u_admin")["ok"])

    def test_restart_before_any_claim_keeps_frozen_bytes(self):
        req = self.create_approved()
        reset_thread_connection()
        svc2 = ExportService(self.db_path, rows_per_chunk=self.ROWS_PER_CHUNK)
        # 重启后再改库，已冻结导出不变
        svc2.update_customer("u_admin", "C001", {"email": "z@z.io"})
        c0 = svc2.claim_chunk("u_applicant", req["id"], 0)
        self.assertIn("c*****@example.com", c0["content"])

    def test_out_of_range_chunk(self):
        req = self.create_approved()
        with self.assertRaises(ExportError) as cm:
            self.svc.claim_chunk("u_applicant", req["id"], 99)
        self.assertEqual(cm.exception.http_status, 404)

    def test_reordered_delivery_concatenates_by_index_not_claim_time(self):
        # 允许不按顺序领取；整体摘要以 chunk_index 顺序拼接定义
        req = self.create_approved()
        total = req["total_chunks"]
        bag = {}
        for i in range(total - 1, -1, -1):
            bag[i] = self.svc.claim_chunk("u_applicant", req["id"], i)["content"]
        ordered = "".join(bag[i] for i in range(total))
        self.assertEqual(sha(ordered), req["full_sha256"])
