"""审批快照冻结：审批后的数据修改与规则调整不得改变任何导出字节。"""

import hashlib

from export_demo.tests.base import ServiceCase


def fetch_snapshot_rows(svc, app_id):
    conn = svc._conn()
    try:
        rows = conn.execute(
            "SELECT data_json FROM snapshot_rows sr "
            "JOIN snapshots s ON s.id = sr.snapshot_id "
            "WHERE s.application_id=? ORDER BY position",
            (app_id,),
        ).fetchall()
        return [r[0] for r in rows]
    finally:
        conn.close()


class TestSnapshotFreeze(ServiceCase):
    def test_data_modified_after_approval_does_not_change_bytes(self):
        app_id = self._apply_approve(chunk_size=3)
        info, before = self._all_chunks(app_id)
        before_blob = b"".join(d.content for d in before)
        before_hashes = [d.content_sha256 for d in before]

        # 审批后：修改全部客户 + 追加新客户
        for cid in range(1, 7):
            self.svc.upsert_customer(
                "root", customer_id=cid, name="被篡改的名字",
                email="hacker@evil.example", phone="10000000000",
                id_card="999999999999999999", address="某秘密地址",
            )
        self.svc.upsert_customer("root", customer_id=None, name="第七条新客户")

        info2 = self.svc.get_application("alice", app_id)
        self.assertEqual(len(info2["chunks"]), len(before), "块数量不得变化")
        after = [
            self.svc.claim_chunk("alice", app_id, i)
            for i in range(len(before))
        ]
        after_blob = b"".join(d.content for d in after)
        self.assertEqual(before_blob, after_blob, "审批后改数据不得改变导出字节")
        self.assertEqual(before_hashes, [d.content_sha256 for d in after])

        # 快照行数也固定为 6（新客户不进入已审批导出）
        frozen = fetch_snapshot_rows(self.svc, app_id)
        self.assertEqual(len(frozen), 6)

    def test_rule_change_after_approval_does_not_change_bytes(self):
        app_id = self._apply_approve(chunk_size=2)
        _, before = self._all_chunks(app_id)
        before_blob = b"".join(d.content for d in before)

        # 审批后把规则全部改成明文
        for col in ["name", "email", "phone", "id_card", "address"]:
            self.svc.set_masking_rule("root", col, "none")

        after = [
            self.svc.claim_chunk("alice", app_id, i)
            for i in range(len(before))
        ]
        self.assertEqual(before_blob, b"".join(d.content for d in after))

    def test_new_export_picks_up_new_rules_and_data(self):
        app_id_old = self._apply_approve(chunk_size=10)
        _, old = self._all_chunks(app_id_old)

        # 改规则 + 改数据后，新审批的导出反映新规则、新数据
        self.svc.set_masking_rule("root", "email", "full")
        self.svc.upsert_customer(
            "root", customer_id=1, name="张伟",
            email="changed@example.com", phone="13800138000",
            id_card="110101199001011234", address="北京市海淀区中关村大街1号",
        )
        app_id_new = self._apply_approve(chunk_size=10)
        _, new = self._all_chunks(app_id_new)
        self.assertNotEqual(b"".join(d.content for d in old),
                            b"".join(d.content for d in new))
        text = b"".join(d.content for d in new).decode("utf-8")
        self.assertIn("****", text, "新规则把邮箱整列遮蔽")
        self.assertNotIn("changed@example.com", text)

    def test_frozen_csv_is_deterministic_and_masked(self):
        app_id = self._apply_approve(chunk_size=2)  # 6 行 -> 3 块
        info = self.svc.get_application("alice", app_id)
        self.assertEqual(len(info["chunks"]), 3)

        d0 = self.svc.claim_chunk("alice", app_id, 0)
        text = d0.content.decode("utf-8")
        lines = text.split("\r\n")
        self.assertEqual(lines[0], "id,name,email,phone,id_card,address",
                         "只有第 0 块带表头")
        self.assertIn("1,****,z*@example.com,138****8000,**************1234,****", text)
        self.assertIn("\r\n", text, "CSV 必须统一 CRLF")

        d1 = self.svc.claim_chunk("alice", app_id, 1)
        self.assertFalse(d1.content.startswith(b"id,"), "后续块不重复表头")

        # 服务端回传的 sha256 必须与字节真实摘要一致
        for d in (d0, d1, self.svc.claim_chunk("alice", app_id, 2)):
            self.assertEqual(d.content_sha256,
                             hashlib.sha256(d.content).hexdigest())

    def test_empty_export_still_has_header_chunk(self):
        # 空库场景：至少交付一个只含表头的块
        from export_demo.service import ExportService
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            svc = ExportService(str(Path(td) / "empty.db"))
            app_id = svc.apply_export("alice", "空导出", chunk_size=10)
            svc.approve_export("bob", app_id)
            d = svc.claim_chunk("alice", app_id, 0)
            self.assertEqual(d.content, b"id,name,email,phone,id_card,address\r\n")
            with self.assertRaises(Exception):
                svc.claim_chunk("alice", app_id, 1)
