"""冻结测试：审批时刻的快照与遮蔽规则被永久固定。

之后的客户记录修改、遮蔽规则调整都不得改变该次导出的任何字节，
也不得改变块摘要与整体摘要。
"""
from __future__ import annotations

import hashlib

from exportsvc.masking import split_into_chunks

from .base import ServiceCase


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class TestFreeze(ServiceCase):

    def test_block_layout_and_masked_content(self):
        # 7 条客户记录，每块 3 行 -> 3 块（3/3/1）
        req = self.create_approved()
        self.assertEqual(req["total_chunks"], 3)
        self.assertEqual(
            req["frozen_rules"],
            {"email": "email", "phone": "phone", "id_card": "id_card"},
        )

        listing = self.svc.list_chunks("u_applicant", req["id"])
        self.assertEqual([c["chunk_index"] for c in listing["chunks"]], [0, 1, 2])
        self.assertTrue(all(c["state"] == "available" for c in listing["chunks"]))

        c0 = self.svc.claim_chunk("u_applicant", req["id"], 0)
        # 第 0 块带表头；email/phone/id_card 按审批时的规则遮蔽
        expected = (
            "id,name,email,phone,id_card,region\r\n"
            "C001,陈晓明,c*****@example.com,138****8001,110101********1234,北京\r\n"
            "C002,林美玲,l****@example.cn,139****5678,310104********0022,上海\r\n"
            "C003,王建国,w*****@example.com,137****7788,440305********3456,深圳\r\n"
        )
        self.assertEqual(c0["content"], expected)
        self.assertEqual(c0["sha256"], sha(expected))
        self.assertTrue(c0["delivered_now"])
        self.assertFalse(c0["repeated"])

        c1 = self.svc.claim_chunk("u_applicant", req["id"], 1)
        self.assertNotIn("id,name", c1["content"].split("\r\n")[0])  # 后续块无表头
        c2 = self.svc.claim_chunk("u_applicant", req["id"], 2)

        # 整体摘要 = 各块字节按顺序拼接的 SHA256
        joined = c0["content"] + c1["content"] + c2["content"]
        self.assertEqual(sha(joined), req["full_sha256"])

    def test_modifying_customers_after_approval_changes_nothing(self):
        req = self.create_approved()
        before = [
            self.svc.claim_chunk("u_applicant", req["id"], i)
            for i in range(3)
        ]

        # 审批后：管理员大幅修改全部记录
        for cid, email in (("C001", "hacked@evil.com"), ("C002", "x@y.io"),
                           ("C003", "a@b.c"), ("C004", "p@q.r"),
                           ("C005", "m@n.d"), ("C006", "u@v.e"),
                           ("C007", "w@z.f")):
            self.svc.update_customer("u_admin", cid, {
                "email": email, "name": "被改过", "region": "月球",
                "phone": "19900000000", "id_card": "999999999999999999",
            })

        after = [
            self.svc.claim_chunk("u_applicant", req["id"], i)
            for i in range(3)
        ]
        for b, a in zip(before, after):
            self.assertEqual(b["content"], a["content"], "字节发生变化")
            self.assertEqual(b["sha256"], a["sha256"])

        joined = "".join(a["content"] for a in after)
        self.assertEqual(sha(joined), req["full_sha256"])

        # 新的申请看到的是新数据（证明库确实被改了，而非缓存假象）
        req2 = self.create_approved()
        new_c0 = self.svc.claim_chunk("u_applicant", req2["id"], 0)
        # 邮箱按 email 策略遮蔽：本地部分仅留首字母
        self.assertIn("h*****@evil.com", new_c0["content"])
        self.assertNotIn("陈晓明", new_c0["content"])
        # 新手机号 19900000000：前3+后4
        self.assertIn("199****0000", new_c0["content"])

    def test_changing_masking_rules_after_approval_changes_nothing(self):
        req = self.create_approved()
        before = self.svc.claim_chunk("u_applicant", req["id"], 0)

        # 审批后：email 改为明文、phone 改为全星号、并新增 name 遮蔽
        self.svc.set_masking_rule("u_admin", "email", "plain")
        self.svc.set_masking_rule("u_admin", "phone", "all_stars")
        self.svc.set_masking_rule("u_admin", "name", "name")

        after = self.svc.claim_chunk("u_applicant", req["id"], 0)
        self.assertEqual(before["content"], after["content"])
        self.assertEqual(before["sha256"], after["sha256"])

        # 新申请按新规则渲染
        req2 = self.create_approved()
        c0 = self.svc.claim_chunk("u_applicant", req2["id"], 0)
        self.assertIn("chenxm@example.com", c0["content"])  # email 明文
        self.assertIn("陈**", c0["content"])                 # name 遮蔽
        self.assertIn("***********", c0["content"])          # phone 全星号

    def test_frozen_snapshot_is_stored_and_canonical(self):
        # 直接读库验证冻结快照是审批时的独立副本
        req = self.create_approved()
        self.svc.update_customer("u_admin", "C001", {"email": "later@x.com"})

        import json
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        row = conn.execute(
            "SELECT frozen_snapshot, frozen_rules FROM export_requests WHERE id = ?",
            (req["id"],),
        ).fetchone()
        snapshot = json.loads(row[0])
        self.assertEqual(snapshot[0]["email"], "chenxm@example.com")
        self.assertEqual(snapshot[0]["name"], "陈晓明")
        conn.close()

        # 用冻结快照+冻结规则重渲染，必须与库里的块逐字节一致
        rules = json.loads(row[1])
        re_rendered = split_into_chunks(snapshot, rules, self.ROWS_PER_CHUNK)
        for i, text in enumerate(re_rendered):
            got = self.svc.claim_chunk("u_applicant", req["id"], i)
            self.assertEqual(got["content"], text)

    def test_region_filter_freeze(self):
        req = self.create_approved(region="北京")
        listing = self.svc.list_chunks("u_applicant", req["id"])
        # 北京只有 C001、C004 -> 1 块
        self.assertEqual(req["total_chunks"], 1)
        c0 = self.svc.claim_chunk("u_applicant", req["id"], 0)
        self.assertIn("C001", c0["content"])
        self.assertIn("C004", c0["content"])
        self.assertNotIn("C002", c0["content"])

    def test_empty_result_still_has_one_header_only_chunk(self):
        # 直接插入一个没有任何客户的区域过滤
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        conn.execute("INSERT OR IGNORE INTO users (id, display_name, role) VALUES ('x','x','applicant')")
        conn.commit()
        conn.close()
        # 用不存在客户的方式：先把广州客户不存在校验绕过——创建一条再删
        # （create_request 会校验区域存在客户，这里直接造审批流程：
        #  通过插临时客户）
        import sqlite3 as sq
        from exportsvc.audit import now_iso
        conn = sq.connect(self.db_path)
        conn.execute(
            "INSERT INTO customers (id,name,email,phone,id_card,region,updated_at)"
            " VALUES ('CTMP','t','t@t','1','2','广州',?)",
            (now_iso(),),
        )
        conn.commit()
        conn.close()
        req = self.svc.create_request("u_applicant", "广州")
        # 审批前删掉该客户 -> 审批时快照为空
        conn = sq.connect(self.db_path)
        conn.execute("DELETE FROM customers WHERE id = 'CTMP'")
        conn.commit()
        conn.close()
        req = self.svc.approve_request("u_approver", req["id"])
        self.assertEqual(req["total_chunks"], 1)
        chunk = self.svc.claim_chunk("u_applicant", req["id"], 0)
        self.assertEqual(chunk["content"],
                         "id,name,email,phone,id_card,region\r\n")
