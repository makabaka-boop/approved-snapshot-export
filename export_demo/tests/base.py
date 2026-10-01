"""测试公共夹具：每个用例使用临时数据库并播种 6 条客户数据。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from export_demo.service import ExportService

CUSTOMERS = [
    # name, email, phone, id_card, address
    ("张伟", "zhangwei@example.com", "13800138000", "110101199001011234", "北京市海淀区中关村大街1号"),
    ("王芳", "wangfang@example.com", "13911139111", "310104198805052345", "上海市徐汇区漕溪北路2号"),
    ("李娜", "lina@example.com", "13722237222", "440305199212123456", "广州市天河区体育西路3号"),
    ("刘洋", "liuyang@example.com", "13633336333", "510107199507074567", "成都市武侯区人民南路4号"),
    ("陈静", "chenjing@example.com", "13544435444", "330106199909095678", "杭州市西湖区文三路5号"),
    ("赵磊", "zhaolei@example.com", "13455534555", "320105198706066789", "南京市鼓楼区中山北路6号"),
]


class ServiceCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "test.db")
        self.svc = ExportService(self.db_path)
        # root 播种客户与规则
        for i, (name, email, phone, id_card, address) in enumerate(CUSTOMERS, start=1):
            self.svc.upsert_customer(
                "root",
                customer_id=None,
                name=name,
                email=email,
                phone=phone,
                id_card=id_card,
                address=address,
            )

    def tearDown(self):
        self.tmp.cleanup()

    # -- 便捷帮助 --

    def _apply_approve(self, applicant="alice", approver="bob", chunk_size=2):
        app_id = self.svc.apply_export(applicant, "合规审计需要", chunk_size=chunk_size)
        self.svc.approve_export(approver, app_id)
        return app_id

    def _all_chunks(self, app_id, actor="alice"):
        info = self.svc.get_application(actor, app_id)
        deliveries = [
            self.svc.claim_chunk(actor, app_id, c["chunk_index"])
            for c in info["chunks"]
        ]
        return info, deliveries
