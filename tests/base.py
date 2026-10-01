"""测试公共工具：临时数据库 + 播种 + 额外用户。"""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from exportsvc import cli
from exportsvc.db import reset_thread_connection
from exportsvc.service import ExportService


class ServiceCase(unittest.TestCase):
    """每个用例一个独立的临时数据库。"""

    ROWS_PER_CHUNK = 3

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "test.db")
        cli.seed(self.db_path)
        self._add_extra_users()
        reset_thread_connection()
        self.svc = ExportService(self.db_path, rows_per_chunk=self.ROWS_PER_CHUNK)

    def tearDown(self) -> None:
        reset_thread_connection()
        self.tmp.cleanup()

    def _add_extra_users(self) -> None:
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "INSERT INTO users (id, display_name, role) VALUES (?, ?, ?)",
                ("u_other", "申请人 赵六", "applicant"),
            )
            conn.execute(
                "INSERT INTO users (id, display_name, role) VALUES (?, ?, ?)",
                ("u_clerk", "普通审批人 孙七", "approver"),
            )
            conn.commit()
        finally:
            conn.close()

    # 业务快捷方法 --------------------------------------------------------

    def create_approved(self, applicant="u_applicant", approver="u_approver",
                        region=None):
        req = self.svc.create_request(applicant, region)
        req = self.svc.approve_request(approver, req["id"])
        self.assertEqual(req["status"], "approved")
        return req

    def raw_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def audit_actions(self, request_id=None) -> list[str]:
        return [e["action"] for e in self.svc.list_audit("u_admin", request_id)]
