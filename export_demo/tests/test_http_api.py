"""HTTP 层端到端冒烟测试（真实线程化 HTTP 服务器 + urllib）。"""

from __future__ import annotations

import base64
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from export_demo.http_api import make_server


def request(url, *, method="GET", user=None, body=None):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if user:
        headers["X-User"] = user
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


class TestHttpApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = str(Path(cls.tmp.name) / "http.db")
        cls.server = make_server(cls.db, "127.0.0.1", 0)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.tmp.cleanup()

    def test_01_health_and_auth(self):
        status, body = request(f"{self.base}/health")
        self.assertEqual(status, 200)
        status, body = request(f"{self.base}/exports", method="POST", body={"reason": "x"})
        self.assertEqual(status, 401)
        self.assertEqual(body["error"], "unauthorized")

    def test_02_full_flow_over_http(self):
        # 播种客户
        status, _ = request(
            f"{self.base}/customers", method="POST", user="root",
            body={"name": "钱七", "email": "qianqi@example.com",
                  "phone": "13312341234", "id_card": "123456789012345678",
                  "address": "深圳南山区"},
        )
        self.assertEqual(status, 201)

        # 越权：dave 申请
        status, body = request(
            f"{self.base}/exports", method="POST", user="dave",
            body={"reason": "偷看"},
        )
        self.assertEqual(status, 403)

        # alice 申请
        status, body = request(
            f"{self.base}/exports", method="POST", user="alice",
            body={"reason": "月度合规导出", "chunk_size": 1},
        )
        self.assertEqual(status, 201)
        app_id = body["id"]

        # 自审被拒
        status, body = request(
            f"{self.base}/exports/{app_id}/approve", method="POST",
            user="alice", body={},
        )
        # alice 没有审批权限 -> 403
        self.assertEqual(status, 403)

        # bob 审批通过
        status, body = request(
            f"{self.base}/exports/{app_id}/approve", method="POST",
            user="bob", body={},
        )
        self.assertEqual(status, 200)
        chunk_count = body["chunk_count"]

        # 领取并验证 base64 字节与摘要一致
        import hashlib

        payloads = []
        for i in range(chunk_count):
            status, body = request(
                f"{self.base}/exports/{app_id}/chunk/{i}", method="POST",
                user="alice", body={},
            )
            self.assertEqual(status, 200)
            raw = base64.b64decode(body["content_base64"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), body["sha256"])
            payloads.append(raw)

        # 重复领取得到完全一致的内容
        status, again = request(
            f"{self.base}/exports/{app_id}/chunk/0", method="POST",
            user="alice", body={},
        )
        self.assertEqual(again["content_base64"],
                         base64.b64encode(payloads[0]).decode())
        self.assertTrue(again["repeated"])

        # 不是本人不能领取
        status, body = request(
            f"{self.base}/exports/{app_id}/chunk/0", method="POST",
            user="bob", body={},
        )
        self.assertEqual(status, 403)

        # carol 撤销
        status, body = request(
            f"{self.base}/exports/{app_id}/revoke", method="POST",
            user="carol", body={},
        )
        self.assertEqual(status, 200)
        self.assertGreaterEqual(body["already_delivered"], 1)

        # 审计与验链
        status, body = request(f"{self.base}/audit/verify", user="root")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"], body)

        status, entries = request(f"{self.base}/audit?limit=50", user="root")
        self.assertEqual(status, 200)
        self.assertTrue(any(e["action"] == "EXPORT_REVOKED" for e in entries["entries"]))
