"""HTTP 端到端测试：真实 socket、多线程请求、服务器重启。"""
from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from exportsvc import cli
from exportsvc.api import build_server
from exportsvc.db import reset_thread_connection


import unittest  # noqa: E402


def http(method: str, url: str, user: str | None = None, body=None):
    """发 HTTP 请求，返回 ``(status, json_body)``；4xx/5xx 不抛异常。"""
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if user is not None:
        headers["X-User-Id"] = user
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


class TestHttpApi(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "http.db")
        cli.seed(self.db_path)
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT INTO users (id, display_name, role) VALUES ('u_other','其他申请人','applicant')"
        )
        conn.commit()
        conn.close()
        reset_thread_connection()
        self.server = build_server(self.db_path, port=0)
        self.port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        reset_thread_connection()
        self.tmp.cleanup()

    def url(self, *parts):
        return self.base + "/" + "/".join(parts)

    # -- 基础生命周期 -----------------------------------------------------

    def test_happy_path_over_http(self):
        # 未认证
        status, body = http("POST", self.url("requests"), body={})
        self.assertEqual(status, 401)
        self.assertEqual(body["error"], "UNAUTHORIZED")

        # 申请
        status, body = http("POST", self.url("requests"), "u_applicant", {})
        self.assertEqual(status, 201)
        rid = body["id"]
        self.assertEqual(body["status"], "pending")

        # 自审
        status, body = http("POST", self.url("requests", rid, "approve"),
                            "u_applicant")
        self.assertEqual(status, 403)
        self.assertEqual(body["error"], "SELF_APPROVAL")

        # 审批通过
        status, body = http("POST", self.url("requests", rid, "approve"),
                            "u_approver")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "approved")
        self.assertEqual(body["total_chunks"], 3)

        # 领取全部
        contents = {}
        for i in range(3):
            status, body = http("GET", self.url("requests", rid, "chunks", str(i)),
                                "u_applicant")
            self.assertEqual(status, 200)
            contents[i] = body["content"]
            self.assertEqual(
                body["sha256"],
                hashlib.sha256(body["content"].encode()).hexdigest(),
            )

        # 重复领取
        status, body = http("GET", self.url("requests", rid, "chunks", "0"),
                            "u_applicant")
        self.assertEqual(status, 200)
        self.assertTrue(body["repeated"])
        self.assertEqual(body["content"], contents[0])

        # 越权
        status, _ = http("GET", self.url("requests", rid, "chunks", "0"),
                         "u_other")
        self.assertEqual(status, 403)  # 禁止领取（denied 审计留痕）
        status, _ = http("GET", self.url("requests", rid), "u_other")
        self.assertEqual(status, 404)  # 查看则隐藏存在性

    def test_revoke_over_http_blocks_unclaimed_410(self):
        status, body = http("POST", self.url("requests"), "u_applicant", {})
        rid = body["id"]
        http("POST", self.url("requests", rid, "approve"), "u_approver")

        status, c0 = http("GET", self.url("requests", rid, "chunks", "0"),
                          "u_applicant")
        self.assertEqual(status, 200)

        status, rev = http("POST", self.url("requests", rid, "revoke"),
                           "u_approver")
        self.assertEqual(status, 200)
        self.assertEqual(rev["chunks_already_claimed"], 1)
        self.assertEqual(rev["chunks_blocked"], 2)

        # 已交付内容仍可重取
        status, body = http("GET", self.url("requests", rid, "chunks", "0"),
                            "u_applicant")
        self.assertEqual(status, 200)
        self.assertEqual(body["content"], c0["content"])

        # 未领块 410
        for i in (1, 2):
            status, body = http("GET",
                                self.url("requests", rid, "chunks", str(i)),
                                "u_applicant")
            self.assertEqual(status, 410)
            self.assertEqual(body["error"], "CHUNK_REVOKED")

        # 再撤销 -> 409
        status, body = http("POST", self.url("requests", rid, "revoke"),
                            "u_approver")
        self.assertEqual(status, 409)

    def test_rules_and_customers_admin_only(self):
        status, _ = http("PUT", self.url("admin", "masking-rules", "email"),
                         "u_applicant", {"strategy": "plain"})
        self.assertEqual(status, 403)
        status, body = http("PUT",
                            self.url("admin", "masking-rules", "email"),
                            "u_admin", {"strategy": "plain"})
        self.assertEqual(status, 200)
        self.assertEqual(body["old"], "email")
        self.assertEqual(body["new"], "plain")

    def test_audit_and_verify_endpoints(self):
        status, body = http("POST", self.url("requests"), "u_applicant", {})
        rid = body["id"]
        http("POST", self.url("requests", rid, "approve"), "u_applicant")  # denied
        http("POST", self.url("requests", rid, "approve"), "u_approver")

        status, events = http("GET",
                              self.base + "/audit?request_id=" + rid,
                              "u_approver")
        self.assertEqual(status, 200)
        self.assertTrue(any(
            e["action"] == "request_approval_denied"
            and e["details"]["reason"] == "self_approval"
            for e in events
        ))

        status, report = http("POST", self.url("audit", "verify"), "u_admin")
        self.assertEqual(status, 200)
        self.assertTrue(report["ok"])
        self.assertGreaterEqual(report["count"], 2)

    def test_concurrent_http_claim_and_revoke_race(self):
        """真实 HTTP 并发：三个领取请求与撤销同时到达。"""
        # 全量 7 条 -> 3 块
        status, body = http("POST", self.url("requests"), "u_applicant", {})
        rid = body["id"]
        http("POST", self.url("requests", rid, "approve"), "u_approver")

        indices = [0, 1, 2]
        results: dict[int, tuple] = {}
        lock = threading.Lock()
        barrier = threading.Barrier(4)

        def claim(i):
            barrier.wait()
            with lock:
                pass
            return ("claim", i,
                    http("GET", self.url("requests", rid, "chunks", str(i)),
                         "u_applicant"))

        def revoke():
            barrier.wait()
            return ("revoke", None,
                    http("POST", self.url("requests", rid, "revoke"),
                         "u_approver"))

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(claim, i) for i in indices]
            futures.append(pool.submit(revoke))
            for f in futures:
                kind, i, (st, payload) = f.result()
                if kind == "claim":
                    results[i] = (st, payload)

        claimed = {i for i, (st, _) in results.items() if st == 200}
        blocked = {i for i, (st, _) in results.items() if st == 410}
        self.assertTrue(claimed.isdisjoint(blocked))
        self.assertEqual(claimed | blocked, {0, 1, 2})

        # 终态核对
        status, listing = http("GET",
                               self.url("requests", rid, "chunks"),
                               "u_applicant")
        for c in listing["chunks"]:
            if c["chunk_index"] in claimed:
                self.assertEqual(c["state"], "claimed")
            else:
                self.assertEqual(c["state"], "revoked")

        # 已交付块重取仍为同一字节
        for i in claimed:
            st, payload = http("GET",
                               self.url("requests", rid, "chunks", str(i)),
                               "u_applicant")
            self.assertEqual(st, 200)
            self.assertEqual(payload["sha256"],
                             results[i][1]["sha256"])

        status, report = http("POST", self.url("audit", "verify"), "u_admin")
        self.assertTrue(report["ok"])

    def test_server_restart_preserves_everything(self):
        status, body = http("POST", self.url("requests"), "u_applicant", {})
        rid = body["id"]
        http("POST", self.url("requests", rid, "approve"), "u_approver")
        http("GET", self.url("requests", rid, "chunks", "0"), "u_applicant")

        # 关掉旧服务器，同一路径起新服务器
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()
        reset_thread_connection()
        self.server = build_server(self.db_path, port=0)
        self.port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()

        status, listing = http("GET",
                               self.url("requests", rid, "chunks"),
                               "u_applicant")
        self.assertEqual(status, 200)
        self.assertEqual(listing["chunks"][0]["state"], "claimed")
        self.assertEqual(listing["chunks"][1]["state"], "available")

        status, body = http("GET",
                            self.url("requests", rid, "chunks", "1"),
                            "u_applicant")
        self.assertEqual(status, 200)
