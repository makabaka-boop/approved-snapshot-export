"""基于标准库 ``http.server`` 的 HTTP 适配层。

线程模型：``ThreadingHTTPServer`` 每请求一线程；每个线程持有自己的
SQLite 连接（见 :mod:`exportsvc.db`），关键区由 ``BEGIN IMMEDIATE``
串行化，因此服务重启与并发请求都不需要额外锁。

鉴权：演示项目用请求头 ``X-User-Id`` 表示当前用户（无密码体系）。

接口：

* ``POST /requests``                       申请人提交导出申请
* ``GET  /requests/{id}``                  查看申请（含冻结状态/总块数）
* ``GET  /requests/{id}/chunks``           块状态清单（断点续传用）
* ``POST /requests/{id}/approve``          审批并冻结
* ``GET  /requests/{id}/chunks/{index}``   领取一块（重复领取幂等）
* ``POST /requests/{id}/revoke``           撤销审批
* ``GET  /audit?request_id=...``           审计记录（审批人/管理员）
* ``POST /audit/verify``                   哈希链核对（管理员）
* ``POST /admin/customers/{id}``           修改客户记录（管理员）
* ``PUT  /admin/masking-rules/{column}``   调整遮蔽规则（管理员）
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .errors import ExportError
from .service import ExportService


class ApiHandler(BaseHTTPRequestHandler):
    service: ExportService = None  # 由 build_server 注入（类属性）

    server_version = "ExportSvc/1.0"

    # -- 基础读写 ---------------------------------------------------------

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            raise ExportError("VALIDATION", "invalid JSON body", 400)
        if not isinstance(data, dict):
            raise ExportError("VALIDATION", "JSON body must be an object", 400)
        return data

    def _send_json(self, status: int, payload) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, exc: ExportError) -> None:
        self._send_json(exc.http_status,
                        {"error": exc.code, "message": exc.message})

    def _user(self) -> str | None:
        return self.headers.get("X-User-Id")

    def log_message(self, fmt, *args):  # 静音默认访问日志，测试输出更干净
        pass

    # -- 路由 -------------------------------------------------------------

    def _route(self, method: str):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        parts = [p for p in path.split("/") if p]
        svc = self.service

        try:
            if method == "POST" and parts == ["requests"]:
                body = self._read_json()
                return self._send_json(201, svc.create_request(
                    self._user(), body.get("filter_region")))

            if method == "GET" and len(parts) == 2 and parts[0] == "requests":
                return self._send_json(200, svc.get_request(self._user(), parts[1]))

            if (method == "GET" and len(parts) == 3
                    and parts[0] == "requests" and parts[2] == "chunks"):
                return self._send_json(200, svc.list_chunks(self._user(), parts[1]))

            if (method == "POST" and len(parts) == 3
                    and parts[0] == "requests" and parts[2] == "approve"):
                return self._send_json(200, svc.approve_request(self._user(), parts[1]))

            if (method == "POST" and len(parts) == 3
                    and parts[0] == "requests" and parts[2] == "revoke"):
                return self._send_json(200, svc.revoke_approval(self._user(), parts[1]))

            if (method == "GET" and len(parts) == 4
                    and parts[0] == "requests" and parts[2] == "chunks"):
                try:
                    index = int(parts[3])
                except ValueError:
                    raise ExportError("VALIDATION", "chunk index must be an integer", 400)
                if index < 0:
                    raise ExportError("VALIDATION", "chunk index must be >= 0", 400)
                return self._send_json(200, svc.claim_chunk(self._user(), parts[1], index))

            if method == "GET" and parts == ["audit"]:
                q = parsed.query
                request_id = None
                if q.startswith("request_id="):
                    request_id = q.split("=", 1)[1] or None
                return self._send_json(200, svc.list_audit(self._user(), request_id))

            if method == "POST" and parts == ["audit", "verify"]:
                self._read_json()
                return self._send_json(200, svc.verify_audit(self._user()))

            if (method == "POST" and len(parts) == 3
                    and parts[0] == "admin" and parts[1] == "customers"):
                return self._send_json(200, svc.update_customer(
                    self._user(), parts[2], self._read_json()))

            if (method == "PUT" and len(parts) == 3
                    and parts[0] == "admin"
                    and parts[1] == "masking-rules"):
                body = self._read_json()
                if "strategy" not in body:
                    raise ExportError("VALIDATION", "strategy is required", 400)
                return self._send_json(200, svc.set_masking_rule(
                    self._user(), parts[2], body["strategy"]))

            raise ExportError("NOT_FOUND", f"no route: {method} {path}", 404)
        except ExportError as exc:
            return self._send_error(exc)
        except Exception as exc:  # 未预期错误：500，但不吞掉细节
            self._send_json(500, {"error": "INTERNAL", "message": str(exc)})

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def do_PUT(self):
        self._route("PUT")


def build_server(db_path: str, host: str = "127.0.0.1", port: int = 0,
                 rows_per_chunk: int = 3) -> ThreadingHTTPServer:
    """构造并返回一个已就绪但未 ``serve_forever`` 的服务器。"""
    service = ExportService(db_path, rows_per_chunk=rows_per_chunk)

    class _BoundHandler(ApiHandler):
        pass

    _BoundHandler.service = service
    server = ThreadingHTTPServer((host, port), _BoundHandler)
    server.export_service = service
    return server
