"""标准库实现的 HTTP 适配层（零第三方依赖）。

鉴权方式：请求头 ``X-User: username`` —— 演示用的简化身份头，
真实系统应替换为会话/JWT 校验，领域层的权限判断不受影响。
"""

from __future__ import annotations

import base64
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .errors import ApiError
from .service import ExportService


def _json_response(handler, status: int, payload: dict | list):
    body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class _Handler(BaseHTTPRequestHandler):
    server_version = "ExportDemo/1.0"

    # 由 server 注入
    service: ExportService = None  # type: ignore[assignment]

    def log_message(self, fmt, *args):  # 安静一点，测试输出不被污染
        if getattr(self.server, "export_demo_verbose", False):
            super().log_message(fmt, *args)

    # ------------------------------------------------------------ 解析辅助

    def _actor(self) -> str:
        actor = self.headers.get("X-User", "").strip()
        if not actor:
            raise _MissingUser()
        return actor

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            from .errors import ValidationError

            raise ValidationError(f"请求体不是合法 JSON: {exc}")
        if not isinstance(data, dict):
            from .errors import ValidationError

            raise ValidationError("请求体必须是 JSON 对象")
        return data

    # ------------------------------------------------------------ 路由

    def do_GET(self):
        self._dispatch(write=False)

    def do_POST(self):
        self._dispatch(write=True)

    def _dispatch(self, *, write: bool):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        qs = parse_qs(parsed.query)
        svc: ExportService = self.server.service  # type: ignore[attr-defined]
        try:
            if path == "/health":
                _json_response(self, 200, {"ok": True})
                return
            actor = self._actor()
            body = self._body() if write else {}
            status, payload = self._route(svc, actor, path, body, qs)
            _json_response(self, status, payload)
        except ApiError as exc:
            _json_response(
                self,
                exc.http_status,
                {"error": exc.code, "message": str(exc)},
            )
        except Exception as exc:  # 兜底，不让连接挂死
            _json_response(
                self, 500, {"error": "internal_error", "message": str(exc)}
            )

    def _route(self, svc, actor, path, body, qs):
        # ---- 客户 / 规则管理 ----
        if path == "/customers":
            customer_id = body.get("id")
            new_id = svc.upsert_customer(
                actor,
                customer_id=customer_id,
                name=body["name"],
                email=body.get("email"),
                phone=body.get("phone"),
                id_card=body.get("id_card"),
                address=body.get("address"),
            )
            return 201, {"id": new_id}

        if path == "/rules":
            svc.set_masking_rule(actor, body["column"], body["mode"])
            return 200, {"ok": True, "column": body["column"], "mode": body["mode"]}

        # ---- 导出生命周期 ----
        if path == "/exports":
            app_id = svc.apply_export(
                actor, body["reason"], int(body.get("chunk_size", 2))
            )
            return 201, {"id": app_id}

        if path == "/exports/list":
            return 200, {"applications": svc.list_applications(actor)}

        parts = path.strip("/").split("/")
        # /exports/{id}/approve | revoke | chunk/{n}
        if len(parts) >= 2 and parts[0] == "exports" and parts[1].isdigit():
            app_id = int(parts[1])
            if len(parts) == 3 and parts[2] == "approve":
                return 200, svc.approve_export(actor, app_id)
            if len(parts) == 3 and parts[2] == "revoke":
                return 200, svc.revoke_export(actor, app_id)
            if len(parts) == 4 and parts[2] == "chunk" and parts[3].lstrip("-").isdigit():
                delivery = svc.claim_chunk(actor, app_id, int(parts[3]))
                return 200, {
                    "application_id": delivery.application_id,
                    "chunk_index": delivery.chunk_index,
                    "chunk_count": delivery.chunk_count,
                    "status": delivery.status,
                    "repeated": delivery.repeated,
                    "sha256": delivery.content_sha256,
                    "encoding": "utf-8",
                    "content_base64": base64.b64encode(delivery.content).decode("ascii"),
                }
            if len(parts) == 2:
                return 200, svc.get_application(actor, app_id)

        if path == "/audit":
            limit = int((qs.get("limit") or ["200"])[0])
            return 200, {"entries": svc.list_audit(actor, limit)}

        if path == "/audit/verify":
            return 200, svc.verify_audit(actor)

        if path == "/health":
            return 200, {"ok": True}

        from .errors import NotFoundError

        raise NotFoundError(f"未知路径: {path}")


class _MissingUser(ApiError):
    http_status = 401
    code = "unauthorized"

    def __init__(self):
        super().__init__("缺少 X-User 身份头")


def make_server(db_path: str, host: str = "127.0.0.1", port: int = 8000,
                verbose: bool = False) -> ThreadingHTTPServer:
    service = ExportService(db_path)
    server = ThreadingHTTPServer((host, port), _Handler)
    server.service = service  # type: ignore[attr-defined]
    server.export_demo_verbose = verbose  # type: ignore[attr-defined]
    return server


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description="客户记录导出审批演示 API")
    parser.add_argument("--db", default="/tmp/export_demo.db")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    server = make_server(args.db, args.host, args.port, args.verbose)
    print(f"导出演示 API 已启动: http://{args.host}:{args.port}  (db={args.db})")
    print("演示账号: alice(申请人) bob(审批人) carol(合规) root(管理员) dave(无权限)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
