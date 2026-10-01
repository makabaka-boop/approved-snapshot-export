"""业务错误类型与错误码。

服务层只抛出 :class:`ExportError`；HTTP 层负责把它翻译成状态码与 JSON。
错误码字符串保持稳定，测试与审计核对都依赖它。
"""
from __future__ import annotations


class ExportError(Exception):
    """所有可预期的业务错误。

    :param code: 机器可读错误码（如 ``FORBIDDEN``、``SELF_APPROVAL``）
    :param message: 人类可读描述
    :param http_status: 对应的 HTTP 状态码
    """

    def __init__(self, code: str, message: str, http_status: int = 400,
                 persist_audit: bool = False):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status
        # True：拒绝类错误，事务里只写了"拒绝留痕"这一条审计、没有任何
        # 业务变更，事务应当提交（保留审计）而不是回滚。
        self.persist_audit = persist_audit


# 常用错误工厂 ------------------------------------------------------------

def not_found(what: str, ident) -> ExportError:
    return ExportError("NOT_FOUND", f"{what} not found: {ident}", 404)


def unauthorized(message: str = "authentication required") -> ExportError:
    return ExportError("UNAUTHORIZED", message, 401)


def forbidden(message: str = "operation not permitted") -> ExportError:
    return ExportError("FORBIDDEN", message, 403)


def bad_state(message: str) -> ExportError:
    return ExportError("BAD_STATE", message, 409)
