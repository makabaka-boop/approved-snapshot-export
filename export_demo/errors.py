"""统一的领域异常与 HTTP 状态码映射。"""


class ApiError(Exception):
    """所有可预期 API 错误的基类。"""

    http_status = 400
    code = "bad_request"

    def __init__(self, message: str, *, code: str | None = None):
        super().__init__(message)
        if code:
            self.code = code


class ValidationError(ApiError):
    http_status = 400
    code = "validation_error"


class AuthError(ApiError):
    http_status = 401
    code = "unauthorized"


class PermissionError_(ApiError):
    """已认证用户缺少所需权限（越权）。"""

    http_status = 403
    code = "forbidden"


class ForbiddenError(ApiError):
    """通过了权限检查但被业务规则拒绝（例如自审、领取他人导出）。"""

    http_status = 403
    code = "forbidden"


class NotFoundError(ApiError):
    http_status = 404
    code = "not_found"


class InvalidStateError(ApiError):
    """资源当前状态不允许该操作（重复审批、重复撤销、撤销售后领块等）。"""

    http_status = 409
    code = "conflict"
