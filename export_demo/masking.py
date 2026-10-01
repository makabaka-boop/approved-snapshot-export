"""列级遮蔽（脱敏）规则。

规则在审批通过时被冻结进快照；规则表之后的调整只影响今后的新导出，
不会改变任何已经审批的导出。
"""

from __future__ import annotations

MASK_FULL = "full"          # 整列遮蔽为 ****
MASK_EMAIL = "email"        # 保留首字符与域名
MASK_PHONE = "phone"        # 保留前 3 后 4
MASK_TAIL4 = "tail4"        # 仅保留后 4 位
MASK_NONE = "none"          # 明文

ALL_MODES = {MASK_FULL, MASK_EMAIL, MASK_PHONE, MASK_TAIL4, MASK_NONE}


def mask_value(value, mode: str):
    if value is None or mode == MASK_NONE:
        return value
    text = str(value)
    if not text:
        return text
    if mode == MASK_FULL:
        return "****"
    if mode == MASK_EMAIL:
        if "@" in text:
            name, _, domain = text.partition("@")
            if not name:
                return "*@" + domain
            return name[0] + "*@" + domain
        return "****"
    if mode == MASK_PHONE:
        digits = [c for c in text if c.isdigit()]
        if len(digits) >= 7:
            return text[:3] + "*" * (len(digits) - 7) + "".join(digits[-4:])
        return "****"
    if mode == MASK_TAIL4:
        if len(text) <= 4:
            return text
        return "*" * (len(text) - 4) + text[-4:]
    # 未知规则按最保守方式处理
    return "****"
