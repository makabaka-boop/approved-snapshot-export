"""列级遮蔽规则与 CSV 渲染。

遮蔽规则在**审批时刻**按当时内容冻结（见 ``service.approve_request``），
之后无论客户记录如何修改、规则如何调整，已审批导出的字节都不变。

遮蔽策略（均为确定性、无随机性）：

* ``plain``     —— 原值
* ``all_stars`` —— 全部字符替换为 ``*``（保留长度）
* ``name``      —— 保留首字符，其余替换为 ``*``
* ``email``     —— 本地部分保留首字符；域名保留
* ``phone``     —— 保留前 3 位与后 4 位，中间 ``****``
* ``id_card``   —— 保留前 6 位与后 4 位，中间 ``********``
"""
from __future__ import annotations

import csv
import io

EXPORT_COLUMNS = ["id", "name", "email", "phone", "id_card", "region"]


def mask_value(strategy: str, value: str) -> str:
    """按策略遮蔽一个单元格。"""
    value = "" if value is None else str(value)
    if strategy == "plain":
        return value
    if strategy == "all_stars":
        return "*" * len(value)
    if strategy == "name":
        if len(value) <= 1:
            return value
        return value[0] + "*" * (len(value) - 1)
    if strategy == "email":
        if "@" not in value:
            return "*" * len(value)
        local, _, domain = value.partition("@")
        head = local[:1]
        return f"{head}{'*' * (len(local) - 1)}@{domain}" if len(local) > 1 else f"{head}@{domain}"
    if strategy == "phone":
        digits = value
        if len(digits) <= 7:
            return "*" * len(digits)
        return digits[:3] + "****" + digits[-4:]
    if strategy == "id_card":
        if len(value) <= 10:
            return "*" * len(value)
        return value[:6] + "********" + value[-4:]
    # 未知策略默认全遮蔽，宁可多遮不可泄露
    return "*" * len(value)


def render_row(row: dict, rules: dict[str, str]) -> list[str]:
    """按冻结规则把一条客户记录渲染成 CSV 字段序列。"""
    return [mask_value(rules.get(col, "plain"), row.get(col, "")) for col in EXPORT_COLUMNS]


def render_csv_chunk(rows: list[dict], rules: dict[str, str], include_header: bool) -> str:
    """渲染一个 CSV 块。

    每个块都是独立可读的 CSV：第 0 块带表头，其余块只有数据行。
    使用 ``csv.writer`` 保证引号/换行转义规范；行尾固定 ``\\r\\n``，
    末尾保留换行符——相同输入必须产生逐字节相同的输出。
    """
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\r\n")
    if include_header:
        writer.writerow(EXPORT_COLUMNS)
    for row in rows:
        writer.writerow(render_row(row, rules))
    return buf.getvalue()


def split_into_chunks(snapshot: list[dict], rules: dict[str, str],
                      rows_per_chunk: int) -> list[str]:
    """把快照按固定顺序切成 CSV 块字符串列表。"""
    if rows_per_chunk <= 0:
        raise ValueError("rows_per_chunk must be positive")
    chunks: list[str] = []
    for start in range(0, len(snapshot), rows_per_chunk):
        part = snapshot[start:start + rows_per_chunk]
        chunks.append(render_csv_chunk(part, rules, include_header=(start == 0)))
    if not chunks:
        # 空结果也要有且仅有一个块（仅表头），领取协议保持统一
        chunks.append(render_csv_chunk([], rules, include_header=True))
    return chunks
