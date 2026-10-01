"""把冻结快照渲染成确定性的 CSV 块。"""

from __future__ import annotations

import csv
import hashlib
import io
from typing import Iterable

from .masking import mask_value


def render_chunk(
    rows: list[dict],
    columns: list[str],
    rules: dict[str, str],
    *,
    include_header: bool,
) -> bytes:
    """渲染单个 CSV 块。

    - 统一 CRLF 行结束符、UTF-8 无 BOM；
    - 表头只出现在第 0 块（``include_header=True``），
      拼接全部块即得到完整 CSV；
    - 同样的输入字节必然得到同样的输出字节（领取幂等的基础）。
    """
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\r\n")
    if include_header:
        writer.writerow(columns)
    for row in rows:
        writer.writerow([mask_value(row.get(col), rules.get(col, "full")) for col in columns])
    return buf.getvalue().encode("utf-8")


def split_ordered(items: list, chunk_size: int) -> list[list]:
    """按固定顺序切块；空列表也产生一个只含表头的第 0 块（由调用方渲染）。"""
    if chunk_size <= 0:
        raise ValueError("chunk_size 必须为正整数")
    return [items[i : i + chunk_size] for i in range(0, len(items), chunk_size)]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def content_fingerprint(parts: Iterable[bytes]) -> str:
    """按顺序喂给同一个哈希，得到快照整体指纹。"""
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.hexdigest()
