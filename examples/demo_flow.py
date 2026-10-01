"""端到端演示：申请 → 自审被拒 → 审批冻结 → 分块领取 → 撤销 → 审计核对。

运行：python3 examples/demo_flow.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from export_demo.service import ExportService


def banner(title: str):
    print("\n" + "=" * 64)
    print(f"  {title}")
    print("=" * 64)


def main():
    tmp = tempfile.TemporaryDirectory()
    db = str(Path(tmp.name) / "demo.db")
    svc = ExportService(db)

    banner("1. root 录入客户数据")
    customers = [
        ("张伟", "zhangwei@example.com", "13800138000", "110101199001011234", "北京海淀"),
        ("王芳", "wangfang@example.com", "13911139111", "310104198805052345", "上海徐汇"),
        ("李娜", "lina@example.com", "13722237222", "440305199212123456", "广州天河"),
    ]
    for c in customers:
        cid = svc.upsert_customer(
            "root", customer_id=None, name=c[0], email=c[1], phone=c[2],
            id_card=c[3], address=c[4],
        )
        print(f"  录入客户 #{cid}: {c[0]}")

    banner("2. alice 提交导出申请")
    app_id = svc.apply_export("alice", "2026Q3 合规审计", chunk_size=2)
    print(f"  申请编号: {app_id} (chunk_size=2)")

    banner("3. dave 越权审批 → 403，且留下审计")
    try:
        svc.approve_export("dave", app_id)
    except Exception as exc:
        print(f"  被拒绝: {type(exc).__name__}: {exc}")

    banner("4. alice 试图自审 → 403（身份规则，即使有审批权限也不行）")
    # bob 有申请+审批两种权限，用他演示自审拦截
    own = svc.apply_export("bob", "bob 自己的申请", chunk_size=2)
    try:
        svc.approve_export("bob", own)
    except Exception as exc:
        print(f"  被拒绝: {type(exc).__name__}: {exc}")

    banner("5. bob 审批 alice 的申请，冻结快照与遮蔽规则")
    result = svc.approve_export("bob", app_id)
    print(f"  冻结于: {result['frozen_at']}")
    print(f"  块数量: {result['chunk_count']}, rows_hash={result['rows_hash'][:12]}…")

    banner("6. 审批后篡改数据 / 放宽规则 —— 不影响已冻结导出")
    svc.upsert_customer(
        "root", customer_id=1, name="被篡改", email="x@evil.example",
        phone="10000000000", id_card="000000000000000000", address="??",
    )
    svc.set_masking_rule("root", "id_card", "none")
    print("  已把客户1改得面目全非，并把身份证列改为明文")

    banner("7. 按固定顺序领取 CSV 块，重复领取字节/摘要完全一致")
    for i in range(result["chunk_count"]):
        d = svc.claim_chunk("alice", app_id, i)
        print(f"  --- 块 {i} (sha256={d.content_sha256[:16]}…) ---")
        print("  " + d.content.decode("utf-8").replace("\r\n", "\r\n  ").rstrip())
        again = svc.claim_chunk("alice", app_id, i)
        assert again.content == d.content
    print("  ✓ 重复领取内容一致")

    banner("8. carol 撤销：未领取的块被阻止，已交付的不收回")
    # 新开一个申请演示撤销效果
    app2 = svc.apply_export("alice", "另一次导出", chunk_size=2)
    svc.approve_export("bob", app2)
    first = svc.claim_chunk("alice", app2, 0)
    rev = svc.revoke_export("carol", app2)
    print(f"  阻止未交付块: {rev['blocked_undelivered']}, 已交付: {rev['already_delivered']}")
    try:
        svc.claim_chunk("alice", app2, 1)
    except Exception as exc:
        print(f"  领取块1被拒绝: {type(exc).__name__}: {exc}")
    replay = svc.claim_chunk("alice", app2, 0)
    assert replay.content == first.content
    print("  ✓ 块0 已交付，撤销后仍可拿到完全相同的内容（不声称收回）")

    banner("9. 审计链核对")
    verdict = svc.verify_audit("root")
    print(f"  哈希链完好: {verdict['ok']}")
    entries = svc.list_audit("root", limit=100)
    print(f"  共 {len(entries)} 条审计，最近 8 条：")
    for e in entries[:8]:
        print(f"  #{e['seq']:>2} {e['ts']} {e['actor']:<6} "
              f"{e['action']:<16} {e['result']}")

    tmp.cleanup()
    print("\n演示完成。")


if __name__ == "__main__":
    main()
