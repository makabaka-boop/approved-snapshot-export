"""并发与重启测试：双审批、领取竞争、撤销竞争、审批期间改数据。"""

import threading

from export_demo.errors import InvalidStateError
from export_demo.service import ExportService
from export_demo.tests.base import ServiceCase


class TestConcurrency(ServiceCase):
    def test_parallel_claims_each_chunk_has_single_first_delivery(self):
        app_id = self._apply_approve(chunk_size=2)
        svc = ExportService(self.db_path)  # 独立实例、独立连接，模拟多工作进程

        results: dict[tuple[int, int], object] = {}
        errors: list[Exception] = []
        barrier = threading.Barrier(12)  # 3 块 x 4 个竞争线程

        def worker(chunk_index: int):
            barrier.wait()
            try:
                d = svc.claim_chunk("alice", app_id, chunk_index)
                results[(threading.get_ident(), chunk_index)] = d
            except Exception as exc:  # 只有两种可能：赢或重试后成功/冲突
                errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(i % 3,)) for i in range(12)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # 失败的请求只可能是“状态被并发改变”；成功重放的请求 repeated=True
        for exc in errors:
            self.assertIsInstance(exc, InvalidStateError)

        info = svc.get_application("alice", app_id)
        delivered = [c for c in info["chunks"] if c["status"] == "delivered"]
        self.assertEqual(len(delivered), 3, "每块恰好被首次交付一次")
        # 每块有且仅有一次 repeated=False 的 CHUNK_CLAIMED 成功审计
        audit = svc.list_audit("root", limit=500)
        firsts = [
            e for e in audit
            if e["action"] == "CHUNK_CLAIMED"
            and e["result"] == "success"
            and not e["details"].get("repeated")
        ]
        self.assertEqual(len(firsts), 3)

        # 每个线程拿到的字节都与最终状态一致
        for (_, idx), d in results.items():
            ref = svc.claim_chunk("alice", app_id, idx)
            self.assertEqual(d.content, ref.content)
            self.assertEqual(d.content_sha256, ref.content_sha256)

    def test_concurrent_double_approval(self):
        app_id = self.svc.apply_export("alice", "审批竞争")
        svc = ExportService(self.db_path)
        outcomes: list[str] = []
        lock = threading.Lock()
        barrier = threading.Barrier(2)

        def approver(name: str):
            barrier.wait()
            try:
                svc.approve_export(name, app_id)
                with lock:
                    outcomes.append(f"{name}:ok")
            except InvalidStateError:
                with lock:
                    outcomes.append(f"{name}:conflict")
            except Exception as exc:
                with lock:
                    outcomes.append(f"{name}:{type(exc).__name__}")

        t1 = threading.Thread(target=approver, args=("bob",))
        t2 = threading.Thread(target=approver, args=("root",))
        t1.start(); t2.start(); t1.join(); t2.join()

        oks = [o for o in outcomes if o.endswith(":ok")]
        conflicts = [o for o in outcomes if o.endswith(":conflict")]
        self.assertEqual(len(oks), 1, "恰好一个审批成功")
        self.assertEqual(len(conflicts), 1, "另一个必须冲突失败")

        info = svc.get_application("alice", app_id)
        self.assertEqual(info["status"], "approved")
        # 快照与块只生成一份
        self.assertEqual(len(info["chunks"]), 3)
        winner = oks[0].split(":")[0]
        self.assertEqual(info["snapshot"]["frozen_at"] is not None, True)
        approvals = [
            e for e in svc.list_audit("root") if e["action"] == "EXPORT_APPROVED"
        ]
        self.assertEqual(len(approvals), 1)
        self.assertEqual(approvals[0]["actor"], winner)

    def test_revoke_claim_race(self):
        """撤销与未交付块领取同时进行：结果非此即彼，但永不矛盾。

        - 若领取先提交：块 delivered，撤销记录 already_delivered 包含它；
        - 若撤销先提交：领取被 409 拒绝，块仍 available。
        """
        for trial in range(5):
            app_id = self._apply_approve(chunk_size=2)
            svc = ExportService(self.db_path)
            barrier = threading.Barrier(2)
            claim_result: dict = {}
            revoke_result: dict = {}

            def claim():
                barrier.wait()
                try:
                    claim_result["d"] = svc.claim_chunk("alice", app_id, 2)
                except InvalidStateError as exc:
                    claim_result["err"] = exc

            def revoke():
                barrier.wait()
                try:
                    revoke_result["r"] = svc.revoke_export("carol", app_id)
                except InvalidStateError as exc:
                    revoke_result["err"] = exc

            t1 = threading.Thread(target=claim)
            t2 = threading.Thread(target=revoke)
            t1.start(); t2.start(); t1.join(); t2.join()

            info = svc.get_application("alice", app_id)
            chunk2 = next(c for c in info["chunks"] if c["chunk_index"] == 2)
            self.assertEqual(info["status"], "revoked", "撤销最终必然生效")

            if "d" in claim_result:
                # 领取赢：必须恰好一次，撤销计数把它算进已交付
                self.assertEqual(chunk2["status"], "delivered")
                self.assertIn("r", revoke_result)
                self.assertGreaterEqual(revoke_result["r"]["already_delivered"], 1)
                # 已交付内容撤销后仍可重放
                again = svc.claim_chunk("alice", app_id, 2)
                self.assertEqual(again.content, claim_result["d"].content)
            else:
                # 撤销赢：块没有被交付，之后任何重试都被阻止
                self.assertIsInstance(claim_result.get("err"), InvalidStateError)
                self.assertEqual(chunk2["status"], "available")

    def test_modification_during_approval_keeps_one_consistent_snapshot(self):
        """审批事务进行中并发写入：快照必须是某个时间点的已提交状态。

        多个 upsert 各自独立提交，快照可能落在写入序列的中间，但每一行都必须
        是某个已提交的完整版本（不能出现新名字配旧邮箱这种“撕裂行”）。
        """
        import json as _json

        app_id = self.svc.apply_export("alice", "审批期间改数据", chunk_size=1)
        svc = ExportService(self.db_path)
        barrier = threading.Barrier(2)
        approve_out: dict = {}

        def approve():
            barrier.wait()
            approve_out["r"] = svc.approve_export("bob", app_id)

        def mutate():
            barrier.wait()
            for cid in range(1, 7):
                svc.upsert_customer(
                    "root", customer_id=cid, name="改后名字",
                    email="after@example.com", phone="13900000000",
                    id_card="000000000000000000", address="改后地址",
                )
            svc.upsert_customer("root", customer_id=None, name="新增客户")

        t1 = threading.Thread(target=approve)
        t2 = threading.Thread(target=mutate)
        t1.start(); t2.start(); t1.join(); t2.join()

        r = approve_out["r"]
        # 快照对应某个已提交时间点：6 行（新增客户尚未插入）或 7 行
        self.assertIn(r["chunk_count"], (6, 7))

        # 逐行验证内部一致性：旧版本（原姓名 + 原邮箱）或
        # 新版本（改后名字 + after 邮箱），不能混合
        conn = svc._conn()
        try:
            rows = conn.execute(
                "SELECT data_json FROM snapshot_rows sr "
                "JOIN snapshots s ON s.id = sr.snapshot_id "
                "WHERE s.application_id=? ORDER BY position",
                (app_id,),
            ).fetchall()
        finally:
            conn.close()
        data_rows = [_json.loads(r[0]) for r in rows]
        for row in data_rows:
            if row["name"] == "改后名字":
                self.assertEqual(row["email"], "after@example.com")
                self.assertEqual(row["phone"], "13900000000")
                self.assertEqual(row["address"], "改后地址")
            else:
                self.assertTrue(row["email"].endswith("@example.com"))
                self.assertNotEqual(row["address"], "改后地址")

        # 审批结束后的再次修改不影响冻结字节
        before = b"".join(
            svc.claim_chunk("alice", app_id, i).content
            for i in range(r["chunk_count"])
        )
        svc.upsert_customer(
            "root", customer_id=1, name="第三次修改",
            email="third@example.com", phone="13900000000",
            id_card="000000000000000000", address="第三次地址",
        )
        after = b"".join(
            svc.claim_chunk("alice", app_id, i).content
            for i in range(r["chunk_count"])
        )
        self.assertEqual(before, after)

    def test_restart_does_not_duplicate_or_lose_state(self):
        app_id = self._apply_approve(chunk_size=2)
        self.svc.claim_chunk("alice", app_id, 0)

        # 重启：模拟进程退出后用同一个数据库文件构造新服务
        svc2 = ExportService(self.db_path)
        info = svc2.get_application("alice", app_id)
        self.assertEqual(info["status"], "approved")
        self.assertEqual(info["chunks"][0]["status"], "delivered")
        self.assertEqual(info["chunks"][1]["status"], "available")
        d0 = svc2.claim_chunk("alice", app_id, 0)
        d1 = svc2.claim_chunk("alice", app_id, 1)
        self.assertTrue(d0.repeated)
        self.assertFalse(d1.repeated)
