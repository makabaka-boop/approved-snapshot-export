"""并发安全测试。

关键正确性靠 ``BEGIN IMMEDIATE`` 串行化保证。这里从外部用多线程
反复制造竞争，断言无论调度如何交错，不变量始终成立。
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from exportsvc.db import reset_thread_connection
from exportsvc.errors import ExportError
from exportsvc.service import ExportService

from .base import ServiceCase


class TestConcurrency(ServiceCase):

    def test_claim_and_revoke_race(self):
        """大量重复下：撤销与对剩余块的领取竞争。

        不变量：
        * 每个块最终要么 claimed（内容==冻结字节），要么 revoked；
        * 没有任何一个块既被撤销又被交付（同一内容不会出现两种结局）；
        * revoked 的领取得到 410；claimed 的重取永远成功且字节不变；
        * 审计链完好。
        """
        rounds = 25
        for r in range(rounds):
            req = self.create_approved()
            rid = req["id"]
            total = req["total_chunks"]
            barrier = threading.Barrier(total + 1)

            delivered: dict[int, str] = {}
            lock = threading.Lock()
            claim_errors: list[ExportError] = []

            def try_claim(index: int):
                reset_thread_connection()
                svc = ExportService(self.db_path, rows_per_chunk=self.ROWS_PER_CHUNK)
                barrier.wait()
                try:
                    out = svc.claim_chunk("u_applicant", rid, index)
                    with lock:
                        delivered[index] = out["content"]
                except ExportError as exc:
                    with lock:
                        claim_errors.append(exc)

            with ThreadPoolExecutor(max_workers=total + 1) as pool:
                futures = [pool.submit(try_claim, i) for i in range(total)]
                barrier.wait()  # 尽量让领取与撤销同时发起
                # 撤销在另一个独立连接上
                reset_thread_connection()
                revoker = ExportService(self.db_path, rows_per_chunk=self.ROWS_PER_CHUNK)
                result = revoker.revoke_approval("u_approver", rid)

                for f in futures:
                    f.result()

            # 撤销统计与实际终态必须一致
            listing = self.svc.list_chunks("u_applicant", rid)
            claimed_idx = {c["chunk_index"] for c in listing["chunks"]
                           if c["state"] == "claimed"}
            revoked_idx = {c["chunk_index"] for c in listing["chunks"]
                           if c["state"] == "revoked"}
            self.assertEqual(
                result["chunks_already_claimed"], len(claimed_idx),
                f"round {r}: revoke 计数与终态不一致",
            )
            self.assertEqual(
                result["chunks_blocked"], len(revoked_idx),
                f"round {r}: revoke 计数与终态不一致",
            )
            self.assertTrue(claimed_idx.isdisjoint(revoked_idx))
            self.assertEqual(claimed_idx | revoked_idx, set(range(total)))

            # 被交付的内容在撤销后仍可逐字节重取（不收回已交付内容）
            for i in claimed_idx:
                again = self.svc.claim_chunk("u_applicant", rid, i)
                self.assertEqual(again["content"], delivered[i])
                self.assertEqual(again["state"], "claimed")

            # 被阻止的块再领取 -> 410
            for i in revoked_idx:
                with self.assertRaises(ExportError) as cm:
                    self.svc.claim_chunk("u_applicant", rid, i)
                self.assertEqual(cm.exception.code, "CHUNK_REVOKED")
                self.assertEqual(cm.exception.http_status, 410)

            # 失败原因只能是 410（不可能是其它状态错误/500）
            self.assertTrue(all(e.code == "CHUNK_REVOKED" for e in claim_errors))

        self.assertTrue(self.svc.verify_audit("u_admin")["ok"])

    def test_concurrent_claims_same_chunk_exactly_one_delivery(self):
        req = self.create_approved()
        rid = req["id"]
        n = 12
        start = threading.Barrier(n)
        outcomes: list[tuple[str, str]] = []
        lock = threading.Lock()

        def worker():
            reset_thread_connection()
            svc = ExportService(self.db_path, rows_per_chunk=self.ROWS_PER_CHUNK)
            start.wait()
            try:
                out = svc.claim_chunk("u_applicant", rid, 0)
                with lock:
                    outcomes.append(("ok", out["content"]))
            except ExportError as exc:
                with lock:
                    outcomes.append(("err", exc.code))

        # 同一申请人的并发请求（允许"同一用户的多客户端同时重试"）
        with ThreadPoolExecutor(max_workers=n) as pool:
            futures = [pool.submit(worker) for _ in range(n)]
            [f.result() for f in futures]

        self.assertEqual(len(outcomes), n)
        self.assertTrue(all(o[0] == "ok" for o in outcomes))
        contents = {o[1] for o in outcomes}
        self.assertEqual(len(contents), 1)  # 所有人拿到同一份冻结字节

        listing = self.svc.list_chunks("u_applicant", rid)
        self.assertEqual(listing["chunks"][0]["state"], "claimed")

        events = self.svc.list_audit("u_admin", rid)
        self.assertEqual(
            sum(1 for e in events if e["action"] == "chunk_claimed"), 1
        )
        self.assertEqual(
            sum(1 for e in events if e["action"] == "chunk_reclaimed"), n - 1
        )

    def test_concurrent_double_approval_only_one_succeeds(self):
        req = self.svc.create_request("u_applicant")
        rid = req["id"]
        n = 6
        start = threading.Barrier(n)
        results: list[str] = []
        lock = threading.Lock()

        approvers = ["u_approver", "u_clerk"]

        def worker(idx):
            reset_thread_connection()
            svc = ExportService(self.db_path, rows_per_chunk=self.ROWS_PER_CHUNK)
            start.wait()
            try:
                svc.approve_request(approvers[idx % 2], rid)
                with lock:
                    results.append("ok")
            except ExportError as exc:
                with lock:
                    results.append(exc.code)

        with ThreadPoolExecutor(max_workers=n) as pool:
            futures = [pool.submit(worker, i) for i in range(n)]
            [f.result() for f in futures]

        self.assertEqual(results.count("ok"), 1)
        self.assertEqual(results.count("BAD_STATE"), n - 1)

        # 块只能有一份（UNIQUE 约束 + 单次冻结）
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        count = conn.execute(
            "SELECT COUNT(*) FROM export_chunks WHERE request_id = ?", (rid,)
        ).fetchone()[0]
        conn.close()
        self.assertEqual(count, 3)  # 7 条记录 / 3
        self.assertTrue(self.svc.verify_audit("u_admin")["ok"])

    def test_concurrent_self_approval_never_succeeds(self):
        # 申请人与两名审批人同时点"通过"；申请人无论先抢还是后抢都必败
        ok = denied = 0
        for _ in range(10):
            req = self.svc.create_request("u_applicant")
            rid = req["id"]
            start = threading.Barrier(3)
            lock = threading.Lock()
            verdicts = []

            def actor(uid, tag):
                reset_thread_connection()
                svc = ExportService(self.db_path, rows_per_chunk=self.ROWS_PER_CHUNK)
                start.wait()
                try:
                    svc.approve_request(uid, rid)
                    with lock:
                        verdicts.append((tag, "ok"))
                except ExportError as exc:
                    with lock:
                        verdicts.append((tag, exc.code))

            with ThreadPoolExecutor(max_workers=3) as pool:
                fs = [pool.submit(actor, "u_applicant", "self"),
                      pool.submit(actor, "u_approver", "a1"),
                      pool.submit(actor, "u_clerk", "a2")]
                [f.result() for f in fs]

            self_verdicts = [v for tag, v in verdicts if tag == "self"]
            self.assertEqual(self_verdicts, ["SELF_APPROVAL"])
            approver_ok = [v for tag, v in verdicts if tag != "self" and v == "ok"]
            self.assertEqual(len(approver_ok), 1)

        self.assertTrue(self.svc.verify_audit("u_admin")["ok"])

    def test_modification_during_approval_is_serialized_after_freeze(self):
        """审批持锁期间发起的修改必须阻塞到提交之后，且不能污染冻结快照。

        通过 ``freeze_hook`` 在快照已读、锁未释放时触发并发修改，
        验证：hook 返回前修改无法完成；最终冻结内容仍是修改前的数据。
        """
        req = self.svc.create_request("u_applicant")
        rid = req["id"]
        modification_finished = threading.Event()
        modification_blocked_during_hook = threading.Event()

        def hook():
            # 在写锁持有期间发起修改（另起守护线程、**独立的裸连接**，
            # 不能复用 ExportService 的线程本地连接，否则会自竞争）。
            # 同进程内 SQLite 写锁竞争会立刻返回 BUSY，所以该线程用
            # 短超时重试，直到主事务提交后才能成功。
            def modify():
                import sqlite3
                import time
                from exportsvc.audit import now_iso
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    c = sqlite3.connect(self.db_path, timeout=1)
                    c.execute("PRAGMA busy_timeout = 1000")
                    try:
                        c.execute("BEGIN IMMEDIATE")
                        c.execute(
                            "UPDATE customers SET email = ?, updated_at = ? WHERE id = ?",
                            ("race@x.com", now_iso(), "C001"),
                        )
                        c.commit()
                        modification_finished.set()
                        return
                    except sqlite3.OperationalError:
                        pass
                    finally:
                        c.close()
                    time.sleep(0.02)

            t = threading.Thread(target=modify, daemon=True)
            t.start()
            # 给被阻塞的修改 0.5s 去抢锁——它必须抢不到
            finished = modification_finished.wait(0.5)
            if not finished:
                modification_blocked_during_hook.set()
            # 不 join：它在主事务提交后才可能拿到锁

        # hook 运行在审批事务内部
        out = self.svc.approve_request("u_approver", rid, freeze_hook=hook)
        # 主事务已提交，修改此时才能完成
        self.assertTrue(modification_finished.wait(timeout=10))
        self.assertTrue(
            modification_blocked_during_hook.is_set(),
            "审批持锁期间修改居然能插入，冻结可能被污染",
        )
        self.assertTrue(modification_finished.is_set())
        self.assertEqual(out["status"], "approved")

        c0 = self.svc.claim_chunk("u_applicant", rid, 0)
        self.assertIn("c*****@example.com", c0["content"])
        self.assertNotIn("race@x.com", c0["content"])
