"""演示数据播种与命令行入口。

``python -m exportsvc init DB_PATH`` 建库并播种：

* 用户：``u_applicant``（申请人）、``u_approver``（审批人）、
  ``u_admin``（管理员）；
* 客户记录若干（含中文示例）；
* 默认遮蔽规则：email/phone/id_card 遮蔽，其余明文。

``python -m exportsvc serve DB_PATH [--port 8080]`` 启动 HTTP 服务。
"""
from __future__ import annotations

import argparse
import sqlite3
import sys

from .api import build_server
from .audit import now_iso
from .db import init_db

SEED_USERS = [
    ("u_applicant", "申请人 张三", "applicant"),
    ("u_approver", "审批人 李四", "approver"),
    ("u_admin", "管理员 王五", "admin"),
]

SEED_CUSTOMERS = [
    ("C001", "陈晓明", "chenxm@example.com", "13800138001", "110101199003071234", "北京"),
    ("C002", "林美玲", "linml@example.cn", "13912345678", "310104199511220022", "上海"),
    ("C003", "王建国", "wangjg@example.com", "13700007788", "440305198807153456", "深圳"),
    ("C004", "赵雅婷", "zhaoyt@example.net", "13611112222", "110102199912314321", "北京"),
    ("C005", "刘志强", "liuzq@example.org", "13533334444", "320106199201019876", "上海"),
    ("C006", "孙丽华", "sunlh@example.cn", "15055556666", "440301198506071122", "深圳"),
    ("C007", "周子轩", "zhouzx@example.com", "18877778888", "330108200101023344", "杭州"),
]

SEED_RULES = {
    "email": "email",
    "phone": "phone",
    "id_card": "id_card",
}


def seed(db_path: str) -> None:
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    try:
        at = now_iso()
        conn.executemany(
            "INSERT OR IGNORE INTO users (id, display_name, role) VALUES (?, ?, ?)",
            SEED_USERS,
        )
        conn.executemany(
            """INSERT OR IGNORE INTO customers
               (id, name, email, phone, id_card, region, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [(*c, at) for c in SEED_CUSTOMERS],
        )
        for col, strategy in SEED_RULES.items():
            conn.execute(
                """INSERT OR IGNORE INTO masking_rules
                   (column_name, strategy, updated_at) VALUES (?, ?, ?)""",
                (col, strategy, at),
            )
        conn.commit()
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="exportsvc")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="initialize database and seed demo data")
    p_init.add_argument("db_path")

    p_serve = sub.add_parser("serve", help="start HTTP server")
    p_serve.add_argument("db_path")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8080)
    p_serve.add_argument("--rows-per-chunk", type=int, default=3)

    args = parser.parse_args(argv)
    if args.cmd == "init":
        seed(args.db_path)
        print(f"initialized: {args.db_path}")
        return 0
    if args.cmd == "serve":
        server = build_server(args.db_path, host=args.host, port=args.port,
                              rows_per_chunk=args.rows_per_chunk)
        print(f"serving on http://{args.host}:{args.port}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
