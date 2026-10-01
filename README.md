# 客户记录导出审批与分块领取服务（exportsvc）

零第三方依赖（仅 Python 3.11 标准库），模拟客户记录导出的**申请 → 审批
（冻结快照与遮蔽规则）→ 分块领取 → 撤销**全流程，带哈希链审计。

## 核心保证

1. **申请人不能审批自己的申请**——自审检查、角色检查与状态翻转在同一个
   `BEGIN IMMEDIATE` 事务内原子完成，并发下无法双审批、无法抢跑自审。
2. **审批即冻结**——审批时刻把当时的遮蔽规则与客户快照逐字节固化
   （`frozen_rules`、`frozen_snapshot`），并一次性生成全部 CSV 块及其
   SHA-256。审批之后再改客户记录、再调遮蔽规则，已批准导出的**任何字节**
   与摘要都不变。
3. **固定顺序分块、重复领取幂等**——块按 `chunk_index` 固定顺序产出，
   每块内容与 `sha256` 在审批时落盘；重复领取返回同一字节、同一摘要，
   状态保持 `claimed`。整体摘要为各块字节按序拼接的 SHA-256。
4. **撤销只阻止未领取块**——撤销原子地把 `available` 块置为 `revoked`
   （再领取返回 `410 CHUNK_REVOKED`）；已 `claimed` 的块状态与内容原样
   保留，仍可幂等重取——系统不声称收回已交付内容。
5. **全程可核对审计**——申请、审批、每次领取/重复领取、撤销、以及所有
   被拒绝的越权/自审/撤销尝试都写入审计表；记录带单调 `seq` 与 SHA-256
   哈希链，`POST /audit/verify` 可发现任何篡改、删除或缺号。
6. **并发与重启安全**——所有"读-判定-写"关键区在 IMMEDIATE 写事务中
   串行化；全部状态在 SQLite（WAL + `synchronous=FULL`），进程崩溃或
   重启后冻结内容、领取进度、审计链均完整。

## 运行

```bash
# 初始化并播种演示数据（3 个用户、7 条客户记录、默认遮蔽规则）
python3 -m exportsvc init /tmp/demo.db

# 启动 HTTP 服务
python3 -m exportsvc serve /tmp/demo.db --port 8080
```

演示用户（用请求头 `X-User-Id` 模拟身份）：

| 用户 | 角色 |
|---|---|
| `u_applicant` | 申请人 |
| `u_approver` / `u_clerk` | 审批人 |
| `u_admin` | 管理员（改数据、改规则、审计校验） |

## API

| 方法与路径 | 说明 |
|---|---|
| `POST /requests` | 提交申请，body `{"filter_region": "北京"}`（可省略） |
| `GET  /requests/{id}` | 申请详情（状态、冻结规则、总块数、整体摘要） |
| `GET  /requests/{id}/chunks` | 块状态清单（断点续传核对进度） |
| `POST /requests/{id}/approve` | 审批并冻结（审批人/管理员，且非申请人本人） |
| `GET  /requests/{id}/chunks/{i}` | 领取/重取第 i 块（幂等） |
| `POST /requests/{id}/revoke` | 撤销审批（仅冻结未领块） |
| `GET  /audit?request_id=...` | 审计记录（审批人/管理员） |
| `POST /audit/verify` | 审计哈希链校验（管理员） |
| `POST /admin/customers/{id}` | 修改客户记录（管理员） |
| `PUT  /admin/masking-rules/{column}` | 调整遮蔽规则（管理员） |

错误以 `{"error": CODE, "message": ...}` 返回，关键状态码：
`401` 未认证、`403` 越权（含 `SELF_APPROVAL`）、`409` 状态非法、
`410 CHUNK_REVOKED` 该块已被撤销、`404` 不存在。

## 遮蔽策略（确定性，无随机）

`plain`（原值）、`all_stars`（全星号保长）、`name`（留首字）、
`email`（本地部分留首字母+域名）、`phone`（前3后4）、
`id_card`（前6后4）。规则按列存于 `masking_rules`，审批时整体冻结。

## 测试

```bash
# 共 40 个用例，标准库 unittest，无需 pytest
python3 -m unittest discover -t . -s tests -v
```

覆盖：

* **越权**：未认证/陌生人角色/跨用户查看与领取/申请人改数据/审批人校验链
  等，且每次拒绝都有 `denied` 审计；
* **自审**：申请人审批自己必被 403，且在 3 线程同时审批（本人+2 审批人）
  ×10 轮的竞争中从未成功；
* **审批期间修改数据**：审批持锁期间发起的修改被阻塞到提交之后，冻结
  快照不含新值；审批后改数据/改规则后逐字节比对所有块不变；
* **断点重试**：同一块重复 5 次领取字节与摘要一致；中途重启后按
  块状态清单续传；乱序领取仍能按索引拼出整体摘要；
* **撤销竞争**：领取与撤销同时发起 ×25 轮（服务层）与 ×10 轮（真实
  HTTP 线程），每个块终态非 `claimed` 即 `revoked`，计数严格一致，
  已交付块撤销后仍可逐字节重取，被阻止块稳定返回 410；
* 另含哈希链篡改/删除检测、双重审批只有一次成功、同一块 12 并发只产生
  一次 `claimed` 等。

## 代码结构

```
exportsvc/
  db.py        # SQLite 连接/建表/IMMEDIATE 事务（含"拒绝留痕提交"语义）
  masking.py   # 遮蔽策略与确定性 CSV 分块渲染
  audit.py     # 审计追加、哈希链、完整性校验
  service.py   # 业务服务层（所有关键状态转换）
  api.py       # http.server HTTP 适配
  cli.py       # init / serve 与播种数据
tests/         # unittest 套件（40 用例）
```
