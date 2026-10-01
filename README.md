# 客户记录导出审批服务（Python 标准库 + SQLite）

模拟客户记录导出的**申请 → 审批（冻结快照与遮蔽规则）→ 固定顺序分块领取 → 撤销**全流程，
所有关键动作写入哈希链审计日志。仅依赖 Python 3.10+ 标准库。

## 核心不变量

| 要求 | 实现方式 |
| --- | --- |
| 申请人不能审批自己的申请 | 审批事务内校验 `applicant != approver`，身份规则独立于权限（即使同时拥有两种权限也拒绝） |
| 审批时冻结记录快照与列级遮蔽规则 | 审批在单个 `BEGIN IMMEDIATE` 事务内把客户行、遮蔽规则复制到 `snapshot_rows/snapshot_rules`，并**一次性渲染全部 CSV 块字节**存入 `chunks` |
| 审批后的记录修改/规则调整不改变导出任何字节 | 领取只读取冻结的 `chunks.content`；原表与规则表的变化与已审批导出物理隔离 |
| 固定顺序 CSV 块，重复领取字节与摘要完全相同 | 块按 `customer_id` 排序切分，`chunk_index` 唯一；内容审批时定型，`content_sha256` 随行存储，领取幂等 |
| 撤销只阻止未领取的块，不收回已交付内容 | 撤销翻转申请状态；未交付块领取被状态闸拒绝，`delivered` 块撤销后仍可重复领取同样字节 |
| 每次申请/审批/领取/撤销均可核对 | 哈希链 `audit_log`（前条 SHA-256），成功与拒绝（含越权、自审）均落审计，`/audit/verify` 检测任何篡改/删除 |
| 并发与服务重启安全 | 所有状态转换在 SQLite WAL + `BEGIN IMMEDIATE` 事务内以 `UPDATE ... WHERE status=...` 原子完成；无进程内状态，新进程打开同一库即恢复 |

## 目录

```
export_demo/
  errors.py          # 领域异常与 HTTP 状态映射
  schema.py          # 表结构、权限常量、连接/事务、种子数据
  masking.py         # 列级遮蔽规则（full/email/phone/tail4/none）
  render.py          # 确定性 CSV 渲染（CRLF、UTF-8、表头只在块0）
  audit.py           # 哈希链审计（追加/验链/篡改检测）
  service.py         # 领域服务（申请/审批/领取/撤销/查询）
  http_api.py        # stdlib ThreadingHTTPServer 适配层
  tests/             # 35 个 unittest 用例
examples/demo_flow.py
```

## 快速开始

```bash
# 端到端演示（无需起服务）
python3 examples/demo_flow.py

# 测试
python3 -m unittest discover -s export_demo/tests -v

# HTTP 服务
python3 -m export_demo.http_api --db /tmp/demo.db --port 8000
```

## HTTP API

身份通过演示用请求头 `X-User: <username>` 传递（生产应替换为会话/JWT）。

| 方法/路径 | 角色 | 说明 |
| --- | --- | --- |
| `POST /customers` | `customers.manage` | 新建/更新客户（`id` 缺省为新建） |
| `POST /rules` | `rules.manage` | 调整列遮蔽规则，只影响今后的导出 |
| `POST /exports` | `export.apply` | `{reason, chunk_size}` 创建申请 |
| `POST /exports/{id}/approve` | `export.approve` | 审批：冻结快照、生成全部块 |
| `POST /exports/{id}/revoke` | `export.revoke` | 撤销：阻止未交付块 |
| `POST /exports/{id}/chunk/{n}` | 申请人本人 | 领取/重放第 n 块（base64 内容 + sha256） |
| `GET /exports/{id}` / `GET /exports/list` | 本人或特权角色 | 查询 |
| `GET /audit` `/audit/verify` | `audit.read` | 审计列表与哈希链校验 |

```bash
curl -s -XPOST localhost:8000/exports -H 'X-User: alice' \
  -H 'Content-Type: application/json' -d '{"reason":"季度审计","chunk_size":100}'
curl -s -XPOST localhost:8000/exports/1/approve -H 'X-User: bob'
curl -s -XPOST localhost:8000/exports/1/chunk/0 -H 'X-User: alice'
```

种子账号：`alice`（仅申请）、`bob`（申请+审批，用于验证自审拦截）、
`carol`（撤销+审计）、`root`（全部权限）、`dave`（无权限）。

## 并发模型要点

- 每个请求使用独立连接，事务以 `BEGIN IMMEDIATE` 立即取得写锁；
  “读状态 → 判定 → 写状态”在同一事务内，等价于行级比较并设置（CAS）。
- 同一块并发首领：只有一个 `UPDATE chunks SET status='delivered' ... WHERE status='available'`
  成功（`rowcount==1`），其余返回冲突，客户端可安全重试（重放得到相同字节）。
- 撤销与领取竞争：结果非此即彼——领取先提交则块 `delivered` 且撤销计数包含它；
  撤销先提交则该块永远停留在 `available` 但被状态闸拒绝。两种结局都自洽，均有审计。
- 审批期间写入：快照是事务开始时的某个已提交时间点；逐行是完整提交版本，
  不会出现“新名字+旧邮箱”的撕裂行，审批后的写入进入下一次导出。

## 测试覆盖（35）

- **越权 / 自审**：无权限申请审批、有审批权的申请人自审、领取他人导出、越权查看（全部留 denied 审计）
- **快照冻结**：审批后改数据/加客户、审批后放宽遮蔽规则，导出字节不变；新导出反映新规则
- **分块与幂等**：表头只在块0、乱序领取拼接一致、重复领取字节+摘要一致、越界块、审批前领取
- **断点重试 / 重启**：部分交付后用新进程重开库，已交付块可重放、未交付块正常首领
- **撤销**：未交付被阻止、已交付不收回、重复撤销、撤销待审批
- **并发**：12 线程抢 3 块、双审批竞争、撤销/领取竞争（5 轮）、审批期间并发修改
- **审计**：哈希链完整性、篡改/删除检测、拒绝事件留痕
- **HTTP**：真实线程服务器端到端（鉴权、自审、领取、撤销、验链）
