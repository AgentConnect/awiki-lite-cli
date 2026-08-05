# AWiki Lite CLI v0.2 实施 Plan（普通群聊 + 附件）

状态：Pending

创建日期：2026-08-06

目标版本：`0.2.0`

前置版本：`0.1.0` 注册与普通私聊已经完成；本文件是 v0.2 唯一实施与验收依据。

## 1. 版本目标

v0.2 在不扩大身份与同步模型的前提下增加两类能力：

1. 创建普通私有群、按精确 DID 添加成员、发送文本并查看群消息；
2. 向私聊或群聊发送单个普通附件，并安全下载和校验附件。

所有消息继续使用 TLS/服务端权限保护，不提供端到端加密。实现必须复用 v0.1 的单身份、Bearer session、安全状态仓库、ANP origin proof 和完全同 payload 幂等重试。

## 2. 范围边界

### 2.1 包含

- `anp.group.base.v1`、`transport-protected` 普通群；
- 群创建、群列表/详情、成员列表、按 DID 添加成员、文本发送、消息历史；
- `anp.attachment.v1` control plane；
- `attachment.create_slot`、HTTPS PUT、`attachment.commit_object`、失败时 best-effort `attachment.abort_object`；
- Direct Base 和 Group Base 的 `application/anp-attachment-manifest+json` 消息；
- `attachment.get_download_ticket`、流式下载、大小与 SHA-256 校验、原子落盘；
- 两个真实测试身份的普通群和 direct/group attachment 远程 E2E。

### 2.2 不包含

- Group E2EE、MLS、KeyPackage、Welcome/Commit、群恢复或设备级成员；
- Direct E2EE、`object-e2ee`、附件密钥/nonce 或客户端加密；
- Handle 成员解析、公开群发现、open-join、邀请/审批；
- 移除成员、离群、管理员转让、群资料/策略更新、回复、编辑、撤回、搜索；
- 多附件消息、断点续传、分片上传、后台上传、缩略图和媒体转码；
- daemon、WebSocket、push、可靠同步 v2 或 SQLite 消息数据库。

## 3. 权威参考

实现前必须重新核对当前代码，不能根据本 Plan 猜测 wire shape：

| 主题 | 参考位置 |
|---|---|
| 群协议与 schema | `../message-service/docs/api/ANP-client-server-api-group.md`、`ANP-client-server-api-group-schema-examples.md` |
| 附件协议与 schema | `../message-service/docs/api/ANP-client-server-api-attachment.md`、`ANP-client-server-api-attachment-schema-examples.md` |
| 服务端验证器 | `../message-service/crates/im-group/`、`im-attachment/`、`im-binding/` |
| Rust 普通群编排 | `../awiki-cli-rs2/crates/im-core/src/internal/group_runtime/`、`internal/wire/group.rs` |
| Rust 附件编排 | `../awiki-cli-rs2/crates/im-core/src/internal/attachment_runtime/`、`internal/wire/attachment.rs` |
| 现有服务 E2E | `../awiki-system-test/tests_v2/message_service/test_group_local.py`、`test_attachment_local.py` |
| ANP proof | `../anp/anp/anp/proof/` |

冲突时以 Message Service 当前 validator 和公开 API 文档为准；Rust CLI 只作为编排、错误恢复和文件安全参考。

## 4. 固定协议决策

### 4.1 普通群

- endpoint 固定为本域 `POST /im/rpc`；
- profile 固定为 `anp.group.base.v1`，security profile 固定为 `transport-protected`；
- 创建群前调用 `anp.get_capabilities`，要求公开 `anp.group.base.v1`、`transport-protected` 和 `text/plain`，并从响应取得精确 `service_did`；
- `group.create` target 为 `kind=service` 和该 `service_did`；其他标准操作 target 为 `kind=group` 和精确 Group DID；
- 创建策略固定为私有、`admin-add`、附件允许、最大 500 人；owner/admin/member 权限使用服务端标准 policy；
- `group.add` v0.2 只接受 `member_did`，role 固定为 `member`；
- 状态改变方法和 `group.send` 必须携带由 ANP SDK 生成的 origin proof；
- 文本发送只允许 `text/plain` 和 `body.text`；附件发送只允许标准 attachment manifest content type 和 `body.payload`；
- 标准成功依赖规定的响应字段与跨域时的 `group_receipt`，不依赖可选 `final_acceptance` 扩展；
- 群列表和成员读取使用 `anp.group.local.v1` opaque cursor，只能原样传回；`group.list_messages` 使用同一 profile 的 `since_seq/next_since_seq`，不得误用可靠同步 v2 cursor/checkpoint；
- `group.list_messages` 只投影普通文本与普通附件 Manifest，过滤 E2EE、MLS、system/control 和未知类型。

### 4.2 普通附件

- v0.2 明确选择 `anp.attachment.v1`，不得静默切换 v2；实现前通过 capability 确认 v1 可用；
- control plane 使用 Bearer session，不生成独立 attachment origin proof；
- create/commit/abort target 为本域 capability 返回的精确 `service_did`；
- `attachment_id`、每个 control operation ID 和最终消息 ID 均由客户端生成并持久化幂等上下文；
- 只支持 `object_encryption_mode=none` 和 `intended_message_security_profile=transport-protected`；
- 上传使用服务端返回的 HTTPS `upload_uri` 和明确 allowlist 的 `upload_headers`，禁止 redirect、代理环境变量和凭据跨 host 转发；
- Manifest 固定包含一个 attachment、SHA-256 base64url digest、对象 URI、MIME、十进制字符串 size 和 `encryption_info.mode=none`；
- 下载 ticket target 从原始消息 sender DID 的权威附件上下文解析，不允许用户提供任意 service DID；
- 数据面 GET 使用短期 ticket，禁止 redirect；下载后必须同时校验字节数和 SHA-256，失败文件不得发布到目标路径。

## 5. 命令面

```text
awiki-lite group create <NAME>
awiki-lite group list [--limit N] [--cursor CURSOR]
awiki-lite group info <GROUP_DID>
awiki-lite group members <GROUP_DID> [--limit N] [--cursor CURSOR]
awiki-lite group add <GROUP_DID> <MEMBER_DID>
awiki-lite group send <GROUP_DID> <TEXT>
awiki-lite group messages <GROUP_DID> [--limit N] [--since-seq N]

awiki-lite attachment send <FILE> (--to <DID> | --group <GROUP_DID>) [--caption TEXT]
awiki-lite attachment download <MESSAGE_ID> <ATTACHMENT_ID> [--output DIR]
```

固定 UX：

- 所有 DID 参数必须是精确 `did:wba`；不隐式做 Handle lookup；
- 需要签名时按次提示本地私钥口令，读取命令不解锁私钥；
- `attachment send` 必须且只能选择 direct 或 group target；
- 下载前必须已通过 inbox/history/group messages 取得该消息的权威 Manifest 上下文，否则提示用户先刷新对应消息列表；
- 默认使用 Manifest 的安全 basename，拒绝绝对路径、`..`、NUL、目录穿越、symlink 目标和已有文件；v0.2 不提供 overwrite；
- 成功退出 `0`，输入错误退出 `2`，认证/远端/完整性失败退出统一非零业务码；
- 终端和异常不得输出 token、upload headers、commit token、download ticket、proof signature 或本地口令。

## 6. 目标架构

```text
commands/groups.py ─────────┐
commands/attachments.py ───┼→ application workflows → domain models
                            └→ infrastructure adapters

infrastructure/
├── message_service.py       # 共享 capability、Direct Manifest send
├── group_service.py         # Group Base builders、proof、local reads
├── attachment_service.py    # P7 v1 control plane 与受限 data plane
├── state.py                 # 通用 pending operation + attachment context index
└── anp_sdk.py               # 继续作为唯一协议签名实现
```

实现规则：

- Typer 只负责参数、提示和渲染；上传/下载编排进入 application；
- 不把所有逻辑继续堆入 `message_service.py`；群和附件使用窄 adapter；
- 把 v0.1 `pending-send.json` 安全演进为可区分 direct/group/control 操作的版本化 pending schema；已有 v0.1 pending 必须可读或给出安全迁移错误；
- 每个 pending 只保存完全重建请求所需的最小非秘密数据和正文摘要，不保存消息/Caption 正文；upload headers、commit token 和 ticket 只存在于当前进程内；
- `attachment-contexts.json` 只保存从已认证消息视图取得的公开 Manifest、sender/target/group、message ID 和安全 profile，权限 `0600`、原子写、有限容量；不保存附件字节、ticket 或上传凭据；
- 同一时间仍只允许一个未知结果的状态改变操作，避免不同 CLI 进程覆盖幂等上下文。

## 7. 文件与网络安全

### 7.1 上传

- 使用 `lstat`/`O_NOFOLLOW` 打开一次，只接受当前用户可读的普通文件；拒绝 symlink、目录、FIFO、socket 和设备文件；
- 用打开后的 fd 流式计算 size 与 SHA-256，并在上传前后用 `fstat` 检查 identity/size/mtime 未变化；
- MIME 仅作为展示元数据，不作为可执行信任判断；无法推断时使用 `application/octet-stream`；
- capability 存在 `limits.max_object_bytes` 时必须在 create_slot 前本地拒绝超限文件；最终仍以服务端配额判断为准；
- PUT 流式上传，不把整个文件读入内存；超时或明确失败按协议决定 exact retry 或 abort，不把“响应未知”误判成未提交。

### 7.2 下载

- 只信任已认证消息视图中与 message/attachment ID 精确匹配的 Manifest；
- 输出目录必须是当前用户拥有的真实目录，拒绝 symlink 路径；
- 在输出目录以 `0600` 随机临时文件流式写入，边写边限制期望 size 并计算 digest；
- 完整校验后执行文件 `fsync`、原子 rename 和目录 `fsync`；不匹配时删除临时文件并返回脱敏完整性错误；
- ticket 和 upload token 不进入 URL 日志、异常字符串、测试 snapshot 或 shell 参数。

## 8. 实施步骤

### Step 01：冻结 Group/P7 v1 契约

提取 capability、Group Base、group local view、attachment control、Manifest 和数据面成功/错误 fixture；确认 `awiki.info` 当前公开 profile、limits、service DID 与响应字段。更新契约文档后再编码。

验收：每个字段能指向当前 schema/validator；fixture 无真实 DID、URI token 或凭据；明确证明运行时不会选择 E2EE、MLS、object-e2ee 或 attachment v2。

### Step 02：通用幂等状态与附件上下文

版本化 v0.1 pending send，支持 group.create/add/send、附件 create/commit/manifest send 的完全同 payload 重建；新增有界 attachment context index。

验收：进程重启、并发写、半写、损坏文件、旧 schema、不同操作冲突、秘密扫描和权限测试全部通过；已有身份/session 不被迁移破坏。

### Step 03：普通群协议 adapter

实现 capability gate、Group DID 校验、create/add/send builders、origin proof、标准响应校验及 list/info/members/messages local builders。

验收：契约 fixture 与服务端 validator 一致；非法 target、非文本、缺 proof、E2EE profile、设备 selector、错误 cursor/since-seq 和不匹配响应全部 fail closed。

### Step 04：群命令与工作流

接通 `group` 命令，默认创建私有 admin-add 群；实现列表、详情、成员、添加、文本发送和历史渲染。每个状态改变操作使用 exact retry 并区分明确拒绝与未知结果。

验收：两个身份能创建群、加入成员、双向发文本并从成员视图读取；非成员发送和无权限 add 被稳定拒绝；CLI help、退出码、空页和 cursor 输出有测试。

### Step 05：附件准备、control plane 与上传

实现安全文件打开、流式 digest、create_slot、受限 HTTPS PUT、commit 和 best-effort abort。所有返回 ID、URI、header 和 commit token 做 closed-shape 校验。

验收：正常上传、空文件、超限、文件变化、symlink/FIFO、恶意 upload URI/header、超时、digest mismatch、slot expiry、commit conflict 和清理路径有测试；无凭据泄漏。

### Step 06：Direct/Group 附件消息

构造单附件标准 Manifest，复用 Direct Base 或 Group Base origin proof 和幂等发送；读取 inbox/history/group messages 时验证并记录 attachment context。

验收：direct 与 group Manifest 均被接收方准确投影；普通文本行为无回归；attachments_allowed=false、非法 Manifest、同 ID 不同 payload 和消息发送未知结果有确定行为。

### Step 07：Ticket、下载与原子发布

从本地权威 context 解析 sender/target/group/object URI，取得一次性 ticket，流式 GET，并在 size/digest 全部匹配后原子发布文件。

验收：direct/group 下载成功；非参与者、已退群成员、缺 context、错误 sender、过期 ticket、redirect、超长响应、size/digest mismatch、目录穿越、symlink 和已有目标文件全部被拒绝且不留半文件。

### Step 08：集成、远程 E2E 与发布

更新 README、命令帮助和安全边界；增加显式 opt-in 的远程脚本，使用专用测试身份并在 finally 中按精确测试 scope 清理群、对象、消息和账号数据。

验收：本 Plan 完成定义、全部本地门禁和远程 E2E 同时通过后，状态才能改为 Done。

## 9. 测试矩阵

| 层级 | 必测内容 |
|---|---|
| Domain/Application | policy 默认值、Manifest、幂等恢复、上传/发送阶段机、context 解析 |
| State/Security | schema migration、原子写、并发、权限、symlink、秘密扫描、索引容量 |
| Group contract | create/add/send、receipt、list/info/members/messages、权限和 cursor 错误 |
| Attachment contract | create/commit/abort/ticket、closed schema、capability/limit、标准错误码 |
| Data plane | HTTPS、无 redirect、header allowlist、streaming、文件变化、size/digest 校验 |
| CLI | help、互斥 target、退出码、分页、空结果、安全文件名、stderr 脱敏 |
| Regression | v0.1 注册、私聊、401 清理和 text pending retry 全部保持通过 |
| Remote E2E | A 创建群并添加 B；双方文本；A→B direct 附件；A→群附件；B 下载并逐字节校验 |

远程 E2E 不进入默认 pytest，不打印真实手机号、OTP、token、proof、ticket、对象凭据或私钥。清理是不可恢复的破坏性操作，运行前必须验证目标为 reviewed 测试环境和专用账号 scope。

## 10. 最终验证命令

```bash
uv sync --group dev
uv run ruff format --check .
uv run ruff check .
uv run mypy src
uv run pytest
uv build
uv run python scripts/remote_group_attachment_e2e.py --target awiki-info-testing
```

远程脚本只有在 Step 08 实际落地并通过后才能加入 README；不能用 mock 或既有 Message Service 测试替代 Lite CLI 自身 E2E。

## 11. 完成定义

- v0.1 注册与普通私聊没有回归；
- 两个真实身份能创建普通私有群、添加成员、双向发送文本和读取群消息；
- direct/group 单附件均能上传、发送、授权下载并通过逐字节 digest 校验；
- 所有群消息均为 `anp.group.base.v1 + transport-protected`；附件 control 明确为 `anp.attachment.v1`；
- 没有可工作的 Group E2EE、MLS、object-e2ee、多设备、恢复或后台同步实现；
- 未知结果重试不会重复创建群、加成员、发送消息或提交附件；
- 本地状态和输出不存在口令、私钥、OTP、Bearer token、upload/commit/download 凭据或 proof signature；
- 文件系统、网络边界、Ruff、mypy、pytest、build 与真实远程 E2E 全部通过；
- README 只宣传已真实验证的能力。

## 12. 执行台账

状态值：`pending`、`in_progress`、`review`、`blocked`、`done`。

| Step | 状态 | 产出 | 验证证据 |
|---|---|---|---|
| 01 契约冻结 | done | `docs/contracts/v0.2-group-attachment-wire-contract.md` 与脱敏 fixtures | `awiki.info` capability probe：Group Base v1/P7 v1/transport-protected；focused pytest 4 passed |
| 02 状态演进 | done | schema v2 通用 pending、v0.1 legacy read、500 条 attachment context index | focused state/regression pytest 23 passed；mypy/ruff 通过 |
| 03 群 adapter | done | capability gate、Group Base proof builders、标准结果与 local view parser | focused group/ANP/direct regression pytest 12 passed；mypy/ruff 通过 |
| 04 群工作流 | done | create/list/info/members/add/send/messages CLI 与 exact-retry workflow | focused group/CLI/direct regression pytest 18 passed；mypy/ruff 通过 |
| 05 附件上传 | done | 单 fd 文件快照、P7 v1 control、受限 HTTPS 流式 PUT、best-effort abort | focused attachment/contract/state/group/direct pytest 38 passed；mypy/ruff 通过 |
| 06 附件消息 | done | 单附件 Manifest、Direct/Group send、三阶段恢复、认证投影 context | focused attachment/group/direct/CLI regression pytest 64 passed；mypy/ruff 通过 |
| 07 附件下载 | done | sender DID 服务解析、绑定 ticket、流式校验、0600 no-replace 原子发布 | focused download/attachment/group/direct/registration pytest 78 passed；mypy/ruff 通过 |
| 08 发布门禁 | pending | 文档、build、远程 E2E | 待执行 |

每个 Step 必须依次完成实现、focused tests、Review、修复、聚焦 commit 和台账回填。前一步未验证并提交，不进入下一步；任何范围、公开命令、profile 或状态格式变更必须先修改本 Plan。
