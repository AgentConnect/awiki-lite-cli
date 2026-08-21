# AWiki Lite CLI 首个版本实施 Plan（注册 + 私聊）

状态：Done

创建日期：2026-08-05

目标版本：`0.1.0`

计划入口：本文件是首个可交付版本的唯一实施与验收依据。

## 1. 版本目标

首个版本只交付两个可真实使用的能力：

1. 用户通过 CLI 注册一个本机单身份；
2. 已注册身份通过 CLI 发送、接收和查看非端到端加密的私聊文本。

群聊和附件仍属于产品总路线，但推迟到后续版本。当前仓库里的 `group`、`attachment` 占位命令不属于本版本完成范围，也不得为了“顺手复用”提前实现。

## 2. 范围边界

### 2.1 本版本包含

- 手机号 OTP + Handle 的交互式身份注册；
- ANP Python SDK 生成 DID WBA 身份、服务端要求的 one-device Manifest 和 proof；
- 单身份本地持久化，包含 DID 文档、私钥和访问令牌；
- 按精确 DID 发送 `text/plain` 私聊；
- 拉取未读私聊、显式标记已读、按对端 DID 查看历史；
- 超时、401、JSON-RPC 业务错误和幂等重试的稳定 CLI 行为；
- 单元测试、协议契约测试以及两个真实测试身份的远程 E2E。

### 2.2 本版本不包含

- 群聊、附件、Handle 联系人解析、消息回复、撤回、编辑、搜索；
- Direct E2EE、预密钥、双棘轮或任何密文消息；
- 多设备加入/撤销、身份恢复、DID 替换或 Rust 身份迁移；
- daemon、WebSocket 常驻监听、推送、可靠同步 v2、SQLite 消息投影；
- macOS Keychain、Windows Credential Manager、Secret Service 或其他系统凭据库；
- TUI、邮件、插件、自动升级和兼容旧版 CLI 工作区。

删除本地身份目录将造成不可恢复的身份控制权丢失，这是首版明确接受的限制。注册前必须向用户展示该提示。

## 3. 参考实现与权威契约

实现前优先阅读以下同级仓库，不从旧记忆猜测 wire shape：

| 主题 | 参考位置 |
|---|---|
| Rust 注册流程 | `../awiki-cli-rs2/crates/im-core/src/internal/identity_generation.rs`、`identity_registration_pending.rs`、`identity_registration_runtime.rs` |
| Rust 注册 wire | `../awiki-cli-rs2/crates/im-core/src/internal/identity_wire/registration.rs` |
| Rust CLI 交互 | `../awiki-cli-rs2/crates/awiki-cli/src/cli_shell/onboarding_handlers.rs` |
| Rust 私聊流程 | `../awiki-cli-rs2/crates/im-core/src/messages/service.rs`、`internal/message_runtime/direct.rs`、`read.rs` |
| Rust CLI 私聊 | `../awiki-cli-rs2/crates/awiki-cli/src/cli_shell/msg_handlers.rs` |
| ANP Python SDK | `anp.authentication`、`anp.proof` |
| User Service 注册 | `../user-service/src/user_service/app/handle/`、`app/did_auth/` |
| Message Service 私聊 | `../message-service/docs/api/ANP-client-server-api-direct.md` |

若 Rust CLI 与服务端当前契约冲突，以 User Service、Message Service 当前验证器和公开 API 文档为准；Rust 代码只用于理解已验证的编排、失败恢复和用户体验。

## 4. 固定协议决策

### 4.1 注册

- Handle 校验和 scoped OTP 使用 `POST /user-service/v1/handle/rpc`；
- OTP 方法为 `send_otp`，purpose 固定为 `awiki.identity.register.v1`；
- DID 注册使用 `POST /user-service/v1/did-auth/rpc` 的 `register`；
- 必须使用 `anp` 包的公开 Python API 生成 DID、Manifest 和 W3C proof，不复制密码学实现；
- User Service 要求 one-device Manifest 时，只生成一个本机设备。Manifest 是 wire 兼容要求，不代表 CLI 支持多设备；
- User Service 当前注册校验器要求 Manifest 使用固定的六项 canonical profile bundle；
  因此 Manifest 会包含 Direct/Group E2EE profile 标识。它们只是服务端注册兼容字段，
  Lite CLI 的命令、payload builder 和运行时 feature gate 仍只允许 Direct Base；
- 注册成功发布本地身份前，使用 exact-device token 调用一次 `sync.bootstrap`；请求前先持久化随机、不透明且可重试复用的 `client_instance_id`；
- 只接受设备匹配的 `tail_only`。`compact_recovery_required` 明确报错并交由完整版 AWiki CLI 处理，Lite 不保存 recovery token，也不实现 snapshot/delta 本地投影；
- 服务地址默认 `https://awiki.ai`，测试可通过显式环境变量覆盖。

### 4.2 私聊发送

- endpoint：Message Service `POST /im/rpc`；
- method：`direct.send`；
- profile：`anp.direct.base.v1`；
- security profile：`transport-protected`；
- target：`kind=agent` 和用户输入的精确 DID；
- content type：首版只允许 `text/plain`，body 只包含 `text`；
- 每次逻辑发送生成稳定的 `message_id` 和 `operation_id`；同一请求重试必须复用；
- `auth.origin_proof` 必填，由 ANP SDK `generate_rfc9421_origin_proof` 生成；
- 成功只依赖标准字段 `accepted`、`message_id`、`operation_id`、`target_did`、`accepted_at`，不得把可选扩展缺失当作失败。

### 4.3 私聊读取

- 未读收件箱：`inbox.get` + `anp.inbox.local.v1`；
- 标记已读：`inbox.mark_read`；
- 对话历史：`direct.get_history` + `anp.direct.local.v1`；
- 三者都是本域 local-only 视图，使用 hop-level 身份认证，不生成 origin proof；
- 首版只读取 `transport-protected` 普通消息；不得请求 `direct-e2ee` selector；
- 使用服务端 `limit/skip` 或当前契约规定的游标分页，不自行拼装可靠同步 checkpoint。
- 读取命令不得根据空页推断同步状态，也不得自动 bootstrap；旧版 Lite 身份继续使用 legacy 读取，只能由用户主动执行 `id init-sync`，新身份则在注册发布本地身份前 bootstrap，避免把正常的空 inbox 或空 history 错当成未登记。

## 5. 用户命令面

```text
awiki-lite id register [--handle HANDLE] [--phone PHONE]
awiki-lite msg send --to <RECIPIENT_DID> --text <TEXT>
awiki-lite msg inbox [--limit N] [--mark-read]
awiki-lite msg history --with <PEER_DID> [--limit N]
```

固定行为：

- 缺少 Handle、手机号或 OTP 时交互式提示；通过参数提供时适合自动化测试；
- `msg` 命令在未注册时退出非零并提示先执行 `awiki-lite id register`；
- 收件箱默认只读，只有显式 `--mark-read` 才调用 `inbox.mark_read`；
- recipient 只接受 DID，不在首版隐式执行 Handle lookup；
- human output 不打印原始 token、proof、完整私钥路径或服务器内部响应；
- 成功退出码为 `0`，用户输入错误为 `2`，远端/认证错误为统一非零业务退出码。

## 6. 目标模块与依赖方向

计划实现沿用当前分层，不新增框架：

```text
commands/identity.py ─┐
commands/direct.py   ─┼→ application use cases → domain models
                      └→ application ports ← infrastructure adapters

infrastructure/
├── anp_sdk.py          # DID、Manifest、W3C proof、origin proof
├── user_service.py     # Handle/OTP/Register RPC payload
├── message_service.py  # direct.send/inbox/history/read RPC payload
├── rpc.py              # HTTPX + JSON-RPC 错误边界
└── state.py            # 单身份原子持久化与权限
```

规则：

- Typer 参数和输出只存在于 `commands/`；
- application 负责注册、发送、读取的步骤编排，不直接依赖 HTTPX；
- 所有 JSON-RPC payload builder 集中在 infrastructure；
- domain 不依赖 Typer、HTTPX、文件系统或 ANP；
- ANP SDK 是唯一密码学来源；禁止复制 Rust 密钥生成或签名代码。

## 7. 本地状态与安全要求

首版使用“用户口令加密的本地文件”，不调用 macOS Keychain，也不设计系统凭据库 adapter。状态目录由 `platformdirs` 解析，可用 `AWIKI_LITE_STATE_DIR` 显式覆盖。

### 7.1 存储结构

```text
<state-dir>/
├── identity.json             # DID、Handle、文档、验证方法和非秘密元数据
├── secrets/
│   ├── root-key.pem          # 口令加密的 PKCS#8 PEM
│   ├── device-signing.pem    # 口令加密的 PKCS#8 PEM
│   └── device-agreement.pem  # 仅当 Manifest 必需；同样加密
├── session.json              # 可撤销 access token 及过期信息，不含私钥
├── sync-installation.json    # 随机安装 ID 和 tail-only 游标，不含 token/消息
├── pending-registration.json # 响应丢失时的最小恢复上下文
└── pending-send.json         # 未知发送结果的非秘密幂等重建参数
```

`identity.json` 只能包含公开 DID 文档和非秘密元数据。任何私钥字节都不得进入该文件、`session.json`、pending 文件、日志或测试 fixture。

### 7.2 私钥加密格式

- 每把私钥独立使用 Python `cryptography` 序列化；
- encoding 固定为 PEM，format 固定为 `PrivateFormat.PKCS8`；
- encryption algorithm 使用 `BestAvailableEncryption(passphrase_bytes)`；
- 加载使用 `load_pem_private_key(data, password=passphrase_bytes)`；
- 文件内容必须是 `BEGIN ENCRYPTED PRIVATE KEY`，不得使用 `NoEncryption`、Raw 私钥或明文 PKCS#8；
- 不自行选择 AES mode、nonce、salt 或 KDF 参数，交给 `cryptography` 当前 curated PKCS#8 encryption 实现；
- 不为兼容 Rust CLI 写第二套私钥格式，首版也不导入 Rust workspace 私钥。

`BestAvailableEncryption` 的具体算法可能随 `cryptography`/OpenSSL 版本变化，因此测试验证“可加密、可解密、错误口令失败、磁盘无明文”，不把内部算法名称冻结为项目 wire contract。

### 7.3 口令生命周期

- 首次注册时通过 TTY 使用 `getpass` 输入并二次确认口令；
- 口令不得通过 CLI 参数、环境变量、配置文件、shell history 或日志传入；
- 不保存口令，不提供“记住密码”，不使用 Keychain；
- 需要签名的命令按次提示口令，只解锁本次操作所需私钥；不得启动后台解锁缓存；
- 错误口令返回稳定、脱敏错误，不区分内部解析与解密细节；
- Python 无法保证 immutable `bytes` 被可靠清零，因此实现只做 best-effort：缩短明文私钥和口令对象生命周期、避免复制、及时释放引用，并明确不声称能够抵御进程内存取证；
- 用户遗忘口令等同于永久失去该身份，本版本没有恢复或重置流程。

口令策略不做复杂字符规则，只要求足够长度并拒绝空白口令；具体最小长度在 Step 01 结合产品 UX 冻结。安全性依赖用户选择不可猜测的长口令，CLI 必须在创建时说明这一点。

### 7.4 文件系统保护

- 进程在创建状态文件前设置严格 `umask 077`；
- 状态目录权限为 `0700`，`identity.json`、`session.json`、pending 文件和所有私钥文件为 `0600`；
- 创建前检查父目录由当前用户拥有且不是符号链接；目标存在时使用 `lstat` 拒绝 symlink 和非普通文件；可用时使用 `O_NOFOLLOW`；
- 写入使用同目录、随机命名、`O_CREAT | O_EXCL` 的 `0600` 临时文件；完整写入后执行文件 `fsync`、原子 `os.replace`，再 `fsync` 父目录；
- 使用进程锁避免两个 CLI 同时注册或覆盖 session；
- 注册远端成功前不得覆盖已有可用身份；
- `pending-registration.json` 不保存 OTP、口令或私钥，只保存安全重试/对账必需的公开标识和状态；
- 异常、debug 日志、测试 snapshot 必须脱敏 Authorization、OTP、private key 和 proof signature；
- 不实现导出、导入、备份或恢复命令。

### 7.5 Session token

access token 是可撤销、可过期的会话秘密，不等同于长期私钥。Step 01 必须先确认能否通过 DID proof 按需重新取得 Message Service 会话：

- 若可以按需签发，默认不持久化 token，只保存非秘密的过期/会话元数据；
- 若当前服务端必须持久化 token，则存入独立 `session.json`，权限为 `0600`，绝不与私钥放在同一文件；
- 任何情况下 token 都不得输出到终端、日志或错误对象，401 后清除失效 session；
- 不为加密 token 而引入自定义 vault 格式；首版长期身份安全依赖加密 PKCS#8 私钥，短期 token 风险通过最小 TTL、权限和撤销控制。

### 7.6 威胁模型

本设计保护：误提交到 Git、其他普通本地用户读取、磁盘/备份文件被离线复制时的明文私钥泄漏，以及写入中断造成的身份文件损坏。

本设计不保护：已控制当前用户会话或 root 权限的恶意程序、键盘记录器、用户输入口令后对进程内存的读取、弱口令离线猜测，以及 CLI 正在签名时的进程劫持。Plan 和 README 必须如实描述该边界，不能把“未使用 Keychain”包装成与硬件或系统密钥库等价的保护。

## 8. 实施步骤

### Step 01：冻结契约和测试夹具

任务：

- 从 Rust CLI、User Service、Message Service 提取注册、会话认证、`direct.send`、inbox/history 的当前请求和响应；
- 确认新 Python CLI 使用的客户端版本 header、Bearer audience、Message Service 会话建立方式；
- 确认 one-device Manifest 的精确 profiles、key IDs、document proof 和注册 response-loss 对账路径；
- 将脱敏成功/错误响应保存为契约 fixture。

验收：每一个请求字段都能指向服务端 schema/validator 或 ANP SDK API；所有未确认项在编码前关闭，不保留“实现时再猜”的关键问题。

### Step 02：单身份状态仓库

任务：实现状态路径、加密 PKCS#8 save/load、TTY 口令交互、权限检查、原子写、已有身份保护、pending registration、session 策略和日志脱敏。不得添加 Keychain 或系统凭据库依赖。

验收：正确/错误口令、明文私钥扫描、`0700/0600`、symlink 拒绝、半写失败、损坏文件、并发写、重复注册和已有身份覆盖全部有单元测试；任何失败都不泄漏秘密或破坏已提交身份。

### Step 03：ANP 身份与 proof adapter

任务：用 PyPI `anp==0.9.2` 生成 DID WBA、协议要求的 one-device Manifest、W3C document proof 和 RFC 9421 origin proof；私钥只以加密 PKCS#8 落盘，对外只暴露首版所需的窄接口。

验收：生成文档通过 ANP SDK 自校验和 User Service schema；Manifest profile 精确匹配服务端
canonical bundle，但运行时不提供 E2EE/Group 能力；私钥文件无法在无口令时加载，磁盘扫描不存在明文 key material；代码中没有自写协议签名或 canonical JSON。

### Step 04：注册用例

任务：实现 Handle 规范化/校验、scoped OTP 发送、OTP 输入、注册请求、成功持久化和响应丢失对账。保留 Rust pending-registration 的安全思想，但不移植多设备/恢复状态机。

验收：真实 User Service 成功注册后，本地身份可再次加载且 token 可认证；错误 OTP、Handle 占用、超时、重复执行、服务端成功但响应丢失都有确定行为。

### Step 05：Message Service 认证与 Direct payload

任务：实现 Message Service session/hop authentication、服务能力预检、Direct Base 文本 payload builder、origin proof 和 JSON-RPC 错误映射。

验收：fixture 与 Message Service 当前 validator 一致；明确拒绝 E2EE profile、非文本 content type、空文本、非法 DID 和不匹配 sender DID。

### Step 06：私聊发送

任务：实现 `msg send --to`，生成并持久保留本次逻辑发送的幂等 ID，区分明确拒绝、可重试网络失败和结果未知的超时。

验收：两个测试身份同域和允许时的跨域发送成功；超时重试不产生重复消息；401、目标 DID 无效、origin proof 无效均返回稳定、脱敏错误。

### Step 07：收件箱、已读与历史

任务：实现 `msg inbox`、可选 `--mark-read` 和 `msg history`，正确处理分页、空结果、消息排序和文本投影。

验收：离线接收方能拉取消息；默认查看不改变已读状态；显式标记后消息从默认 inbox 消失；history 能看到双方文本且不混入群聊/E2EE 数据。

### Step 08：集成、文档与发布门禁

任务：补齐 CLI 文案、README 示例、端到端测试脚本、构建检查和发布说明。只记录已验证行为，不宣传群聊或附件已可用。

验收：所有完成定义通过后才能把本 Plan 状态改为 Done。

## 9. 测试矩阵

| 层级 | 必测内容 |
|---|---|
| Domain/Application | 未注册保护、输入规范化、幂等 ID 复用、错误分类 |
| State | 加密 PKCS#8、正确/错误口令、`0700/0600`、symlink、防半写、并发写、秘密脱敏、无 Keychain 调用 |
| ANP contract | DID/Manifest 校验、W3C proof、origin proof、运行时不发送 E2EE profile |
| User Service contract | validate、scoped send_otp、register 成功与全部稳定错误 |
| Message Service contract | direct.send、inbox.get、inbox.mark_read、direct.get_history |
| CLI | help、交互输入、退出码、空 inbox、分页输出、stderr 脱敏 |
| Remote E2E | 身份 A/B 注册，A→B、B→A，离线拉取、标记已读、历史查询、幂等重试 |

远程 E2E 默认使用 `https://awiki.info` 的测试环境和专用测试 Handle。不得在测试日志、CI artifact 或提交中保存手机号、OTP、token 或私钥。

## 10. 验证命令

每个 Step 运行 focused tests；最终统一运行：

```bash
uv sync --group dev
uv run ruff format --check .
uv run ruff check .
uv run mypy src
uv run pytest
uv build
uv run python scripts/remote_e2e.py --target awiki-info-testing
```

远程 E2E 是显式 opt-in 的破坏性测试，只允许 reviewed `awiki-info-testing` 目标；它在执行前后
清理两个专用测试手机号范围，不进入默认 pytest。输出不得包含手机号、OTP、token、proof 或私钥。

本次执行证据（2026-08-06）：本地 Ruff format/check、mypy、35 个 pytest 和 `uv build`
全部通过。`scripts/remote_e2e.py` 对 `https://awiki.info` 完成真实 A/B 注册、能力预检、A→B
同 payload 幂等重放、单条 inbox 投影、显式 mark-read、B→A 和双方 history；命令退出 `0`。
脚本本次报告在测试前后从两个专用 scope 清理 37 行远程数据，临时本地状态由隔离临时目录清除。

## 11. 完成定义

首个版本只有同时满足以下条件才完成：

- 新用户能在干净状态目录完成一次真实注册；
- 重启进程后仍能加载同一身份并完成认证；
- 两个真实身份能双向发送普通文本；
- 接收方离线后可以通过 inbox/history 拉取，且可显式标记已读；
- 所有 Direct 请求均为 `anp.direct.base.v1 + transport-protected`；
- 没有可工作的 E2EE、多设备、恢复、群聊或附件实现；既有占位命令不得发起远端调用；
- 所有持久化私钥均为口令加密 PKCS#8；不存在明文私钥、已保存口令或 Keychain/系统凭据库依赖；
- 本地秘密权限、symlink 防护、原子写、错误口令和日志脱敏测试通过；
- Ruff、mypy、pytest、build 和远程 E2E 全部通过；
- README 只展示真实可用的注册和私聊命令。

## 12. 执行台账

状态值：`pending`、`in_progress`、`review`、`blocked`、`done`。

| Step | 状态 | 产出 | 验证证据 |
|---|---|---|---|
| 01 契约冻结 | done | `docs/contracts/v0.1-wire-contract.md` 与 wire fixtures | 服务端 validator、ANP 0.9.1 API 与 fixture 测试 |
| 02 状态仓库 | done | encrypted PKCS#8、原子发布、并发锁、pending send adapter | `tests/test_state.py`：故障注入、损坏文件、symlink、并发和幂等状态 |
| 03 ANP adapter | done | one-device identity/document/origin proof adapter | `tests/test_anp_sdk.py` |
| 04 注册 | done | scoped OTP、注册、response-loss staged retry | `tests/test_registration.py` |
| 05 Direct 契约 | done | Bearer、能力预检、plain payload/read builders、error boundary | `tests/test_message_service.py` |
| 06 私聊发送 | done | `msg send --to` 与跨进程完全同 payload 幂等重建 | 单元测试与远程幂等重放 |
| 07 私聊读取 | done | inbox/显式 mark-read/history 与 E2EE 过滤 | `tests/test_message_workflows.py` |
| 08 发布门禁 | done | README、可重复远程 E2E、build 与本地门禁 | 35 pytest；远程 A/B 双向消息、已读、history、幂等重放通过 |

执行期间若需要改变范围、公开命令、协议 profile、状态格式或验收标准，必须先更新本 Plan，再开始对应编码。群聊和附件必须创建独立的后续版本 Plan，不得追加到本版本中。
