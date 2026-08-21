# AWiki Lite CLI

AWiki Lite CLI is a deliberately small AWiki client with two independent implementations:
Python and TypeScript. Both implement the same Lite v0.2 public command structure for one local
identity, ordinary transport-protected direct/group messages, and single-file plain attachments.

AWiki Lite CLI 是一个精简的 AWiki 命令行客户端，仓库内包含彼此独立的 Python 和
TypeScript 两个版本。两版遵循同一套 Lite v0.2 公开命令结构，支持一个本地身份、普通
传输保护的私聊/群聊消息和单文件普通附件。

Lite intentionally does not provide E2EE, MLS, object encryption, multiple devices, identity
recovery, member removal, multi-file messages, resumable transfer, or a persistent local message
database. 精简版有意不包含 E2EE、MLS、对象加密、多设备、身份恢复、移除群成员、多文件
消息、断点续传或持久化本地消息数据库。

## Choose a Version / 选择版本

You only need one implementation. Choose the toolchain already available on your machine; the
supported CLI commands and options are aligned. 只需选择一个版本，不需要同时安装两套。选择
电脑上已有的开发环境即可，两版支持的 CLI 命令和参数已经对齐。

| Implementation / 版本 | Location / 位置 | Requirements / 运行环境 | Command prefix / 命令前缀 |
|---|---|---|---|
| Python | repository root / 仓库根目录 | Python 3.10+ and `uv` | `uv run awiki-lite` |
| TypeScript | `typescript/` | Node.js 20.11+ and pnpm 9.15.x | `pnpm exec awiki-lite-ts` |

The two implementations do not call each other and do not share local identity files. Each uses
its own state directory, but the native listener service name is shared. Switching languages does not move an existing
identity; register and manage each implementation separately. Do not point both implementations at
the same `AWIKI_LITE_STATE_DIR`. Only install one native listener at a time; uninstall and reinstall
it when switching the listener implementation.

两个版本不会互相调用，也不会共享本地身份文件。它们各自使用独立的状态目录，但系统
listener 使用同一个服务名，不能同时安装两份。切换语言不会自动迁移已有身份，需要分别注册
和管理；不要把两版的 `AWIKI_LITE_STATE_DIR` 指向同一个目录。切换 listener 语言时，先卸载
旧版，再用新版重新安装。

## Quick Start / 快速开始

Clone the source once. 先克隆仓库：

```powershell
git clone https://github.com/AgentConnect/awiki-lite-cli.git
cd awiki-lite-cli
```

### Python

Install the Python CLI without development-only test tools, check the command, then register one
identity. 安装 Python CLI（不安装开发测试工具），检查命令，然后注册一个身份：

```powershell
uv sync --no-dev
uv run awiki-lite --help
uv run awiki-lite id register --handle alice --phone +15555550100
```

The compatible Python ANP SDK is installed automatically from PyPI. Python ANP SDK 会由 `uv`
自动从 PyPI 安装。

### TypeScript

From the repository root, enter `typescript/`, install dependencies, build `dist`, check the
command, then register one identity. 从仓库根目录进入 `typescript/`，安装依赖、构建 `dist`、
检查命令，然后注册一个身份：

```powershell
cd typescript
pnpm install
pnpm build
pnpm exec awiki-lite-ts --help
pnpm exec awiki-lite-ts id register --handle alice --phone +15555550100
```

`pnpm install` automatically downloads `@awiki/anp-typescript-sdk@0.9.3` from npm; no sibling ANP
repository is needed. The TypeScript Lite CLI itself is currently run from this source checkout and
is marked private in `package.json`, so it is not installed globally from npm.

`pnpm install` 会自动从 npm 下载 `@awiki/anp-typescript-sdk@0.9.3`，不需要额外克隆相邻的
ANP 仓库。TypeScript Lite CLI 本身目前从这个源码仓库运行，`package.json` 标记为 private，
因此不是通过 npm 全局安装的公开 CLI 包。

Both implementations use `https://awiki.ai` by default. Tests and self-hosted deployments may
explicitly override `AWIKI_USER_SERVICE_URL`, `AWIKI_MESSAGE_SERVICE_URL`, and
`AWIKI_LITE_STATE_DIR`. An identity registered on another deployment must override both service
URLs so the DID domain and server still match.

两个版本默认都连接 `https://awiki.ai`。测试或自建服务可以显式设置
`AWIKI_USER_SERVICE_URL`、`AWIKI_MESSAGE_SERVICE_URL` 和 `AWIKI_LITE_STATE_DIR`。如果身份在
其他服务上注册，必须同时修改两个服务地址，确保 DID 域名和实际服务器一致。
Use `AWIKI_LITE_CA_BUNDLE` to trust an explicit private CA when connecting to a local or
self-hosted Open Server; TLS verification remains enabled.
For an explicitly trusted local/private attachment data plane, also set
`AWIKI_LITE_ALLOW_PRIVATE_NETWORK=1`. This weakens the default SSRF boundary and must not be used
for untrusted service endpoints.

Registration also performs the Message Service's one-time Sync V2 device initialization. There is
no extra command to run: Lite stores a random installation ID locally and reuses it only when an
interrupted initialization must be retried. An identity created by an older Lite version is
initialized automatically if its first inbox/history query returns an empty page. The server's
`tail_only` rule means messages from before that device initialization are not copied into the new
device's history. Accounts that require full historical recovery must use the full AWiki CLI;
Lite does not download or maintain a local message database.

注册时还会自动完成 Message Service 所需的一次性 Sync V2 设备初始化，不需要用户再执行额外
命令。Lite 只在本地保存一个随机安装 ID；如果初始化中断，重试会继续使用同一个 ID。旧版 Lite
创建的身份如果第一次读取收件箱/历史得到空页，也会自动补做设备登记。服务器的 `tail_only`
规则决定了登记之前的消息不会倒灌到这个新设备。需要恢复完整旧历史的账号应使用完整版 AWiki
CLI；Lite 不下载或维护本地消息数据库。

## Common Commands / 常用命令

The examples below use Python. For TypeScript, run from `typescript/` and replace
`uv run awiki-lite` with `pnpm exec awiki-lite-ts`; all following subcommands and options stay the
same. 下列示例使用 Python。TypeScript 用户在 `typescript/` 目录中把命令前缀
`uv run awiki-lite` 替换为 `pnpm exec awiki-lite-ts` 即可，后面的子命令和参数不变。

```bash
uv run awiki-lite id register --handle alice --phone +15555550100
uv run awiki-lite msg send --to bob --text 'hello'
uv run awiki-lite msg inbox --limit 20
uv run awiki-lite msg history --with bob.awiki.ai --limit 20

uv run awiki-lite group create --name 'Project room'
uv run awiki-lite group add --group 'did:wba:...:group:...' --member bob
uv run awiki-lite msg send --group 'did:wba:...:group:...' --text 'hello group'
uv run awiki-lite group messages --group 'did:wba:...:group:...'

uv run awiki-lite msg send --to bob --file ./report.pdf
uv run awiki-lite msg send --group 'did:wba:...:group:...' --file ./report.pdf
uv run awiki-lite msg attachment download --message-id MESSAGE_ID --attachment-id ATTACHMENT_ID --output ./downloads
uv run awiki-lite id refresh-token

# Real-time sync hints / 前台接收实时同步提示，按 Ctrl-C 停止
uv run awiki-lite runtime listener run
# One JSON event then exit / 输出一个 JSON 事件后退出
uv run awiki-lite runtime listener run --once --json

# Native per-user service / 安装和管理当前用户的系统服务
uv run awiki-lite runtime listener install
uv run awiki-lite runtime listener start
uv run awiki-lite runtime listener status --json
uv run awiki-lite runtime listener restart
uv run awiki-lite runtime listener stop
uv run awiki-lite runtime listener uninstall
```

For private text, use standard input to avoid storing the text in shell history or process
arguments. 私密文本可以从标准输入传入，避免出现在 shell 历史和进程参数中：

```bash
printf '%s' 'private message' | uv run awiki-lite msg send --to 'did:wba:...' --stdin
printf '%s' 'private group message' | uv run awiki-lite msg send --group 'did:wba:...' --stdin
printf '%s' 'private caption' | uv run awiki-lite msg send --to 'did:wba:...' --file ./report.pdf --stdin
```

Direct peers and group members accept an exact `did:wba` identifier, a full handle such as
`bob.awiki.ai`, or a bare handle such as `bob` / `@bob`. A bare handle uses the current identity's
domain. Handle lookup is stateless and verifies the remote handle and DID documents; exact DIDs do
not trigger lookup.

私聊对象和群成员可以填写完整 `did:wba`、完整 handle（例如 `bob.awiki.ai`），也可以只写
`bob` 或 `@bob`。短 handle 会自动使用当前身份的域名。handle 查询不会保存联系人或缓存，
并会验证远程 handle 和 DID 文档；直接填写完整 DID 时不会额外查询。

Refresh the corresponding inbox/history/group messages before downloading so the CLI has an
authenticated Manifest context. Downloads never overwrite an existing file. 下载附件前应先刷新
对应的收件箱、私聊历史或群消息，让 CLI 保存经过认证的附件上下文；下载不会覆盖已有文件。

## Password and Identity / 密码与身份

- Registration asks for the SMS OTP, a new local key passphrase, and passphrase confirmation.
  注册时需要输入短信 OTP、本地密钥密码，并再次确认密码。
- The passphrase must contain at least 12 characters. It encrypts private keys locally and is never
  uploaded or saved. 密码至少 12 个字符，只用于在本地加密私钥，不会上传或保存。
- Sending text or attachments, creating a group, adding a member, and refreshing a session require
  the passphrase because those operations sign a request. 发送文本或附件、创建群、添加成员和
  刷新会话需要密码，因为这些操作必须使用私钥签名。
- Reading inbox/history/group data, downloading a previously discovered attachment, and running the
  listener do not unlock the private key. 读取收件箱、历史和群数据、下载已经发现的附件以及
  运行 listener 不会解锁私钥，因此不要求输入密码。
- Losing either the state directory or passphrase permanently loses control of the identity; Lite
  v0.2 has no recovery. 状态目录或密码任意一个丢失都会永久失去该身份，Lite v0.2 没有恢复功能。

The listener follows the Rust CLI's `/im/ws` contract: it authenticates with the saved exact-device
Bearer token, requires the `awiki.sync.changed.v2` subprotocol, sends protocol Ping frames every 60
seconds, and reconnects with a bounded 1–30 second exponential delay. It emits change hints only;
use the existing inbox, history, or group commands to fetch authoritative content. The listener is
a foreground process and does not load private keys.

Service commands install the same listener under the native per-user manager: a systemd **user**
unit on Linux, a LaunchAgent on macOS, and an interactive logon task in Windows Task Scheduler.
Installation does not require root or an administrator. `start` installs the definition when
missing, while `restart` requires an existing installation. The generated definition captures the
active Python interpreter, state directory, and message-service URL, but never embeds the session
token, passphrase, or private key.
Reinstall the service after moving/removing the Python environment or changing those paths.

On Linux, the user service normally follows the user-manager lifetime. Keeping it active after
logout may require an administrator to enable lingering with `loginctl enable-linger USER`; the CLI
does not change this system policy. Logs are available through `journalctl --user -u
com.agentconnect.awiki-lite-listener.service`. macOS logs are written below the state directory's
`logs/` folder; Windows state is visible in Task Scheduler under `AgentConnect`.

## Key and Transfer Security

Private keys are passphrase-encrypted PKCS#8 PEM files; no Keychain is used, the passphrase is not
saved, and unlocked keys are not cached. On POSIX, state directories are mode `0700` and files are
mode `0600`; on Windows they use a protected current-user/SYSTEM ACL. Writes are atomic and reject
unsafe symlink targets.

Unknown-result retries retain stable IDs, timestamps, a proof nonce, lifecycle stage, target DID,
and content fingerprints—but no message/caption plaintext, proof signature, private key, upload
header, commit token, or download ticket. Uploads accept one regular non-symlink file and verify it
through one file descriptor. Downloads use sender-DID-bound one-time tickets, reject redirects,
stream into a `0600` temporary file, verify size and SHA-256, and publish atomically without
overwrite.

Losing the state directory or passphrase permanently loses control of the identity because v0.2
has no recovery. At-rest encryption does not protect a compromised user/root session, keylogger,
weak passphrase, or process memory while a key is unlocked.

## Development Gates

The default suites are language-independent. Python does not need Node or pnpm, and TypeScript
does not need Python or uv:

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy src
uv run pytest
uv build

cd typescript
pnpm typecheck
pnpm lint
pnpm test
pnpm build
```

When both toolchains are installed, run both independent test suites with one cross-platform
command. This is only an orchestrator and does not contact a remote service.

```bash
uv run python scripts/test_all.py
```

The remote E2E is destructive, explicit opt-in, and restricted to the reviewed AWiki testing
target. It uses two dedicated test phone scopes and irreversibly deletes their account, group,
message, and object data before and after execution:

```bash
uv run python scripts/remote_group_attachment_e2e.py --target awiki-info-testing
```

The v0.2 implementation plan and execution ledger are in
[`docs/plan/v2-groups-attachments.md`](docs/plan/v2-groups-attachments.md). The v0.1 record remains
in [`docs/plan/v1-registration-direct.md`](docs/plan/v1-registration-direct.md).
