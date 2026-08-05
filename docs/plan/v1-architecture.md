# AWiki Lite CLI v1 架构与实施计划

状态：Draft
日期：2026-08-05

## 1. 背景与目标

现有 Rust 仓库 `../awiki-cli-rs2` 已覆盖 daemon、多设备、身份恢复、E2EE、本地数据库、邮件和运行时插件等完整产品能力，学习成本和维护面都较大。本项目用 Python 提供一个可阅读、可安装、可脚本化的最小客户端，复用现有 User Service、Message Service 和 `../anp/anp` Python SDK，不复制完整客户端内核。

v1 的成功标准只有四项：

1. 注册一个本机单身份并安全保存凭据；
2. 发送和读取不带 E2EE 的私聊文本；
3. 创建群、添加成员、发送和读取不带 E2EE 的群消息；
4. 在私聊或群聊中发送、下载附件。

明确不做：多设备加入/撤销、身份恢复、端到端加密、daemon/后台同步、TUI、邮件、联系人、消息搜索、推送、插件、自动升级和 Rust 本地数据库兼容迁移。

## 2. 外部契约与设计依据

- ANP SDK：`../anp/anp`，使用 DID WBA、one-device Manifest、W3C proof 和 RFC 9421 origin proof 能力。
- 注册：User Service `POST /user-service/handle/rpc` 的 `send_otp`，以及 `POST /user-service/did-auth/rpc` 的 `register`。
- 私聊：Message Service `/im/rpc` 的 `direct.send`、`inbox.get`、`direct.get_history`。
- 群聊：`group.create`、`group.add`、`group.send`、`group.list_messages`。
- 附件：`attachment.create_slot` → HTTPS `PUT upload_uri` → `attachment.commit_object` → Direct/Group Base 附件消息；下载使用 `attachment.get_download_ticket`。

所有消息固定为 `transport-protected`；不得导入或调用 Direct/Group E2EE 路径。服务地址默认 `https://awiki.info`，可通过环境变量覆盖。

## 3. 目录结构

```text
awiki-lite-cli/
├── docs/plan/                 # 架构、范围、里程碑和验收记录
├── src/awiki_lite_cli/
│   ├── cli.py                 # Typer 根命令，只负责装配
│   ├── commands/              # register/dm/group/attachment 参数与输出
│   ├── application/           # 用例端口、编排和稳定错误模型
│   ├── domain/                # 身份、消息、群和附件值对象
│   └── infrastructure/        # ANP adapter、HTTP JSON-RPC、状态文件
└── tests/                     # 与 src 分层对应的单元/契约测试
```

依赖方向必须保持为 `commands → application → domain`。`infrastructure` 实现 application ports；domain 不依赖 Typer、HTTPX、文件系统或 ANP SDK。命令处理器不直接构造 JSON-RPC payload。

## 4. Python 模块依赖

| 依赖 | 用途 | 约束 |
|---|---|---|
| `anp==0.9.1` | DID、Manifest、proof、协议常量 | `uv` 强制映射到 `../anp/anp` editable 源码 |
| `typer` | 类型化命令和子命令 | CLI 层专用 |
| `httpx` | 复用连接的异步 RPC、流式下载 | 基础设施层专用 |
| `platformdirs` | 跨平台状态目录 | 不存储到仓库目录 |
| `pytest` / `pytest-asyncio` | 单元与异步契约测试 | 仅开发依赖 |
| `ruff` / `mypy` | 格式、lint、严格类型检查 | 合并门禁 |

不引入 ORM、数据库、依赖注入框架、Web 框架或另一个密码学实现。ANP 已提供的协议/签名能力不得在本仓库重复实现。

## 5. 运行时架构与本地状态

```text
Typer command
    → application use case
        → ANP identity/proof adapter
        → User/Message JSON-RPC gateway
        → secure local state store
```

默认状态目录由 `platformdirs` 决定，允许 `AWIKI_LITE_STATE_DIR` 覆盖。只保存一个 `identity.json`、对应私钥文件、Bearer token 和少量分页游标。秘密文件权限必须为 `0600`，写入采用同目录临时文件加原子替换；日志和异常不得输出 token、OTP 或私钥。没有恢复能力意味着删除状态目录即永久丢失身份控制权，CLI 必须在注册前明确提示。

User Service 当前要求新客户端提交 one-device Manifest。这里的 Manifest 只用于服务端协议兼容：始终生成一个本机设备，不暴露 join、revoke、recovery 或第二设备命令。

## 6. 命令面

```text
awiki-lite register
awiki-lite dm send <DID> <TEXT>
awiki-lite dm inbox [--limit N]
awiki-lite dm history <DID> [--limit N]
awiki-lite group create <NAME>
awiki-lite group add <GROUP_DID> <MEMBER_DID>
awiki-lite group send <GROUP_DID> <TEXT>
awiki-lite group messages <GROUP_DID> [--limit N]
awiki-lite attachment send <FILE> (--to <DID> | --group <GROUP_DID>)
awiki-lite attachment download <MESSAGE_ID> <ATTACHMENT_ID>
```

`register` 是交互流程：校验 Handle → 发送 scoped OTP → 读取 OTP → 由 ANP SDK 生成并签名 DID/Manifest → 注册 → 保存状态。所有写操作生成稳定的 `operation_id`/`message_id`，同一次自动重试必须复用它们。读取采用显式命令和分页，不启动后台进程。

## 7. 里程碑与验收

### M0：仓库骨架（本次初始化）

- 建立 `uv`、Typer、src layout、四类命令占位、ANP adapter、RPC helper 和测试门禁。
- `uv run awiki-lite --help`、pytest、Ruff、mypy 全部通过。

### M1：单身份注册

- 实现手机号 OTP 注册和 one-device Manifest；原子保存身份。
- 测试重复注册、Handle 冲突、错误 OTP、网络中断和敏感信息脱敏。
- 真实 User Service 注册后可用返回 token 调用本人接口。

### M2：普通私聊

- ANP origin proof 封装 `direct.send`；实现 inbox/history 分页。
- 两个真实测试身份互发文本，离线后仍能拉取；确认没有 E2EE profile。

### M3：普通群聊

- 实现 create/add/send/messages，固定 Group Base + `transport-protected`。
- 三个身份完成建群、加成员、互发与分页读取；非成员发送得到稳定错误。

### M4：附件

- 流式计算 SHA-256 和大小，完成 slot/upload/commit，再发送 manifest。
- 私聊和群聊各覆盖上传、下载、摘要校验；失败上传执行 abort，不把本地路径发到服务端。

### M5：发布门禁

- 单元测试覆盖成功、无身份、401、JSON-RPC error、超时和幂等冲突。
- 运行 `uv run pytest`、`uv run ruff check .`、`uv run ruff format --check .`、`uv run mypy src`、`uv build`。
- 在远程 `awiki.info` 环境完成注册、私聊、群聊和附件端到端冒烟测试，补齐 README 安装与使用示例。

## 8. 风险与控制

- 服务端契约仍在演进：payload builder 集中在 infrastructure adapter，并用冻结 fixture 做契约测试。
- 本地 path source 不适合独立 CI clone：CI 在实现阶段同时 checkout `agent-network-protocol/anp` 的匹配 revision，发布时再验证 PyPI `anp==0.9.1` 等价性。
- 无恢复是产品取舍，不是遗漏：首次注册必须提示备份不受支持，v1 不提供任何“看似恢复”的命令。
- 附件可能较大：禁止一次性读入内存；上传、下载、摘要计算均使用流式处理和明确大小上限。

完成定义：只有四项真实后端流程均通过、文档与命令一致、未出现范围外命令或 E2EE/multi-device 依赖时，v1 才可标记完成。
