# AWiki Lite CLI

AWiki Lite CLI 是 AWiki 的精简 Python 命令行客户端。v1 只计划支持四类能力：注册单一身份、普通私聊、普通群聊和附件传输。它不会包含 Rust 版 `awiki-cli-rs2` 的 daemon、多设备、恢复、端到端加密、邮件或插件系统。

当前仓库处于架构初始化阶段：命令面、依赖边界、基础设施接口和测试工具已经建立，业务命令会明确返回“尚未实现”。完整实施顺序和验收标准见 [v1 架构与实施计划](docs/plan/v1-architecture.md)。

## 开发环境

要求 Python 3.10+、`uv`，以及同级目录中的 ANP Python SDK：

```text
awiki-space/
├── anp/anp/
└── awiki-lite-cli/
```

初始化并检查项目：

```bash
uv sync --group dev
uv run awiki-lite --help
uv run pytest
uv run ruff check .
uv run mypy src
```

CLI 的预留命令面如下：

```bash
awiki-lite register
awiki-lite dm send DID "hello"
awiki-lite dm inbox
awiki-lite group create "Team"
awiki-lite group send GROUP_DID "hello"
awiki-lite attachment send FILE --to DID
```

默认服务地址为 `https://awiki.info`，后续实现可用 `AWIKI_USER_SERVICE_URL`、`AWIKI_MESSAGE_SERVICE_URL` 和 `AWIKI_LITE_STATE_DIR` 覆盖。不要在仓库中保存真实身份密钥或访问令牌。
