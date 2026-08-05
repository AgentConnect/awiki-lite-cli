from typer.testing import CliRunner

from awiki_lite_cli.cli import app
from awiki_lite_cli.commands.direct import _save_attachment_contexts
from awiki_lite_cli.domain.models import AttachmentRef, ChatMessage
from awiki_lite_cli.infrastructure.rpc import JsonRpcFailure
from awiki_lite_cli.infrastructure.state import SecureStateStore

runner = CliRunner()


def test_root_help_exposes_only_implemented_capability_groups() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    for command in ("register", "dm", "group", "attachment"):
        assert command in result.stdout


def test_attachment_help_exposes_only_completed_commands() -> None:
    result = runner.invoke(app, ["attachment", "--help"])
    assert result.exit_code == 0
    assert "send" in result.stdout
    assert "download" in result.stdout


def test_group_help_exposes_only_v02_commands() -> None:
    result = runner.invoke(app, ["group", "--help"])
    assert result.exit_code == 0
    for command in ("create", "list", "info", "members", "add", "send", "messages"):
        assert command in result.stdout
    for command in ("remove", "leave", "e2ee"):
        assert command not in result.stdout


def test_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == "0.1.0"


def test_dm_send_requires_registered_identity(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("AWIKI_LITE_STATE_DIR", str(tmp_path / "missing"))
    result = runner.invoke(
        app,
        ["dm", "send", "did:wba:example.com:agents:bob", "hello"],
        input="long passphrase value\n",
    )

    assert result.exit_code == 1
    assert "not registered" in result.stderr


def test_register_input_error_uses_exit_two(monkeypatch) -> None:
    async def invalid(handle: str, phone: str):  # type: ignore[no-untyped-def]
        raise ValueError("invalid handle")

    monkeypatch.setattr("awiki_lite_cli.commands.identity._register", invalid)
    result = runner.invoke(app, ["register", "--handle", "bad", "--phone", "+15555550100"])
    assert result.exit_code == 2
    assert "Invalid input" in result.stderr


def test_register_remote_error_redacts_service_message(monkeypatch) -> None:
    async def rejected(handle: str, phone: str):  # type: ignore[no-untyped-def]
        raise JsonRpcFailure(1400, "bad OTP 123456", {"access_token": "secret-token"})

    monkeypatch.setattr("awiki_lite_cli.commands.identity._register", rejected)
    result = runner.invoke(app, ["register", "--handle", "alice", "--phone", "+15555550100"])
    assert result.exit_code == 1
    assert "JSON-RPC code 1400" in result.stderr
    assert "123456" not in result.output
    assert "secret-token" not in result.output


def test_direct_projection_context_is_saved_for_later_download(tmp_path) -> None:  # type: ignore[no-untyped-def]
    attachment = AttachmentRef(
        "att-direct",
        "https://objects.example.test/object-direct",
        "direct.txt",
        "text/plain",
        1,
        "a" * 43,
    )
    message = ChatMessage(
        "message-direct",
        "did:wba:example.test:user:alice:e1_fixture",
        "did:wba:example.test:user:bob:e1_fixture",
        "",
        attachments=(attachment,),
    )
    store = SecureStateStore(tmp_path / "state")
    _save_attachment_contexts(store, [message])
    context = store.load_attachment_context("message-direct", "att-direct")
    assert context.message_target_did == message.target_did
    assert context.group_did is None
    assert context.attachment == attachment
