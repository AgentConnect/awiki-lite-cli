from pathlib import Path

from rich.text import Text
from typer.main import get_command
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
    root = get_command(app)
    visible = {name for name, command in root.commands.items() if not command.hidden}
    assert visible == {"id", "msg", "group", "runtime"}
    assert root.commands["listener"].hidden


def test_id_help_exposes_only_completed_commands() -> None:
    result = runner.invoke(app, ["id", "--help"])
    assert result.exit_code == 0
    assert "register" in result.stdout
    assert "refresh-token" in result.stdout


def test_msg_help_exposes_only_completed_commands() -> None:
    result = runner.invoke(app, ["msg", "--help"])
    assert result.exit_code == 0
    for command in ("send", "inbox", "history", "attachment"):
        assert command in result.stdout

    send_help = runner.invoke(app, ["msg", "send", "--help"])
    assert send_help.exit_code == 0
    send_output = Text.from_ansi(send_help.stdout).plain
    for option in ("--to", "--group", "--text", "--file"):
        assert option in send_output

    download_help = runner.invoke(app, ["msg", "attachment", "download", "--help"])
    assert download_help.exit_code == 0
    download_output = Text.from_ansi(download_help.stdout).plain
    for option in ("--message-id", "--attachment-id", "--output"):
        assert option in download_output


def test_group_help_exposes_only_v02_commands() -> None:
    result = runner.invoke(app, ["group", "--help"])
    assert result.exit_code == 0
    for command in ("create", "list", "get", "members", "add", "messages"):
        assert command in result.stdout
    for command in ("info", "send", "remove", "leave", "e2ee"):
        assert command not in result.stdout


def test_runtime_help_exposes_listener_commands() -> None:
    result = runner.invoke(app, ["runtime", "listener", "--help"])
    assert result.exit_code == 0
    for command in ("run", "install", "start", "stop", "restart", "status", "uninstall"):
        assert command in result.stdout


def test_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == "0.2.0"


def test_msg_send_requires_registered_identity(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("AWIKI_LITE_STATE_DIR", str(tmp_path / "missing"))
    result = runner.invoke(
        app,
        [
            "msg",
            "send",
            "--to",
            "did:wba:example.com:agents:bob",
            "--text",
            "hello",
        ],
        input="long passphrase value\n",
    )

    assert result.exit_code == 1
    assert "not registered" in result.stderr


def test_private_text_input_modes_are_mutually_exclusive() -> None:
    direct = runner.invoke(
        app,
        [
            "msg",
            "send",
            "--to",
            "did:wba:example.com:user:bob",
            "--text",
            "visible",
            "--stdin",
        ],
        input="hidden",
    )
    group = runner.invoke(
        app,
        [
            "msg",
            "send",
            "--group",
            "did:wba:example.com:group:one",
            "--text",
            "visible",
            "--stdin",
        ],
        input="hidden",
    )
    assert direct.exit_code == 2
    assert group.exit_code == 2
    assert "mutually exclusive" in direct.stderr
    assert "mutually exclusive" in group.stderr


def test_msg_send_reports_empty_text_as_invalid_input() -> None:
    cases = [
        ["msg", "send", "--to", "bob", "--text", ""],
        ["msg", "send", "--to", "bob"],
        ["msg", "send", "--group", "did:wba:example.com:group:one", "--text", ""],
        ["msg", "send", "--group", "did:wba:example.com:group:one"],
    ]
    for args in cases:
        result = runner.invoke(app, args, input="\n")
        assert result.exit_code == 2
        assert "Invalid input: message text must not be empty" in result.stderr
        assert "failed" not in result.stderr.lower()


def test_msg_send_requires_exactly_one_target() -> None:
    missing = runner.invoke(app, ["msg", "send", "--text", "hello"])
    conflicting = runner.invoke(
        app,
        [
            "msg",
            "send",
            "--to",
            "did:wba:example.test:user:a",
            "--group",
            "did:wba:example.test:group:a",
            "--text",
            "hello",
        ],
    )

    assert missing.exit_code == 2
    assert conflicting.exit_code == 2
    assert "exactly one" in missing.stderr
    assert "exactly one" in conflicting.stderr


def test_msg_send_dispatches_direct_group_and_attachment(monkeypatch, tmp_path: Path) -> None:
    calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        "awiki_lite_cli.commands.messages.direct.send",
        lambda recipient, text, stdin: calls.append(("direct", recipient, text, stdin)),
    )
    monkeypatch.setattr(
        "awiki_lite_cli.commands.messages.groups.send",
        lambda group, text, stdin: calls.append(("group", group, text, stdin)),
    )
    monkeypatch.setattr(
        "awiki_lite_cli.commands.messages.attachments.send",
        lambda file, recipient, group, caption, stdin: calls.append(
            ("attachment", file, recipient, group, caption, stdin)
        ),
    )
    attachment = tmp_path / "report.txt"

    direct = runner.invoke(
        app, ["msg", "send", "--to", "did:wba:example.test:user:a", "--text", "hello"]
    )
    group = runner.invoke(
        app,
        ["msg", "send", "--group", "did:wba:example.test:group:a", "--text", "hi"],
    )
    file = runner.invoke(
        app,
        [
            "msg",
            "send",
            "--to",
            "did:wba:example.test:user:a",
            "--file",
            str(attachment),
            "--text",
            "caption",
        ],
    )

    assert direct.exit_code == group.exit_code == file.exit_code == 0
    assert calls == [
        ("direct", "did:wba:example.test:user:a", "hello", False),
        ("group", "did:wba:example.test:group:a", "hi", False),
        (
            "attachment",
            attachment,
            "did:wba:example.test:user:a",
            None,
            "caption",
            False,
        ),
    ]


def test_numeric_options_report_invalid_input() -> None:
    for args in (
        ["msg", "inbox", "--limit", "-1"],
        ["msg", "history", "--with", "bob", "--limit", "1.5"],
        ["group", "list", "--limit", "NaN"],
        ["group", "messages", "--group", "did:wba:example.test:group:a", "--since-seq", "-1"],
    ):
        result = runner.invoke(app, args)
        assert result.exit_code == 2, args
        assert "Invalid input" in result.stderr


def test_register_input_error_uses_exit_two(monkeypatch) -> None:
    async def invalid(handle: str, phone: str):  # type: ignore[no-untyped-def]
        raise ValueError("invalid handle")

    monkeypatch.setattr("awiki_lite_cli.commands.identity._register", invalid)
    result = runner.invoke(app, ["id", "register", "--handle", "bad", "--phone", "+15555550100"])
    assert result.exit_code == 2
    assert "Invalid input" in result.stderr


def test_register_remote_error_redacts_service_message(monkeypatch) -> None:
    async def rejected(handle: str, phone: str):  # type: ignore[no-untyped-def]
        raise JsonRpcFailure(1400, "bad OTP 123456", {"access_token": "secret-token"})

    monkeypatch.setattr("awiki_lite_cli.commands.identity._register", rejected)
    result = runner.invoke(app, ["id", "register", "--handle", "alice", "--phone", "+15555550100"])
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
