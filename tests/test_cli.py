from typer.testing import CliRunner

from awiki_lite_cli.cli import app
from awiki_lite_cli.infrastructure.rpc import JsonRpcFailure

runner = CliRunner()


def test_root_help_exposes_only_v1_capability_groups() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    for command in ("register", "dm"):
        assert command in result.stdout
    assert "group" not in result.stdout
    assert "attachment" not in result.stdout


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
