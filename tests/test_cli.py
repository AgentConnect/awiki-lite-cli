from typer.testing import CliRunner

from awiki_lite_cli.cli import app

runner = CliRunner()


def test_root_help_exposes_only_v1_capability_groups() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    for command in ("register", "dm", "group", "attachment"):
        assert command in result.stdout


def test_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == "0.1.0"


def test_unimplemented_operation_fails_explicitly() -> None:
    result = runner.invoke(app, ["dm", "send", "did:wba:example.com:agents:bob", "hello"])

    assert result.exit_code == 2
    assert "not implemented" in result.stderr
