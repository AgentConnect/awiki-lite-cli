from typer.testing import CliRunner

from awiki_lite_cli.cli import app

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
