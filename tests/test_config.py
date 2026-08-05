from pathlib import Path

from awiki_lite_cli.config import DEFAULT_SERVICE_URL, Settings


def test_settings_use_safe_remote_defaults(monkeypatch) -> None:
    monkeypatch.delenv("AWIKI_USER_SERVICE_URL", raising=False)
    monkeypatch.delenv("AWIKI_MESSAGE_SERVICE_URL", raising=False)
    monkeypatch.setenv("AWIKI_LITE_STATE_DIR", "/tmp/awiki-lite-test-state")

    settings = Settings.from_env()

    assert settings.user_service_url == DEFAULT_SERVICE_URL
    assert settings.message_service_url == DEFAULT_SERVICE_URL
    assert settings.state_dir == Path("/tmp/awiki-lite-test-state")


def test_settings_strip_endpoint_trailing_slashes(monkeypatch) -> None:
    monkeypatch.setenv("AWIKI_USER_SERVICE_URL", "https://users.example///")
    monkeypatch.setenv("AWIKI_MESSAGE_SERVICE_URL", "https://messages.example/")

    settings = Settings.from_env()

    assert settings.user_service_url == "https://users.example"
    assert settings.message_service_url == "https://messages.example"
