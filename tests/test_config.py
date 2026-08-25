from pathlib import Path

import pytest

from awiki_lite_cli.config import DEFAULT_SERVICE_URL, Settings


def test_settings_use_safe_remote_defaults(monkeypatch) -> None:
    monkeypatch.delenv("AWIKI_USER_SERVICE_URL", raising=False)
    monkeypatch.delenv("AWIKI_MESSAGE_SERVICE_URL", raising=False)
    monkeypatch.setenv("AWIKI_LITE_STATE_DIR", "/tmp/awiki-lite-test-state")

    settings = Settings.from_env()

    assert DEFAULT_SERVICE_URL == "https://awiki.ai"
    assert settings.user_service_url == DEFAULT_SERVICE_URL
    assert settings.message_service_url == DEFAULT_SERVICE_URL
    assert settings.state_dir == Path("/tmp/awiki-lite-test-state")


def test_settings_strip_endpoint_trailing_slashes(monkeypatch) -> None:
    monkeypatch.setenv("AWIKI_USER_SERVICE_URL", "https://users.example///")
    monkeypatch.setenv("AWIKI_MESSAGE_SERVICE_URL", "https://messages.example/")

    settings = Settings.from_env()

    assert settings.user_service_url == "https://users.example"
    assert settings.message_service_url == "https://messages.example"


def test_settings_parse_private_network_and_validate_ca_bundle(monkeypatch, tmp_path: Path) -> None:
    ca_bundle = tmp_path / "ca.pem"
    ca_bundle.write_text("not a certificate", encoding="ascii")
    monkeypatch.setenv("AWIKI_LITE_CA_BUNDLE", str(ca_bundle))
    monkeypatch.setenv("AWIKI_LITE_ALLOW_PRIVATE_NETWORK", "YES")

    settings = Settings.from_env()

    assert settings.ca_bundle == ca_bundle
    assert settings.allow_private_network is True
    with pytest.raises(ValueError, match="readable CA bundle"):
        settings.tls_context()
