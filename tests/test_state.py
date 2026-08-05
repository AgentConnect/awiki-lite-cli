from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from awiki_lite_cli.domain.models import IdentityState
from awiki_lite_cli.infrastructure.state import (
    IdentityExistsError,
    InvalidPassphraseError,
    SecureStateStore,
    StateError,
)


def identity() -> IdentityState:
    return IdentityState(
        "did:wba:example.test:user:a:e1_x",
        "a@example.test",
        "#key",
        "dev",
        {"id": "did:wba:example.test:user:a:e1_x"},
    )


def keys() -> dict[str, object]:
    return {
        "root-key": ed25519.Ed25519PrivateKey.generate(),
        "device-signing": ed25519.Ed25519PrivateKey.generate(),
        "device-agreement": x25519.X25519PrivateKey.generate(),
    }


def test_state_encrypts_keys_and_round_trips(tmp_path: Path) -> None:
    store = SecureStateStore(tmp_path / "state")
    store.save_registration(identity(), "fixture-token", keys(), "long passphrase value")
    unlocked = store.unlock("long passphrase value")
    assert unlocked.identity.did == identity().did
    assert unlocked.session.access_token == "fixture-token"
    assert oct(store.root.stat().st_mode & 0o777) == "0o700"
    for path in store.root.rglob("*"):
        if path.is_file():
            assert oct(path.stat().st_mode & 0o777) == "0o600"
            assert b"BEGIN PRIVATE KEY" not in path.read_bytes()


def test_wrong_password_and_overwrite_are_rejected(tmp_path: Path) -> None:
    store = SecureStateStore(tmp_path / "state")
    store.save_registration(identity(), "fixture-token", keys(), "long passphrase value")
    with pytest.raises(InvalidPassphraseError, match="unlock"):
        store.unlock("another long password")
    with pytest.raises(IdentityExistsError):
        store.save_registration(identity(), "other", keys(), "long passphrase value")


def test_symlink_target_and_secret_pending_fields_are_rejected(tmp_path: Path) -> None:
    store = SecureStateStore(tmp_path / "state")
    store.initialize()
    target = tmp_path / "target"
    target.write_text("safe")
    (store.root / "identity.json").symlink_to(target)
    with pytest.raises(StateError, match="unsafe"):
        store.save_registration(identity(), "fixture-token", keys(), "long passphrase value")
    with pytest.raises(StateError, match="forbidden"):
        store.save_pending({"otp_code": "123456"})


def test_short_passphrase_is_rejected_without_writes(tmp_path: Path) -> None:
    store = SecureStateStore(tmp_path / "state")
    with pytest.raises(StateError, match="12"):
        store.save_registration(identity(), "token", keys(), "short")
    assert not store.exists
