from pathlib import Path
from threading import Barrier, Thread

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


def test_staged_registration_can_resume_without_plaintext_keys(tmp_path: Path) -> None:
    store = SecureStateStore(tmp_path / "state")
    store.stage_registration(identity(), keys(), "long passphrase value")
    assert not store.exists
    assert store.load_pending_identity() == identity()
    assert store.unlock_pending_keys("long passphrase value")
    assert b"BEGIN PRIVATE KEY" not in (store.secrets_dir / "root-key.pem").read_bytes()


def test_finalize_failure_never_publishes_half_identity(tmp_path: Path, monkeypatch) -> None:
    store = SecureStateStore(tmp_path / "state")
    store.stage_registration(identity(), keys(), "long passphrase value")
    original = store._atomic_json

    def fail_session(path, value):  # type: ignore[no-untyped-def]
        if path.name == "session.json":
            raise OSError("injected write failure")
        original(path, value)

    monkeypatch.setattr(store, "_atomic_json", fail_session)
    with pytest.raises(OSError, match="injected"):
        store.finalize_registration(identity(), "fixture-token")
    assert not store.exists
    assert store.load_pending_identity() == identity()


def test_corrupt_state_and_parent_symlink_are_rejected(tmp_path: Path) -> None:
    store = SecureStateStore(tmp_path / "state")
    store.initialize()
    (store.root / "identity.json").write_text("not json")
    with pytest.raises(StateError, match="invalid"):
        store.load_public()

    actual = tmp_path / "actual"
    actual.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(actual, target_is_directory=True)
    with pytest.raises(StateError, match="unsafe"):
        SecureStateStore(linked_parent / "state").initialize()


def test_concurrent_registration_staging_has_one_winner(tmp_path: Path) -> None:
    store = SecureStateStore(tmp_path / "state")
    barrier = Barrier(2)
    outcomes: list[str] = []

    def stage() -> None:
        barrier.wait()
        try:
            store.stage_registration(identity(), keys(), "long passphrase value")
            outcomes.append("saved")
        except IdentityExistsError:
            outcomes.append("rejected")

    threads = [Thread(target=stage) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(outcomes) == ["rejected", "saved"]
    assert store.load_pending_identity() == identity()


def test_pending_send_reuses_ids_without_storing_plaintext(tmp_path: Path) -> None:
    store = SecureStateStore(tmp_path / "state")
    first = store.prepare_send("did:wba:example.test:user:bob", "private hello")
    second = store.prepare_send("did:wba:example.test:user:bob", "private hello")
    assert second == first
    raw = (store.root / "pending-send.json").read_text()
    assert "private hello" not in raw
    with pytest.raises(StateError, match="exact same"):
        store.prepare_send("did:wba:example.test:user:bob", "different")
    store.complete_send(first)
    assert not (store.root / "pending-send.json").exists()
