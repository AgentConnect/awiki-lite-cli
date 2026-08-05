import hashlib
import json
from pathlib import Path
from threading import Barrier, Thread

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from awiki_lite_cli.domain.models import AttachmentContext, AttachmentRef, IdentityState
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


def test_versioned_operation_blocks_different_work_and_reuses_exact_state(tmp_path: Path) -> None:
    store = SecureStateStore(tmp_path / "state")
    digest = hashlib.sha256(b"group input").hexdigest()
    first = store.prepare_operation(
        "group.send",
        "did:wba:groups.example.test:group:fixture",
        digest,
        needs_message_id=True,
        values={"group_state": "4"},
    )
    resumed = SecureStateStore(store.root).prepare_operation(
        "group.send",
        "did:wba:groups.example.test:group:fixture",
        digest,
        needs_message_id=True,
        values={"group_state": "4"},
    )
    assert resumed == first
    raw = json.loads((store.root / "pending-send.json").read_text())
    assert raw["schema_version"] == 2
    assert raw["kind"] == "group.send"
    with pytest.raises(StateError, match="exact same"):
        store.prepare_operation(
            "group.add",
            "did:wba:groups.example.test:group:fixture",
            digest,
            needs_message_id=False,
        )
    store.complete_operation(first)


def test_pending_operation_rejects_secret_fields_and_unknown_schema(tmp_path: Path) -> None:
    store = SecureStateStore(tmp_path / "state")
    digest = hashlib.sha256(b"input").hexdigest()
    with pytest.raises(StateError, match="unsafe"):
        store.prepare_operation(
            "attachment.send",
            "did:wba:example.test:user:bob",
            digest,
            needs_message_id=True,
            values={"commit_token": "must-not-persist"},
        )
    store.initialize()
    store._atomic_json(store.root / "pending-send.json", {"schema_version": 99})
    with pytest.raises(StateError, match="unsupported"):
        store.prepare_operation(
            "group.send",
            "did:wba:groups.example.test:group:fixture",
            digest,
            needs_message_id=True,
        )


def test_legacy_pending_send_is_resumed_and_can_complete(tmp_path: Path) -> None:
    store = SecureStateStore(tmp_path / "state")
    store.initialize()
    legacy = {
        "recipient_did": "did:wba:example.test:user:bob",
        "content_sha256": hashlib.sha256(b"hello").hexdigest(),
        "operation_id": "legacy-operation",
        "message_id": "legacy-message",
        "created_at": "2026-08-05T00:00:00Z",
        "proof_created": 1785888000,
        "proof_nonce": "legacy-nonce",
    }
    store._atomic_json(store.root / "pending-send.json", legacy)
    pending = store.prepare_send("did:wba:example.test:user:bob", "hello")
    assert pending.operation_id == "legacy-operation"
    store.complete_send(pending)
    assert not (store.root / "pending-send.json").exists()


def attachment_context(index: int = 1) -> AttachmentContext:
    return AttachmentContext(
        message_id=f"message-{index}",
        sender_did="did:wba:example.test:user:alice",
        message_target_did="did:wba:example.test:user:bob",
        group_did=None,
        attachment=AttachmentRef(
            attachment_id=f"attachment-{index}",
            object_uri=f"https://objects.example.test/object-{index}",
            filename=f"file-{index}.txt",
            mime_type="text/plain",
            size=index,
            sha256_b64u=f"digest-{index}",
        ),
    )


def test_attachment_context_index_round_trips_and_is_bounded(tmp_path: Path) -> None:
    store = SecureStateStore(tmp_path / "state")
    store.save_attachment_contexts([attachment_context(index) for index in range(1, 502)])
    assert store.load_attachment_context("message-501", "attachment-501") == attachment_context(501)
    with pytest.raises(StateError, match="unavailable"):
        store.load_attachment_context("message-1", "attachment-1")
    path = store.root / "attachment-contexts.json"
    assert path.stat().st_mode & 0o777 == 0o600
    raw = path.read_text()
    for forbidden in ("download_ticket", "upload_headers", "commit_token"):
        assert forbidden not in raw


def test_attachment_context_rejects_non_https_and_corrupt_index(tmp_path: Path) -> None:
    store = SecureStateStore(tmp_path / "state")
    unsafe = attachment_context()
    unsafe = AttachmentContext(
        unsafe.message_id,
        unsafe.sender_did,
        unsafe.message_target_did,
        unsafe.group_did,
        AttachmentRef(
            unsafe.attachment.attachment_id,
            "http://objects.example.test/object",
            unsafe.attachment.filename,
            unsafe.attachment.mime_type,
            unsafe.attachment.size,
            unsafe.attachment.sha256_b64u,
        ),
    )
    with pytest.raises(StateError, match="invalid"):
        store.save_attachment_contexts([unsafe])
    store.initialize()
    store._atomic_json(
        store.root / "attachment-contexts.json", {"schema_version": 99, "contexts": []}
    )
    with pytest.raises(StateError, match="unsupported"):
        store.load_attachment_context("message", "attachment")
