"""Secure single-identity state storage."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import stat
import tempfile
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives import serialization

from awiki_lite_cli.domain.models import (
    AttachmentContext,
    AttachmentRef,
    IdentityState,
    PendingOperation,
    PendingSend,
    SessionState,
    UnlockedIdentity,
)

PENDING_SCHEMA_VERSION = 2
ATTACHMENT_CONTEXT_SCHEMA_VERSION = 1
MAX_ATTACHMENT_CONTEXTS = 500


class StateError(RuntimeError):
    """Safe state error whose message contains no secret material."""


class IdentityExistsError(StateError):
    pass


class IdentityMissingError(StateError):
    pass


class PendingOperationError(StateError):
    pass


class InvalidPassphraseError(StateError):
    pass


class SecureStateStore:
    """Persist one identity with encrypted PKCS#8 keys and atomic mode-0600 files."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.secrets_dir = root / "secrets"

    def initialize(self) -> None:
        os.umask(0o077)
        self._ensure_directory(self.root)
        self._ensure_directory(self.secrets_dir)

    @property
    def exists(self) -> bool:
        return (self.root / "identity.json").is_file()

    @contextmanager
    def lock(self) -> Iterator[None]:
        self.initialize()
        path = self.root / ".lock"
        self._reject_unsafe_target(path)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def save_registration(
        self,
        identity: IdentityState,
        access_token: str,
        private_keys: Mapping[str, Any],
        passphrase: str,
    ) -> None:
        self.stage_registration(identity, private_keys, passphrase)
        self.finalize_registration(identity, access_token)

    def stage_registration(
        self,
        identity: IdentityState,
        private_keys: Mapping[str, Any],
        passphrase: str,
    ) -> None:
        """Stage encrypted keys and public retry context before remote commit."""
        self._validate_passphrase(passphrase)
        with self.lock():
            self._reject_unsafe_target(self.root / "identity.json")
            if self.exists:
                raise IdentityExistsError("a local identity already exists")
            existing_pending = self._load_pending_identity_unlocked()
            if existing_pending is not None:
                raise IdentityExistsError("a registration is already pending")
            required = {"root-key", "device-signing", "device-agreement"}
            if set(private_keys) != required:
                raise StateError("registration key set is incomplete")
            for name, key in private_keys.items():
                pem = key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.BestAvailableEncryption(passphrase.encode()),
                )
                if b"BEGIN ENCRYPTED PRIVATE KEY" not in pem:
                    raise StateError("private key encryption failed")
                self._atomic_write(self.secrets_dir / f"{name}.pem", pem)
            pending_data = {
                "did": identity.did,
                "handle": identity.handle,
                "verification_method": identity.verification_method,
                "device_id": identity.device_id,
                "did_document": identity.did_document,
            }
            self._atomic_json(self.root / "pending-registration.json", pending_data)

    def finalize_registration(self, identity: IdentityState, access_token: str) -> None:
        """Publish an already-staged identity after server acceptance."""
        with self.lock():
            if self.exists:
                raise IdentityExistsError("a local identity already exists")
            identity_data = {
                "did": identity.did,
                "handle": identity.handle,
                "verification_method": identity.verification_method,
                "device_id": identity.device_id,
                "did_document": identity.did_document,
            }
            pending = self._load_pending_identity_unlocked()
            if pending != identity:
                raise StateError("pending registration does not match the accepted identity")
            # Publish identity.json last: its presence is the committed-state marker.
            self._atomic_json(self.root / "session.json", {"access_token": access_token})
            self._atomic_json(self.root / "identity.json", identity_data)
            self.clear_pending()

    def load_public(self) -> IdentityState:
        data = self._read_json(self.root / "identity.json")
        try:
            document = data["did_document"]
            if not isinstance(document, dict):
                raise TypeError
            return IdentityState(
                did=str(data["did"]),
                handle=str(data["handle"]),
                verification_method=str(data["verification_method"]),
                device_id=str(data["device_id"]),
                did_document=document,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise StateError("local identity metadata is invalid") from exc

    def load_session(self) -> SessionState:
        data = self._read_json(self.root / "session.json")
        token = data.get("access_token")
        if not isinstance(token, str) or not token:
            raise StateError("local session is invalid")
        return SessionState(access_token=token)

    def unlock(self, passphrase: str) -> UnlockedIdentity:
        identity = self.load_public()
        session = self.load_session()
        keys = self._load_keys(passphrase)
        return UnlockedIdentity(identity, session, keys[0], keys[1], keys[2])

    def load_pending_identity(self) -> IdentityState | None:
        return self._load_pending_identity_unlocked()

    def _load_pending_identity_unlocked(self) -> IdentityState | None:
        path = self.root / "pending-registration.json"
        if not path.exists() and not path.is_symlink():
            return None
        data = self._read_json(path)
        try:
            document = data["did_document"]
            if not isinstance(document, dict):
                raise TypeError
            return IdentityState(
                str(data["did"]),
                str(data["handle"]),
                str(data["verification_method"]),
                str(data["device_id"]),
                document,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise StateError("pending registration is invalid") from exc

    def unlock_pending_keys(self, passphrase: str) -> tuple[Any, Any, Any]:
        if self.load_pending_identity() is None:
            raise IdentityMissingError("no pending registration exists")
        return self._load_keys(passphrase)

    def _load_keys(self, passphrase: str) -> tuple[Any, Any, Any]:
        try:
            keys = [
                serialization.load_pem_private_key(
                    self._read_regular(self.secrets_dir / f"{name}.pem"),
                    password=passphrase.encode(),
                )
                for name in ("root-key", "device-signing", "device-agreement")
            ]
        except (TypeError, ValueError) as exc:
            raise InvalidPassphraseError("unable to unlock identity") from exc
        return keys[0], keys[1], keys[2]

    def save_pending(self, data: Mapping[str, Any]) -> None:
        forbidden = {"otp", "otp_code", "passphrase", "private_key", "access_token"}
        if forbidden.intersection(data):
            raise StateError("pending registration contains forbidden secret fields")
        with self.lock():
            self._atomic_json(self.root / "pending-registration.json", dict(data))

    def clear_pending(self) -> None:
        path = self.root / "pending-registration.json"
        if path.exists() and not path.is_symlink():
            path.unlink()

    def clear_session(self) -> None:
        path = self.root / "session.json"
        if path.exists() and not path.is_symlink():
            path.unlink()

    def prepare_send(self, recipient_did: str, text: str) -> PendingSend:
        """Persist stable IDs before a logical send; reuse them after an unknown result."""
        content_sha256 = hashlib.sha256(text.encode()).hexdigest()
        operation = self.prepare_operation(
            "direct.send", recipient_did, content_sha256, needs_message_id=True
        )
        assert operation.message_id is not None
        return PendingSend(
            recipient_did=operation.target_did,
            content_sha256=operation.input_sha256,
            operation_id=operation.operation_id,
            message_id=operation.message_id,
            created_at=operation.created_at,
            proof_created=operation.proof_created,
            proof_nonce=operation.proof_nonce,
        )

    def prepare_operation(
        self,
        kind: str,
        target_did: str,
        input_sha256: str,
        *,
        needs_message_id: bool,
        values: Mapping[str, str] | None = None,
    ) -> PendingOperation:
        """Create or resume one versioned, non-secret idempotent operation."""
        normalized_values = dict(values or {})
        self._validate_pending_input(kind, target_did, input_sha256, normalized_values)
        path = self.root / "pending-send.json"
        with self.lock():
            if path.exists() or path.is_symlink():
                pending = self._parse_pending_operation(self._read_json(path))
                if (
                    pending.kind != kind
                    or pending.target_did != target_did
                    or pending.input_sha256 != input_sha256
                    or pending.values != normalized_values
                    or (pending.message_id is not None) != needs_message_id
                ):
                    raise PendingOperationError(
                        "another operation has an unknown result; retry the exact same command"
                    )
                return pending
            pending = PendingOperation(
                schema_version=PENDING_SCHEMA_VERSION,
                kind=kind,
                target_did=target_did,
                input_sha256=input_sha256,
                operation_id=str(uuid4()),
                message_id=str(uuid4()) if needs_message_id else None,
                created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                proof_created=int(time.time()),
                proof_nonce=secrets.token_urlsafe(12),
                values=normalized_values,
            )
            self._atomic_json(path, self._pending_operation_json(pending))
            return pending

    def complete_send(self, pending: PendingSend) -> None:
        self.complete_operation(self._operation_from_send(pending))

    def complete_operation(self, pending: PendingOperation) -> None:
        path = self.root / "pending-send.json"
        with self.lock():
            current = self._parse_pending_operation(self._read_json(path))
            if current != pending:
                raise PendingOperationError("pending send state changed unexpectedly")
            path.unlink()
            self._fsync_directory(path.parent)

    def abandon_send(self, pending: PendingSend) -> None:
        """Discard IDs only after the service explicitly rejects the operation."""
        self.abandon_operation(self._operation_from_send(pending))

    def abandon_operation(self, pending: PendingOperation) -> None:
        """Discard a pending operation only after an explicit rejection."""
        path = self.root / "pending-send.json"
        with self.lock():
            if not path.exists() and not path.is_symlink():
                return
            current = self._parse_pending_operation(self._read_json(path))
            if current == pending:
                path.unlink()
                self._fsync_directory(path.parent)

    @staticmethod
    def _parse_pending_operation(data: Mapping[str, Any]) -> PendingOperation:
        schema_version = data.get("schema_version")
        if schema_version is None:
            return SecureStateStore._parse_legacy_pending_send(data)
        if schema_version != PENDING_SCHEMA_VERSION:
            raise StateError("pending operation schema is unsupported")
        try:
            kind = str(data["kind"])
            target_did = str(data["target_did"])
            input_sha256 = str(data["input_sha256"])
            operation_id = str(data["operation_id"])
            raw_message_id = data.get("message_id")
            message_id = str(raw_message_id) if raw_message_id is not None else None
            created_at = str(data["created_at"])
            proof_created = int(data["proof_created"])
            proof_nonce = str(data["proof_nonce"])
            raw_values = data.get("values", {})
            if not isinstance(raw_values, dict) or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in raw_values.items()
            ):
                raise TypeError
            values = dict(raw_values)
        except (KeyError, TypeError, ValueError) as exc:
            raise StateError("pending operation state is invalid") from exc
        SecureStateStore._validate_pending_input(kind, target_did, input_sha256, values)
        if not operation_id or not created_at or proof_created <= 0 or not proof_nonce:
            raise StateError("pending operation state is invalid")
        if message_id is not None and not message_id:
            raise StateError("pending operation state is invalid")
        return PendingOperation(
            schema_version=PENDING_SCHEMA_VERSION,
            kind=kind,
            target_did=target_did,
            input_sha256=input_sha256,
            operation_id=operation_id,
            message_id=message_id,
            created_at=created_at,
            proof_created=proof_created,
            proof_nonce=proof_nonce,
            values=values,
        )

    @staticmethod
    def _parse_legacy_pending_send(data: Mapping[str, Any]) -> PendingOperation:
        try:
            message_id = str(data["message_id"])
            pending = PendingOperation(
                schema_version=PENDING_SCHEMA_VERSION,
                kind="direct.send",
                target_did=str(data["recipient_did"]),
                input_sha256=str(data["content_sha256"]),
                operation_id=str(data["operation_id"]),
                message_id=message_id,
                created_at=str(data["created_at"]),
                proof_created=int(data["proof_created"]),
                proof_nonce=str(data["proof_nonce"]),
                values={},
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise StateError("legacy pending send state is invalid") from exc
        SecureStateStore._validate_pending_input(
            pending.kind, pending.target_did, pending.input_sha256, pending.values
        )
        if (
            not pending.operation_id
            or not pending.message_id
            or not pending.created_at
            or pending.proof_created <= 0
            or not pending.proof_nonce
        ):
            raise StateError("legacy pending send state is invalid")
        return pending

    @staticmethod
    def _validate_pending_input(
        kind: str, target_did: str, input_sha256: str, values: Mapping[str, str]
    ) -> None:
        if not kind or not target_did or len(input_sha256) != 64:
            raise StateError("pending operation input is invalid")
        try:
            bytes.fromhex(input_sha256)
        except ValueError as exc:
            raise StateError("pending operation input is invalid") from exc
        forbidden = ("token", "secret", "password", "passphrase", "private", "proof", "header")
        if any(
            not key
            or not value
            or len(key) > 64
            or len(value) > 512
            or any(word in key.lower() for word in forbidden)
            for key, value in values.items()
        ):
            raise StateError("pending operation values are unsafe")

    @staticmethod
    def _pending_operation_json(pending: PendingOperation) -> dict[str, Any]:
        return {
            "schema_version": pending.schema_version,
            "kind": pending.kind,
            "target_did": pending.target_did,
            "input_sha256": pending.input_sha256,
            "operation_id": pending.operation_id,
            "message_id": pending.message_id,
            "created_at": pending.created_at,
            "proof_created": pending.proof_created,
            "proof_nonce": pending.proof_nonce,
            "values": pending.values,
        }

    @staticmethod
    def _operation_from_send(pending: PendingSend) -> PendingOperation:
        return PendingOperation(
            schema_version=PENDING_SCHEMA_VERSION,
            kind="direct.send",
            target_did=pending.recipient_did,
            input_sha256=pending.content_sha256,
            operation_id=pending.operation_id,
            message_id=pending.message_id,
            created_at=pending.created_at,
            proof_created=pending.proof_created,
            proof_nonce=pending.proof_nonce,
            values={},
        )

    def save_attachment_contexts(self, contexts: list[AttachmentContext]) -> None:
        """Merge authenticated public attachment projections into a bounded local index."""
        if not contexts:
            return
        for context in contexts:
            self._validate_attachment_context(context)
        path = self.root / "attachment-contexts.json"
        with self.lock():
            existing = self._load_attachment_contexts_unlocked(path)
            merged = {(item.message_id, item.attachment.attachment_id): item for item in existing}
            for context in contexts:
                key = (context.message_id, context.attachment.attachment_id)
                merged.pop(key, None)
                merged[key] = context
            retained = list(merged.values())[-MAX_ATTACHMENT_CONTEXTS:]
            self._atomic_json(
                path,
                {
                    "schema_version": ATTACHMENT_CONTEXT_SCHEMA_VERSION,
                    "contexts": [self._attachment_context_json(item) for item in retained],
                },
            )

    def load_attachment_context(self, message_id: str, attachment_id: str) -> AttachmentContext:
        path = self.root / "attachment-contexts.json"
        with self.lock():
            for context in reversed(self._load_attachment_contexts_unlocked(path)):
                if (
                    context.message_id == message_id
                    and context.attachment.attachment_id == attachment_id
                ):
                    return context
        raise StateError("attachment context is unavailable; refresh the corresponding messages")

    def _load_attachment_contexts_unlocked(self, path: Path) -> list[AttachmentContext]:
        if not path.exists() and not path.is_symlink():
            return []
        data = self._read_json(path)
        if data.get("schema_version") != ATTACHMENT_CONTEXT_SCHEMA_VERSION:
            raise StateError("attachment context schema is unsupported")
        raw_contexts = data.get("contexts")
        if not isinstance(raw_contexts, list) or len(raw_contexts) > MAX_ATTACHMENT_CONTEXTS:
            raise StateError("attachment context index is invalid")
        return [self._parse_attachment_context(value) for value in raw_contexts]

    @staticmethod
    def _attachment_context_json(context: AttachmentContext) -> dict[str, Any]:
        attachment = context.attachment
        return {
            "message_id": context.message_id,
            "sender_did": context.sender_did,
            "message_target_did": context.message_target_did,
            "group_did": context.group_did,
            "attachment": {
                "attachment_id": attachment.attachment_id,
                "object_uri": attachment.object_uri,
                "filename": attachment.filename,
                "mime_type": attachment.mime_type,
                "size": attachment.size,
                "sha256_b64u": attachment.sha256_b64u,
            },
        }

    @staticmethod
    def _parse_attachment_context(value: Any) -> AttachmentContext:
        if not isinstance(value, dict) or not isinstance(value.get("attachment"), dict):
            raise StateError("attachment context index is invalid")
        attachment = value["attachment"]
        try:
            context = AttachmentContext(
                message_id=str(value["message_id"]),
                sender_did=str(value["sender_did"]),
                message_target_did=(
                    str(value["message_target_did"])
                    if value.get("message_target_did") is not None
                    else None
                ),
                group_did=str(value["group_did"]) if value.get("group_did") is not None else None,
                attachment=AttachmentRef(
                    attachment_id=str(attachment["attachment_id"]),
                    object_uri=str(attachment["object_uri"]),
                    filename=str(attachment["filename"]),
                    mime_type=str(attachment["mime_type"]),
                    size=int(attachment["size"]),
                    sha256_b64u=str(attachment["sha256_b64u"]),
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise StateError("attachment context index is invalid") from exc
        SecureStateStore._validate_attachment_context(context)
        return context

    @staticmethod
    def _validate_attachment_context(context: AttachmentContext) -> None:
        attachment = context.attachment
        if (
            not context.message_id
            or not context.sender_did
            or (context.message_target_did is None) == (context.group_did is None)
            or not attachment.attachment_id
            or not attachment.object_uri.startswith("https://")
            or not attachment.filename
            or not attachment.mime_type
            or attachment.size < 0
            or not attachment.sha256_b64u
        ):
            raise StateError("attachment context is invalid")

    @staticmethod
    def _validate_passphrase(passphrase: str) -> None:
        if len(passphrase) < 12 or not passphrase.strip():
            raise StateError("passphrase must contain at least 12 characters")

    def _ensure_directory(self, path: Path) -> None:
        if path.exists():
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise StateError("state path is not a safe directory")
            if info.st_uid != os.getuid():
                raise StateError("state directory is not owned by the current user")
            os.chmod(path, 0o700)
            return
        self._validate_creation_parent(path.parent)
        try:
            path.mkdir(mode=0o700, parents=True)
        except FileExistsError:
            # Another process may have created the same directory after validation.
            self._ensure_directory(path)
            return
        os.chmod(path, 0o700)

    @staticmethod
    def _validate_creation_parent(parent: Path) -> None:
        candidate = parent
        while not candidate.exists() and not candidate.is_symlink():
            if candidate == candidate.parent:
                raise StateError("state parent directory is unavailable")
            candidate = candidate.parent
        info = candidate.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise StateError("state parent directory is unsafe")
        if info.st_uid != os.getuid():
            raise StateError("state parent directory is not owned by the current user")

    @staticmethod
    def _reject_unsafe_target(path: Path) -> None:
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise StateError("state file target is unsafe")

    def _atomic_json(self, path: Path, value: Mapping[str, Any]) -> None:
        self._atomic_write(path, (json.dumps(value, separators=(",", ":")) + "\n").encode())

    def _atomic_write(self, path: Path, content: bytes) -> None:
        self._reject_unsafe_target(path)
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=True) as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            self._fsync_directory(path.parent)
        except BaseException:
            with suppress(FileNotFoundError):
                os.unlink(temporary)
            raise

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        directory_fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def _read_regular(self, path: Path) -> bytes:
        try:
            info = path.lstat()
        except FileNotFoundError as exc:
            raise IdentityMissingError("local identity is not registered") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise StateError("state file is unsafe")
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise StateError("state file permissions are unsafe")
        return path.read_bytes()

    def _read_json(self, path: Path) -> dict[str, Any]:
        try:
            value = json.loads(self._read_regular(path))
        except json.JSONDecodeError as exc:
            raise StateError("local state file is invalid") from exc
        if not isinstance(value, dict):
            raise StateError("local state file is invalid")
        return value
