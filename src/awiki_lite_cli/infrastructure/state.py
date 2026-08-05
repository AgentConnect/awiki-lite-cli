"""Secure single-identity state storage."""

from __future__ import annotations

import fcntl
import json
import os
import stat
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

from awiki_lite_cli.domain.models import IdentityState, SessionState, UnlockedIdentity


class StateError(RuntimeError):
    """Safe state error whose message contains no secret material."""


class IdentityExistsError(StateError):
    pass


class IdentityMissingError(StateError):
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
            self._atomic_json(self.root / "identity.json", identity_data)
            self._atomic_json(self.root / "session.json", {"access_token": access_token})
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
        path = self.root / "pending-registration.json"
        if not path.exists():
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
        path.mkdir(mode=0o700, parents=True)
        os.chmod(path, 0o700)

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
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except BaseException:
            with suppress(FileNotFoundError):
                os.unlink(temporary)
            raise

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
