"""Plain P7 v1 attachment control plane and secure streaming upload."""

from __future__ import annotations

import base64
import hashlib
import mimetypes
import os
import re
import stat
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

import httpx

from awiki_lite_cli.domain.models import (
    AttachmentContext,
    AttachmentRef,
    AuthenticatedIdentity,
    UnlockedIdentity,
)
from awiki_lite_cli.infrastructure.anp_sdk import resolve_attachment_service_did
from awiki_lite_cli.infrastructure.attachment_manifest import MANIFEST_CONTENT_TYPE
from awiki_lite_cli.infrastructure.message_service import build_capabilities, validate_did
from awiki_lite_cli.infrastructure.rpc import call_json_rpc
from awiki_lite_cli.infrastructure.safe_network import (
    AddressResolver,
    pin_https_url,
    pinned_headers,
    resolve_public_addresses,
)
from awiki_lite_cli.infrastructure.state import (
    _owned_by_current_user,
    _secure_open_file,
)
from awiki_lite_cli.infrastructure.validation import validate_public_hostname

ATTACHMENT_PROFILE = "anp.attachment.v1"
TRANSPORT_PROTECTED = "transport-protected"
UPLOAD_HEADER_ALLOWLIST = frozenset({"x-anp-upload-token"})
CHUNK_SIZE = 64 * 1024


@dataclass(frozen=True, slots=True)
class AttachmentCapabilities:
    service_did: str
    max_object_bytes: int


@dataclass(frozen=True, slots=True)
class AttachmentSlot:
    attachment_id: str
    slot_id: str
    upload_uri: str
    upload_headers: dict[str, str] = field(repr=False)
    object_uri: str = ""
    commit_token: str = field(default="", repr=False)
    expires_at: str = ""


@dataclass(frozen=True, slots=True)
class CommittedAttachment:
    attachment: AttachmentRef
    committed_at: str


@dataclass(frozen=True, slots=True)
class DownloadTicket:
    value: str = field(repr=False)
    expires_at: str = ""


class DownloadDestination:
    """An owner-controlled directory fd and a no-overwrite basename."""

    def __init__(self, directory: Path, directory_fd: int | None, filename: str) -> None:
        self.directory = directory
        self.directory_fd = directory_fd
        self.filename = filename
        self._closed = False

    @property
    def path(self) -> Path:
        return self.directory / self.filename

    def close(self) -> None:
        if not self._closed:
            if self.directory_fd is not None:
                os.close(self.directory_fd)
            self._closed = True

    def __enter__(self) -> DownloadDestination:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


@dataclass(frozen=True, slots=True)
class _Fingerprint:
    device: int
    inode: int
    mode: int
    size: int
    modified_ns: int
    changed_ns: int


class PreparedFile:
    """An already-open immutable-by-verification regular-file snapshot."""

    def __init__(
        self,
        fd: int,
        filename: str,
        mime_type: str,
        size: int,
        sha256_b64u: str,
        fingerprint: _Fingerprint,
    ) -> None:
        self._fd = fd
        self.filename = filename
        self.mime_type = mime_type
        self.size = size
        self.sha256_b64u = sha256_b64u
        self._fingerprint = fingerprint
        self._closed = False

    def close(self) -> None:
        if not self._closed:
            os.close(self._fd)
            self._closed = True

    def __enter__(self) -> PreparedFile:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def assert_unchanged(self) -> None:
        if self._closed:
            raise RuntimeError("attachment file is closed")
        if _fingerprint(os.fstat(self._fd)) != self._fingerprint:
            raise RuntimeError("attachment file changed during processing")

    def rewind(self) -> None:
        self.assert_unchanged()
        os.lseek(self._fd, 0, os.SEEK_SET)

    def read(self, size: int) -> bytes:
        return os.read(self._fd, size)


def prepare_file(path: Path, max_bytes: int) -> PreparedFile:
    """Open exactly one non-symlink regular file and hash it through that descriptor."""
    if max_bytes < 0:
        raise ValueError("attachment size limit is invalid")
    try:
        before_open = path.lstat()
    except OSError as exc:
        raise ValueError("attachment file is unavailable") from exc
    if not stat.S_ISREG(before_open.st_mode):
        raise ValueError("attachment path must be a regular file, not a symlink or special file")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError("attachment file cannot be opened safely") from exc
    try:
        opened = os.fstat(fd)
        fingerprint = _fingerprint(opened)
        if not stat.S_ISREG(opened.st_mode) or (
            opened.st_dev != before_open.st_dev or opened.st_ino != before_open.st_ino
        ):
            raise ValueError("attachment file changed while it was opened")
        if opened.st_size > max_bytes:
            raise ValueError("attachment exceeds the service object-size limit")
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(fd, CHUNK_SIZE):
            total += len(chunk)
            if total > max_bytes:
                raise ValueError("attachment exceeds the service object-size limit")
            digest.update(chunk)
        if total != opened.st_size or _fingerprint(os.fstat(fd)) != fingerprint:
            raise RuntimeError("attachment file changed while it was hashed")
        filename = path.name
        if (
            not filename
            or len(filename.encode()) > 255
            or "\x00" in filename
            or any(ord(character) < 32 or ord(character) == 127 for character in filename)
        ):
            raise ValueError("attachment filename is invalid")
        mime_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        encoded = base64.urlsafe_b64encode(digest.digest()).rstrip(b"=").decode("ascii")
        os.lseek(fd, 0, os.SEEK_SET)
        return PreparedFile(fd, filename, mime_type, total, encoded, fingerprint)
    except Exception:
        os.close(fd)
        raise


def build_create_slot(
    sender_did: str,
    service_did: str,
    attachment_id: str,
    prepared: PreparedFile,
    target_kind: str,
    target_did: str,
    operation_id: str,
    created_at: str,
) -> dict[str, Any]:
    if target_kind not in {"agent", "group"}:
        raise ValueError("attachment target kind must be agent or group")
    if not attachment_id or not operation_id:
        raise ValueError("attachment and operation identifiers must not be empty")
    prepared.assert_unchanged()
    return {
        "meta": _control_meta(sender_did, service_did, operation_id, created_at),
        "body": {
            "attachment_id": attachment_id,
            "expected_size": str(prepared.size),
            "expected_digest": {"alg": "sha-256", "value_b64u": prepared.sha256_b64u},
            "mime_type": prepared.mime_type,
            "filename": prepared.filename,
            "intended_message_security_profile": TRANSPORT_PROTECTED,
            "intended_target": {"kind": target_kind, "did": validate_did(target_did)},
            "object_encryption_mode": "none",
        },
    }


def build_commit_object(
    sender_did: str,
    service_did: str,
    slot: AttachmentSlot,
    prepared: PreparedFile,
    operation_id: str,
    created_at: str,
) -> dict[str, Any]:
    prepared.assert_unchanged()
    return {
        "meta": _control_meta(sender_did, service_did, operation_id, created_at),
        "body": {
            "attachment_id": slot.attachment_id,
            "slot_id": slot.slot_id,
            "commit_token": slot.commit_token,
            "size": str(prepared.size),
            "digest": {"alg": "sha-256", "value_b64u": prepared.sha256_b64u},
            "object_encryption_mode": "none",
        },
    }


def build_abort_object(
    sender_did: str,
    service_did: str,
    attachment_id: str,
    slot_id: str,
    operation_id: str,
    created_at: str,
) -> dict[str, Any]:
    if not attachment_id or not slot_id:
        raise ValueError("attachment and slot identifiers must not be empty")
    return {
        "meta": _control_meta(sender_did, service_did, operation_id, created_at),
        "body": {"attachment_id": attachment_id, "slot_id": slot_id},
    }


def build_download_ticket(
    requester_did: str,
    service_did: str,
    context: AttachmentContext,
    operation_id: str,
    created_at: str,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "attachment_id": context.attachment.attachment_id,
        "object_uri": _https_uri(context.attachment.object_uri, "object_uri"),
        "requester_did": validate_did(requester_did),
        "message_security_profile": TRANSPORT_PROTECTED,
        "message_id": _nonempty(context.message_id, "message_id"),
        "one_time": True,
    }
    if (context.message_target_did is None) == (context.group_did is None):
        raise ValueError("attachment context target is invalid")
    if context.message_target_did is not None:
        body["message_target_did"] = validate_did(context.message_target_did)
    else:
        body["group_did"] = validate_did(str(context.group_did))
    return {
        "meta": _control_meta(requester_did, service_did, operation_id, created_at),
        "body": body,
    }


def prepare_download_destination(output_dir: Path, filename: str) -> DownloadDestination:
    safe_filename = _safe_filename(filename)
    directory = output_dir.absolute()
    if os.name == "nt":
        try:
            resolved = directory.resolve(strict=True)
            opened = directory.stat(follow_symlinks=False)
        except OSError as exc:
            raise ValueError("attachment output directory is unavailable") from exc
        if os.path.normcase(resolved) != os.path.normcase(directory) or not stat.S_ISDIR(
            opened.st_mode
        ):
            raise ValueError("attachment output directory must not contain symlinks")
        if not _owned_by_current_user(directory, opened):
            raise ValueError("attachment output directory must be owned by the current user")
        destination = directory / safe_filename
        if destination.exists() or destination.is_symlink():
            raise ValueError("attachment output file already exists")
        return DownloadDestination(directory, None, safe_filename)
    directory_fd = _open_directory_without_symlinks(directory)
    try:
        opened = os.fstat(directory_fd)
        if not stat.S_ISDIR(opened.st_mode) or not _owned_by_current_user(directory, opened):
            raise ValueError("attachment output directory must be owned by the current user")
        try:
            os.stat(safe_filename, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("attachment output file already exists")
        return DownloadDestination(directory, directory_fd, safe_filename)
    except Exception:
        os.close(directory_fd)
        raise


class AttachmentService:
    def __init__(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        service_resolver: Callable[[str], Awaitable[str]] | None = None,
        address_resolver: AddressResolver = resolve_public_addresses,
    ) -> None:
        self.client = client
        self.endpoint = base_url.rstrip("/") + "/im/rpc"
        self.address_resolver = address_resolver
        self.service_resolver = service_resolver or self._resolve_attachment_service

    async def _resolve_attachment_service(self, sender_did: str) -> str:
        return await resolve_attachment_service_did(
            sender_did,
            client=self.client,
            address_resolver=self.address_resolver,
        )

    async def capabilities(
        self, identity: AuthenticatedIdentity | UnlockedIdentity
    ) -> AttachmentCapabilities:
        value = _object(
            await call_json_rpc(
                self.client,
                self.endpoint,
                "anp.get_capabilities",
                build_capabilities(identity.identity.did),
                access_token=identity.session.access_token,
            )
        )
        _require(value, "supported_profiles", ATTACHMENT_PROFILE)
        _require(value, "supported_security_profiles", TRANSPORT_PROTECTED)
        _require(value, "supported_content_types", MANIFEST_CONTENT_TYPE)
        service_did = value.get("service_did")
        limits = value.get("limits")
        if not isinstance(service_did, str) or not isinstance(limits, dict):
            raise RuntimeError("attachment capability response is incomplete")
        maximum = _decimal_size(limits.get("max_object_bytes"), "max_object_bytes")
        return AttachmentCapabilities(validate_did(service_did), maximum)

    async def create_slot(
        self,
        identity: UnlockedIdentity,
        service_did: str,
        attachment_id: str,
        prepared: PreparedFile,
        target_kind: str,
        target_did: str,
        operation_id: str,
        created_at: str,
    ) -> AttachmentSlot:
        params = build_create_slot(
            identity.identity.did,
            service_did,
            attachment_id,
            prepared,
            target_kind,
            target_did,
            operation_id,
            created_at,
        )
        result = _object(await self._control(identity, "attachment.create_slot", params))
        return _parse_slot(result, attachment_id)

    async def upload(self, slot: AttachmentSlot, prepared: PreparedFile) -> None:
        _require_unexpired(slot.expires_at)
        uri = _https_uri(slot.upload_uri, "upload_uri")
        target = await pin_https_url(
            uri, resolver=self.address_resolver, field="attachment upload URI"
        )
        headers = _upload_headers(slot.upload_headers)
        prepared.rewind()
        stream = _PreparedFileStream(prepared)
        response = await self.client.put(
            target.url,
            headers=pinned_headers(target, {**headers, "Content-Type": prepared.mime_type}),
            content=stream,
            follow_redirects=False,
            extensions=target.extensions,
        )
        response.raise_for_status()
        stream.verify()
        prepared.assert_unchanged()

    async def commit(
        self,
        identity: UnlockedIdentity,
        service_did: str,
        slot: AttachmentSlot,
        prepared: PreparedFile,
        operation_id: str,
        created_at: str,
    ) -> CommittedAttachment:
        params = build_commit_object(
            identity.identity.did, service_did, slot, prepared, operation_id, created_at
        )
        result = _object(await self._control(identity, "attachment.commit_object", params))
        return _parse_commit(result, slot, prepared)

    async def abort(
        self,
        identity: UnlockedIdentity,
        service_did: str,
        slot: AttachmentSlot,
        operation_id: str,
        created_at: str,
    ) -> None:
        params = build_abort_object(
            identity.identity.did,
            service_did,
            slot.attachment_id,
            slot.slot_id,
            operation_id,
            created_at,
        )
        result = _object(await self._control(identity, "attachment.abort_object", params))
        if set(result) != {"aborted", "attachment_id", "aborted_at"}:
            raise RuntimeError("attachment service returned an invalid abort result")
        if result["aborted"] is not True or result["attachment_id"] != slot.attachment_id:
            raise RuntimeError("attachment service returned a mismatched abort result")
        _nonempty(result["aborted_at"], "aborted_at")

    async def best_effort_abort(
        self,
        identity: UnlockedIdentity,
        service_did: str,
        slot: AttachmentSlot,
        operation_id: str,
        created_at: str,
    ) -> None:
        """Try to reclaim an uncommitted slot without masking the original failure."""
        with suppress(Exception):
            await self.abort(identity, service_did, slot, operation_id, created_at)

    async def get_download_ticket(
        self, identity: AuthenticatedIdentity, context: AttachmentContext
    ) -> DownloadTicket:
        _https_uri(context.attachment.object_uri, "object_uri")
        try:
            service_did = validate_did(await self.service_resolver(context.sender_did))
        except ValueError as exc:
            raise RuntimeError("resolved attachment service DID is invalid") from exc
        params = build_download_ticket(
            identity.identity.did,
            service_did,
            context,
            str(uuid4()),
            new_created_at(),
        )
        result = _object(
            await call_json_rpc(
                self.client,
                self.endpoint,
                "attachment.get_download_ticket",
                params,
                access_token=identity.session.access_token,
            )
        )
        if set(result) != {"download_ticket_b64u", "expires_at", "ticket_binding"}:
            raise RuntimeError("attachment service returned an invalid download-ticket result")
        binding = result.get("ticket_binding")
        expected_binding = {
            key: value for key, value in params["body"].items() if key != "one_time"
        }
        if not isinstance(binding, dict) or binding != expected_binding:
            raise RuntimeError("attachment service returned a mismatched download-ticket binding")
        expires_at = _nonempty(result.get("expires_at"), "expires_at")
        _require_unexpired(expires_at, "attachment download ticket")
        return DownloadTicket(
            _nonempty(result.get("download_ticket_b64u"), "download ticket"), expires_at
        )

    async def download(
        self,
        ticket: DownloadTicket,
        attachment: AttachmentRef,
        destination: DownloadDestination,
    ) -> Path:
        _require_unexpired(ticket.expires_at, "attachment download ticket")
        uri = _https_uri(attachment.object_uri, "object_uri")
        target = await pin_https_url(
            uri, resolver=self.address_resolver, field="attachment object URI"
        )
        temporary_name = f".awiki-lite-{uuid4()}.part"
        temporary_fd: int | None = None
        try:
            async with self.client.stream(
                "GET",
                target.url,
                headers=pinned_headers(
                    target,
                    {
                        "Authorization": f"Bearer {ticket.value}",
                        "Accept-Encoding": "identity",
                    },
                ),
                follow_redirects=False,
                extensions=target.extensions,
            ) as response:
                response.raise_for_status()
                encoding = response.headers.get("Content-Encoding")
                if encoding is not None and encoding.lower() != "identity":
                    raise RuntimeError("attachment download returned unsupported content encoding")
                length = response.headers.get("Content-Length")
                if length is not None and (
                    not length.isascii() or not length.isdecimal() or int(length) != attachment.size
                ):
                    raise RuntimeError("attachment download size does not match the Manifest")
                flags = (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                temporary_path = destination.directory / temporary_name
                if destination.directory_fd is None:
                    temporary_fd = os.open(temporary_path, flags, 0o600)
                else:
                    temporary_fd = os.open(
                        temporary_name, flags, 0o600, dir_fd=destination.directory_fd
                    )
                _secure_open_file(temporary_fd, temporary_path)
                digest = hashlib.sha256()
                total = 0
                async for chunk in response.aiter_bytes(CHUNK_SIZE):
                    total += len(chunk)
                    if total > attachment.size:
                        raise RuntimeError("attachment download exceeds the Manifest size")
                    digest.update(chunk)
                    _write_all(temporary_fd, chunk)
                encoded = base64.urlsafe_b64encode(digest.digest()).rstrip(b"=").decode("ascii")
                if total != attachment.size or encoded != attachment.sha256_b64u:
                    raise RuntimeError("attachment download failed integrity verification")
                os.fsync(temporary_fd)
                os.close(temporary_fd)
                temporary_fd = None
            try:
                if destination.directory_fd is None:
                    os.link(temporary_path, destination.path, follow_symlinks=False)
                else:
                    os.link(
                        temporary_name,
                        destination.filename,
                        src_dir_fd=destination.directory_fd,
                        dst_dir_fd=destination.directory_fd,
                        follow_symlinks=False,
                    )
            except FileExistsError as exc:
                raise ValueError("attachment output file already exists") from exc
            if destination.directory_fd is None:
                os.unlink(temporary_path)
            else:
                os.unlink(temporary_name, dir_fd=destination.directory_fd)
                os.fsync(destination.directory_fd)
            return destination.path
        except (ValueError, RuntimeError, httpx.HTTPError):
            raise
        except OSError as exc:
            raise RuntimeError("attachment download could not be published safely") from exc
        finally:
            if temporary_fd is not None:
                with suppress(OSError):
                    os.close(temporary_fd)
            with suppress(OSError):
                if destination.directory_fd is None:
                    os.unlink(destination.directory / temporary_name)
                else:
                    os.unlink(temporary_name, dir_fd=destination.directory_fd)

    async def _control(
        self, identity: UnlockedIdentity, method: str, params: dict[str, Any]
    ) -> Any:
        for attempt in range(2):
            try:
                return await call_json_rpc(
                    self.client,
                    self.endpoint,
                    method,
                    params,
                    access_token=identity.session.access_token,
                )
            except httpx.TransportError:
                if attempt == 1:
                    raise
        raise RuntimeError("attachment control retry loop ended unexpectedly")  # pragma: no cover


class _PreparedFileStream(httpx.AsyncByteStream):
    def __init__(self, prepared: PreparedFile) -> None:
        self.prepared = prepared
        self.digest = hashlib.sha256()
        self.size = 0
        self.finished = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        while chunk := self.prepared.read(CHUNK_SIZE):
            self.size += len(chunk)
            self.digest.update(chunk)
            yield chunk
        self.finished = True

    def verify(self) -> None:
        digest = base64.urlsafe_b64encode(self.digest.digest()).rstrip(b"=").decode("ascii")
        if (
            not self.finished
            or self.size != self.prepared.size
            or digest != self.prepared.sha256_b64u
        ):
            raise RuntimeError("attachment file changed during upload")


def _control_meta(
    sender_did: str, service_did: str, operation_id: str, created_at: str
) -> dict[str, Any]:
    _nonempty(operation_id, "operation_id")
    _nonempty(created_at, "created_at")
    return {
        "profile": ATTACHMENT_PROFILE,
        "security_profile": TRANSPORT_PROTECTED,
        "sender_did": validate_did(sender_did),
        "target": {"kind": "service", "did": validate_did(service_did)},
        "operation_id": operation_id,
        "created_at": created_at,
    }


def new_created_at() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_slot(value: dict[str, Any], attachment_id: str) -> AttachmentSlot:
    allowed = {
        "attachment_id",
        "slot_id",
        "upload_uri",
        "upload_headers",
        "object_uri",
        "commit_token",
        "expires_at",
    }
    keys = set(value)
    if keys != allowed and keys != allowed - {"upload_headers"}:
        raise RuntimeError("attachment service returned an invalid create-slot result")
    if value.get("attachment_id") != attachment_id:
        raise RuntimeError("attachment service returned a mismatched attachment identifier")
    headers = value.get("upload_headers", {})
    if not isinstance(headers, dict):
        raise RuntimeError("attachment service returned invalid upload headers")
    parsed_headers = _upload_headers(headers)
    return AttachmentSlot(
        attachment_id,
        _nonempty(value.get("slot_id"), "slot_id"),
        _https_uri(value.get("upload_uri"), "upload_uri"),
        parsed_headers,
        _https_uri(value.get("object_uri"), "object_uri"),
        _nonempty(value.get("commit_token"), "commit_token"),
        _nonempty(value.get("expires_at"), "expires_at"),
    )


def _parse_commit(
    value: dict[str, Any], slot: AttachmentSlot, prepared: PreparedFile
) -> CommittedAttachment:
    if set(value) != {"committed", "attachment_id", "object_uri", "committed_at"}:
        raise RuntimeError("attachment service returned an invalid commit result")
    if (
        value.get("committed") is not True
        or value.get("attachment_id") != slot.attachment_id
        or value.get("object_uri") != slot.object_uri
    ):
        raise RuntimeError("attachment service returned a mismatched commit result")
    attachment = AttachmentRef(
        slot.attachment_id,
        slot.object_uri,
        prepared.filename,
        prepared.mime_type,
        prepared.size,
        prepared.sha256_b64u,
    )
    return CommittedAttachment(attachment, _nonempty(value.get("committed_at"), "committed_at"))


def _upload_headers(value: dict[str, Any]) -> dict[str, str]:
    output: dict[str, str] = {}
    for raw_name, raw_value in value.items():
        name = str(raw_name).strip().lower()
        if name not in UPLOAD_HEADER_ALLOWLIST:
            raise RuntimeError("attachment service returned a forbidden upload header")
        if (
            not isinstance(raw_value, str)
            or not raw_value
            or "\r" in raw_value
            or "\n" in raw_value
        ):
            raise RuntimeError("attachment service returned an invalid upload header")
        output[name] = raw_value
    return output


def _https_uri(value: Any, field_name: str) -> str:
    uri = _nonempty(value, field_name)
    parsed = urlsplit(uri)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError(f"attachment service returned an unsafe {field_name}")
    try:
        validate_public_hostname(parsed.hostname.lower().rstrip("."), field=field_name)
    except ValueError as exc:
        raise RuntimeError(f"attachment service returned an unsafe {field_name}") from exc
    return uri


def _fingerprint(value: os.stat_result) -> _Fingerprint:
    return _Fingerprint(
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _require(value: dict[str, Any], field_name: str, required: str) -> None:
    advertised = value.get(field_name)
    if not isinstance(advertised, list) or required not in advertised:
        raise RuntimeError(f"message service does not advertise required {required}")


def _decimal_size(value: Any, field_name: str) -> int:
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
        raise RuntimeError(f"attachment service returned an invalid {field_name}")
    parsed = int(value)
    if parsed < 0:
        raise RuntimeError(f"attachment service returned an invalid {field_name}")
    return parsed


def _nonempty(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"attachment service returned an invalid {field_name}")
    return value


def _require_unexpired(value: str, subject: str = "attachment upload slot") -> None:
    matched = re.fullmatch(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})",
        value,
    )
    if matched is None:
        raise RuntimeError("attachment service returned an invalid expires_at")
    fraction = matched.group(2) or ""
    if fraction:
        fraction = fraction[:7]
    normalized = matched.group(1) + fraction + matched.group(3).replace("Z", "+00:00")
    try:
        expires_at = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise RuntimeError("attachment service returned an invalid expires_at") from exc
    if expires_at.tzinfo is None or expires_at <= datetime.now(timezone.utc):
        raise RuntimeError(f"{subject} has expired")


def _safe_filename(value: str) -> str:
    if (
        not value
        or value in {".", ".."}
        or Path(value).name != value
        or "/" in value
        or "\\" in value
        or "\x00" in value
        or len(value.encode()) > 255
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("attachment filename is unsafe")
    return value


def _open_directory_without_symlinks(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        current_fd = os.open(path.anchor, flags)
    except OSError as exc:  # pragma: no cover - a broken filesystem root is unrecoverable here
        raise ValueError("attachment output directory is unavailable") from exc
    try:
        for component in path.parts[1:]:
            next_fd = os.open(component, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except OSError as exc:
        os.close(current_fd)
        raise ValueError("attachment output directory must not contain symlinks") from exc


def _write_all(fd: int, value: bytes) -> None:
    view = memoryview(value)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise RuntimeError("attachment download could not be written")
        view = view[written:]


def _object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError("attachment service returned an invalid result")
    return value
