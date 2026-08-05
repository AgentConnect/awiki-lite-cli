"""Closed single-file plain attachment Manifest encoding and parsing."""

from __future__ import annotations

import base64
import binascii
from pathlib import Path
from typing import Any

from awiki_lite_cli.domain.models import AttachmentRef

MAX_CAPTION_CHARS = 4096
MANIFEST_CONTENT_TYPE = "application/anp-attachment-manifest+json"


def normalize_caption(value: str | None) -> str | None:
    if value is None:
        return None
    if len(value) > MAX_CAPTION_CHARS:
        raise ValueError(f"attachment caption must not exceed {MAX_CAPTION_CHARS} characters")
    return value if value else None


def build_manifest(attachment: AttachmentRef, caption: str | None) -> dict[str, Any]:
    normalized = normalize_caption(caption)
    _validate_ref(attachment)
    manifest: dict[str, Any] = {
        "attachments": [
            {
                "attachment_id": attachment.attachment_id,
                "filename": attachment.filename,
                "mime_type": attachment.mime_type,
                "size": str(attachment.size),
                "digest": {"alg": "sha-256", "value_b64u": attachment.sha256_b64u},
                "access_info": {"object_uri": attachment.object_uri},
                "encryption_info": {"mode": "none"},
            }
        ],
        "primary_attachment_id": attachment.attachment_id,
    }
    if normalized is not None:
        manifest["caption"] = normalized
    return manifest


def parse_manifest(value: Any) -> tuple[AttachmentRef, str | None]:
    manifest = _object(value, "attachment Manifest")
    if set(manifest) not in (
        {"attachments", "primary_attachment_id"},
        {"attachments", "caption", "primary_attachment_id"},
    ):
        raise RuntimeError("message contains an unsupported attachment Manifest shape")
    attachments = manifest.get("attachments")
    if not isinstance(attachments, list) or len(attachments) != 1:
        raise RuntimeError("message does not contain exactly one attachment")
    item = _object(attachments[0], "attachment entry")
    if set(item) != {
        "attachment_id",
        "filename",
        "mime_type",
        "size",
        "digest",
        "access_info",
        "encryption_info",
    }:
        raise RuntimeError("message contains an unsupported attachment entry")
    digest = _object(item["digest"], "attachment digest")
    access = _object(item["access_info"], "attachment access info")
    encryption = _object(item["encryption_info"], "attachment encryption info")
    if set(digest) != {"alg", "value_b64u"} or digest.get("alg") != "sha-256":
        raise RuntimeError("message contains an invalid attachment digest")
    if set(access) != {"object_uri"}:
        raise RuntimeError("message contains invalid attachment access info")
    if encryption != {"mode": "none"}:
        raise RuntimeError("message attachment is not a plain P7 object")
    size = _size(item.get("size"))
    ref = AttachmentRef(
        _string(item.get("attachment_id"), "attachment id"),
        _object_uri(access.get("object_uri")),
        _filename(item.get("filename")),
        _mime_type(item.get("mime_type")),
        size,
        _digest(digest.get("value_b64u")),
    )
    if manifest.get("primary_attachment_id") != ref.attachment_id:
        raise RuntimeError("message contains a mismatched primary attachment id")
    caption_value = manifest.get("caption")
    if caption_value is not None and not isinstance(caption_value, str):
        raise RuntimeError("message contains an invalid attachment caption")
    try:
        caption = normalize_caption(caption_value)
    except ValueError as exc:
        raise RuntimeError("message contains an invalid attachment caption") from exc
    return ref, caption


def _validate_ref(value: AttachmentRef) -> None:
    parsed = parse_manifest(
        {
            "attachments": [
                {
                    "attachment_id": value.attachment_id,
                    "filename": value.filename,
                    "mime_type": value.mime_type,
                    "size": str(value.size),
                    "digest": {"alg": "sha-256", "value_b64u": value.sha256_b64u},
                    "access_info": {"object_uri": value.object_uri},
                    "encryption_info": {"mode": "none"},
                }
            ],
            "primary_attachment_id": value.attachment_id,
        }
    )[0]
    if parsed != value:
        raise ValueError("attachment reference is invalid")


def _filename(value: Any) -> str:
    filename = _string(value, "attachment filename")
    if (
        filename in {".", ".."}
        or Path(filename).name != filename
        or "/" in filename
        or "\\" in filename
        or "\x00" in filename
        or len(filename.encode()) > 255
        or any(ord(character) < 32 or ord(character) == 127 for character in filename)
    ):
        raise RuntimeError("message contains an unsafe attachment filename")
    return filename


def _mime_type(value: Any) -> str:
    mime = _string(value, "attachment MIME type")
    if len(mime) > 255 or "\r" in mime or "\n" in mime:
        raise RuntimeError("message contains an invalid attachment MIME type")
    return mime


def _digest(value: Any) -> str:
    encoded = _string(value, "attachment digest")
    if len(encoded) != 43:
        raise RuntimeError("message contains an invalid SHA-256 digest")
    try:
        decoded = base64.urlsafe_b64decode(encoded + "=")
    except (ValueError, binascii.Error) as exc:
        raise RuntimeError("message contains an invalid SHA-256 digest") from exc
    if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != encoded:
        raise RuntimeError("message contains an invalid SHA-256 digest")
    return encoded


def _object_uri(value: Any) -> str:
    uri = _string(value, "attachment object URI")
    # The full SSRF boundary is re-validated immediately before data-plane GET.
    if not uri.startswith("https://"):
        raise RuntimeError("message contains an unsafe attachment object URI")
    return uri


def _size(value: Any) -> int:
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
        raise RuntimeError("message contains an invalid attachment size")
    return int(value)


def _string(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 1024
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise RuntimeError(f"message contains an invalid {field}")
    return value


def _object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError(f"message contains an invalid {field}")
    return value
