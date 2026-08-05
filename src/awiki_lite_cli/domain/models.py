"""Small immutable values shared across v1 workflows."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class IdentityState:
    did: str
    handle: str
    verification_method: str
    device_id: str
    did_document: dict[str, Any]


@dataclass(frozen=True, slots=True)
class SessionState:
    access_token: str


@dataclass(frozen=True, slots=True)
class UnlockedIdentity:
    identity: IdentityState
    session: SessionState
    root_private_key: object
    device_signing_private_key: object
    device_agreement_private_key: object


@dataclass(frozen=True, slots=True)
class ChatMessage:
    message_id: str
    sender_did: str
    target_did: str
    text: str
    created_at: str | None = None
    is_read: bool | None = None


@dataclass(frozen=True, slots=True)
class AttachmentRef:
    attachment_id: str
    object_uri: str
    filename: str
    mime_type: str
    size: int
    sha256_b64u: str
