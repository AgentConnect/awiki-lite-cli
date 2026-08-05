"""Small immutable values shared across v1 workflows."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class IdentityState:
    did: str
    access_token: str
    verification_method: str


@dataclass(frozen=True, slots=True)
class ChatMessage:
    message_id: str
    sender_did: str
    target_did: str
    text: str


@dataclass(frozen=True, slots=True)
class AttachmentRef:
    attachment_id: str
    object_uri: str
    filename: str
    mime_type: str
    size: int
    sha256_b64u: str
