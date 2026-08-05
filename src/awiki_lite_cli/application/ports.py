"""Outbound interfaces owned by application workflows."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from awiki_lite_cli.domain.models import AttachmentRef, ChatMessage, IdentityState


class IdentityGateway(Protocol):
    async def register(self, handle: str, phone: str, otp_code: str) -> IdentityState: ...


class MessagingGateway(Protocol):
    async def send_direct(self, recipient_did: str, text: str) -> ChatMessage: ...

    async def send_group(self, group_did: str, text: str) -> ChatMessage: ...


class AttachmentGateway(Protocol):
    async def upload(self, source: Path, target_did: str, target_kind: str) -> AttachmentRef: ...


class IdentityStore(Protocol):
    def load(self) -> IdentityState: ...

    def save(self, identity: IdentityState) -> None: ...
