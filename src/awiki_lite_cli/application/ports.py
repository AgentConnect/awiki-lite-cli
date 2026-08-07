"""Narrow outbound interfaces consumed by application workflows."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol

from awiki_lite_cli.domain.models import (
    AttachmentContext,
    AttachmentRef,
    AuthenticatedIdentity,
    GroupMember,
    GroupMessage,
    GroupSummary,
    IdentityState,
    PendingOperation,
    SessionState,
    UnlockedIdentity,
)


class RegistrationServicePort(Protocol):
    base_url: str

    async def validate_handle(self, handle: str, domain: str) -> dict[str, Any]: ...
    async def send_registration_otp(self, handle: str, domain: str, phone: str) -> None: ...
    async def register(
        self, did_document: dict[str, Any], handle: str, phone: str, otp_code: str
    ) -> dict[str, Any]: ...


class StateStorePort(Protocol):
    @property
    def exists(self) -> bool: ...
    def load_public(self) -> IdentityState: ...
    def load_session(self) -> SessionState: ...
    def load_pending_identity(self) -> IdentityState | None: ...
    def unlock_pending_keys(self, passphrase: str) -> tuple[Any, Any, Any]: ...
    def stage_registration(
        self,
        identity: IdentityState,
        private_keys: Mapping[str, Any],
        passphrase: str,
    ) -> None: ...
    def finalize_registration(self, identity: IdentityState, access_token: str) -> None: ...
    def prepare_operation(
        self,
        kind: str,
        target_did: str,
        input_sha256: str,
        *,
        needs_message_id: bool,
        values: Mapping[str, str] | None = None,
        initial_stage: str | None = None,
    ) -> PendingOperation: ...
    def abandon_operation(self, pending: PendingOperation) -> None: ...
    def complete_operation(self, pending: PendingOperation) -> None: ...
    def advance_operation(self, pending: PendingOperation, next_stage: str) -> PendingOperation: ...
    def save_attachment_contexts(self, contexts: list[AttachmentContext]) -> None: ...
    def load_attachment_context(self, message_id: str, attachment_id: str) -> AttachmentContext: ...


class GroupServicePort(Protocol):
    async def capabilities(self, identity: Any) -> Any: ...
    async def create(
        self, identity: UnlockedIdentity, service_did: str, name: str, pending: PendingOperation
    ) -> GroupSummary: ...
    async def add(
        self,
        identity: UnlockedIdentity,
        group_did: str,
        member_did: str,
        pending: PendingOperation,
    ) -> str: ...
    async def send_text(
        self, identity: UnlockedIdentity, group_did: str, text: str, pending: PendingOperation
    ) -> GroupMessage: ...
    async def send_attachment(
        self,
        identity: UnlockedIdentity,
        group_did: str,
        attachment: AttachmentRef,
        caption: str | None,
        pending: PendingOperation,
    ) -> GroupMessage: ...
    async def list_groups(
        self, identity: AuthenticatedIdentity, limit: int, cursor: str | None = None
    ) -> tuple[list[GroupSummary], str | None]: ...
    async def info(self, identity: AuthenticatedIdentity, group_did: str) -> GroupSummary: ...
    async def members(
        self,
        identity: AuthenticatedIdentity,
        group_did: str,
        limit: int,
        cursor: str | None = None,
    ) -> tuple[list[GroupMember], str | None]: ...
    async def messages(
        self,
        identity: AuthenticatedIdentity,
        group_did: str,
        limit: int,
        since_seq: int | None = None,
    ) -> tuple[list[GroupMessage], int | None]: ...


class MessageServicePort(Protocol):
    async def ensure_direct_base(self, identity: Any) -> Any: ...
    async def send_attachment(
        self,
        identity: UnlockedIdentity,
        target_did: str,
        attachment: AttachmentRef,
        caption: str | None,
        pending: PendingOperation,
    ) -> Any: ...


class AttachmentServicePort(Protocol):
    async def capabilities(self, identity: Any) -> Any: ...
    async def create_slot(self, *args: Any, **kwargs: Any) -> Any: ...
    async def upload(self, slot: Any, prepared: Any) -> None: ...
    async def commit(self, *args: Any, **kwargs: Any) -> Any: ...
    async def best_effort_abort(self, *args: Any, **kwargs: Any) -> None: ...
    async def get_download_ticket(
        self, identity: AuthenticatedIdentity, context: AttachmentContext
    ) -> Any: ...
    async def download(self, ticket: Any, attachment: AttachmentRef, destination: Any) -> Path: ...
