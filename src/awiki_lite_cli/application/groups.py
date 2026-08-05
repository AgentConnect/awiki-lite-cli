"""Ordinary Group application workflows with exact-retry state."""

from __future__ import annotations

import hashlib
import json

from awiki_lite_cli.domain.models import (
    AuthenticatedIdentity,
    GroupMember,
    GroupMessage,
    GroupSummary,
    UnlockedIdentity,
)
from awiki_lite_cli.infrastructure.group_service import GroupService, validate_group_did
from awiki_lite_cli.infrastructure.message_service import validate_did
from awiki_lite_cli.infrastructure.rpc import JsonRpcFailure
from awiki_lite_cli.infrastructure.state import SecureStateStore


class GroupWorkflow:
    def __init__(self, service: GroupService, store: SecureStateStore) -> None:
        self.service = service
        self.store = store

    async def create(self, identity: UnlockedIdentity, display_name: str) -> GroupSummary:
        name = display_name.strip()
        if not name or len(name) > 128:
            raise ValueError("group name must contain 1-128 characters")
        capabilities = await self.service.capabilities(identity)
        digest = _input_digest({"display_name": name})
        pending = self.store.prepare_operation(
            "group.create", capabilities.service_did, digest, needs_message_id=False
        )
        try:
            result = await self.service.create(identity, capabilities.service_did, name, pending)
        except JsonRpcFailure:
            self.store.abandon_operation(pending)
            raise
        self.store.complete_operation(pending)
        return result

    async def add(self, identity: UnlockedIdentity, group_did: str, member_did: str) -> str:
        group = validate_group_did(group_did)
        member = validate_did(member_did)
        await self.service.capabilities(identity)
        digest = _input_digest({"group_did": group, "member_did": member})
        pending = self.store.prepare_operation("group.add", group, digest, needs_message_id=False)
        try:
            result = await self.service.add(identity, group, member, pending)
        except JsonRpcFailure:
            self.store.abandon_operation(pending)
            raise
        self.store.complete_operation(pending)
        return result

    async def send(self, identity: UnlockedIdentity, group_did: str, text: str) -> GroupMessage:
        group = validate_group_did(group_did)
        if not text or not text.strip():
            raise ValueError("message text must not be empty")
        capabilities = await self.service.capabilities(identity)
        if (
            capabilities.max_group_message_bytes is not None
            and len(text.encode()) > capabilities.max_group_message_bytes
        ):
            raise ValueError("message text exceeds the service Group message limit")
        digest = _input_digest({"group_did": group, "text": text})
        pending = self.store.prepare_operation("group.send", group, digest, needs_message_id=True)
        try:
            result = await self.service.send_text(identity, group, text, pending)
        except JsonRpcFailure:
            self.store.abandon_operation(pending)
            raise
        self.store.complete_operation(pending)
        return result

    async def list_groups(
        self, limit: int, cursor: str | None
    ) -> tuple[list[GroupSummary], str | None]:
        return await self.service.list_groups(self._authenticated(), limit, cursor)

    async def info(self, group_did: str) -> GroupSummary:
        return await self.service.info(self._authenticated(), group_did)

    async def members(
        self, group_did: str, limit: int, cursor: str | None
    ) -> tuple[list[GroupMember], str | None]:
        return await self.service.members(self._authenticated(), group_did, limit, cursor)

    async def messages(
        self, group_did: str, limit: int, since_seq: int | None
    ) -> tuple[list[GroupMessage], int | None]:
        return await self.service.messages(self._authenticated(), group_did, limit, since_seq)

    def _authenticated(self) -> AuthenticatedIdentity:
        return AuthenticatedIdentity(self.store.load_public(), self.store.load_session())


def _input_digest(value: dict[str, str]) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()
