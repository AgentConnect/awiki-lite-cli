"""Ordinary Group application workflows with exact-retry state."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import Any

from awiki_lite_cli.application.errors import JsonRpcFailure
from awiki_lite_cli.application.ports import GroupServicePort, StateStorePort
from awiki_lite_cli.domain.models import (
    AttachmentContext,
    AuthenticatedIdentity,
    GroupMember,
    GroupMessage,
    GroupSummary,
    UnlockedIdentity,
)
from awiki_lite_cli.domain.validation import validate_wba_did

LITE_MAX_GROUP_MEMBERS = 500


def resolve_max_members(advertised: int | None) -> int:
    limit = advertised if advertised is not None else LITE_MAX_GROUP_MEMBERS
    return min(limit, LITE_MAX_GROUP_MEMBERS)


class GroupWorkflow:
    def __init__(
        self,
        service: GroupServicePort,
        store: StateStorePort,
        manifest_parser: Callable[[Any], tuple[Any, str | None]],
    ) -> None:
        self.service = service
        self.store = store
        self.manifest_parser = manifest_parser

    async def create(self, identity: UnlockedIdentity, display_name: str) -> GroupSummary:
        name = display_name.strip()
        if not name or len(name) > 128:
            raise ValueError("group name must contain 1-128 characters")
        capabilities = await self.service.capabilities(identity)
        max_members = resolve_max_members(getattr(capabilities, "max_members", None))
        digest_input = {"display_name": name}
        if max_members != LITE_MAX_GROUP_MEMBERS:
            digest_input["max_members"] = str(max_members)
        digest = _input_digest(digest_input)
        pending = self.store.prepare_operation(
            "group.create", capabilities.service_did, digest, needs_message_id=False
        )
        try:
            result = await self.service.create(
                identity, capabilities.service_did, name, max_members, pending
            )
        except JsonRpcFailure:
            self.store.abandon_operation(pending)
            raise
        self.store.complete_operation(pending)
        return result

    async def add(self, identity: UnlockedIdentity, group_did: str, member_did: str) -> str:
        group = validate_wba_did(group_did, field="group DID")
        member = validate_wba_did(member_did)
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
        group = validate_wba_did(group_did, field="group DID")
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
        group = validate_wba_did(group_did, field="group DID")
        return await self.service.info(self._authenticated(), group)

    async def members(
        self, group_did: str, limit: int, cursor: str | None
    ) -> tuple[list[GroupMember], str | None]:
        group = validate_wba_did(group_did, field="group DID")
        return await self.service.members(self._authenticated(), group, limit, cursor)

    async def messages(
        self, group_did: str, limit: int, since_seq: int | None
    ) -> tuple[list[GroupMessage], int | None]:
        group = validate_wba_did(group_did, field="group DID")
        rows, next_seq = await self.service.messages(self._authenticated(), group, limit, since_seq)
        contexts = []
        for message in rows:
            if message.message_type == "attachment_manifest":
                attachment, _caption = self.manifest_parser(message.content)
                contexts.append(
                    AttachmentContext(
                        message.message_id,
                        message.sender_did,
                        None,
                        message.group_did,
                        attachment,
                    )
                )
        self.store.save_attachment_contexts(contexts)
        return rows, next_seq

    def _authenticated(self) -> AuthenticatedIdentity:
        return AuthenticatedIdentity(self.store.load_public(), self.store.load_session())


def _input_digest(value: dict[str, str]) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()
