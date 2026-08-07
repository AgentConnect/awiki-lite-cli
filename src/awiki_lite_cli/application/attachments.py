"""Single-file plain attachment upload and Manifest-send workflow."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import httpx

from awiki_lite_cli.application.errors import JsonRpcFailure
from awiki_lite_cli.application.ports import (
    AttachmentServicePort,
    GroupServicePort,
    MessageServicePort,
    StateStorePort,
)
from awiki_lite_cli.domain.models import AuthenticatedIdentity, GroupMessage, UnlockedIdentity
from awiki_lite_cli.domain.validation import validate_wba_did


class AttachmentWorkflow:
    def __init__(
        self,
        attachments: AttachmentServicePort,
        direct: MessageServicePort,
        groups: GroupServicePort,
        store: StateStorePort,
        caption_normalizer: Callable[[str | None], str | None],
        file_preparer: Callable[[Path, int], Any],
        destination_preparer: Callable[[Path, str], Any],
    ) -> None:
        self.attachments = attachments
        self.direct = direct
        self.groups = groups
        self.store = store
        self.caption_normalizer = caption_normalizer
        self.file_preparer = file_preparer
        self.destination_preparer = destination_preparer

    async def send(
        self,
        identity: UnlockedIdentity,
        file_path: Path,
        *,
        recipient_did: str | None,
        group_did: str | None,
        caption: str | None,
    ) -> tuple[str, str]:
        target_kind, target_did, pending_kind = _target(recipient_did, group_did)
        normalized_caption = self.caption_normalizer(caption)
        capabilities = await self.attachments.capabilities(identity)
        if target_kind == "agent":
            await self.direct.ensure_direct_base(identity)
        else:
            await self.groups.capabilities(identity)

        with self.file_preparer(file_path, capabilities.max_object_bytes) as prepared:
            input_digest = _input_digest(
                {
                    "target_kind": target_kind,
                    "target_did": target_did,
                    "filename": prepared.filename,
                    "mime_type": prepared.mime_type,
                    "size": str(prepared.size),
                    "sha256_b64u": prepared.sha256_b64u,
                    "caption": normalized_caption or "",
                }
            )
            stable = _stable_values(identity.identity.did, pending_kind, target_did, input_digest)
            pending = self.store.prepare_operation(
                pending_kind,
                target_did,
                input_digest,
                needs_message_id=True,
                values=stable,
                initial_stage="prepared",
            )
            try:
                slot = await self.attachments.create_slot(
                    identity,
                    capabilities.service_did,
                    stable["attachment_id"],
                    prepared,
                    target_kind,
                    target_did,
                    stable["create_operation_id"],
                    pending.created_at,
                )
            except JsonRpcFailure:
                self.store.abandon_operation(pending)
                raise

            if pending.stage == "prepared":
                try:
                    await self.attachments.upload(slot, prepared)
                except (httpx.HTTPStatusError, RuntimeError):
                    await self.attachments.best_effort_abort(
                        identity,
                        capabilities.service_did,
                        slot,
                        stable["abort_operation_id"],
                        pending.created_at,
                    )
                    self.store.abandon_operation(pending)
                    raise
                pending = self.store.advance_operation(pending, "uploaded")

            try:
                committed = await self.attachments.commit(
                    identity,
                    capabilities.service_did,
                    slot,
                    prepared,
                    stable["commit_operation_id"],
                    pending.created_at,
                )
            except JsonRpcFailure:
                await self.attachments.best_effort_abort(
                    identity,
                    capabilities.service_did,
                    slot,
                    stable["abort_operation_id"],
                    pending.created_at,
                )
                self.store.abandon_operation(pending)
                raise
            if pending.stage == "uploaded":
                pending = self.store.advance_operation(pending, "committed")
            if pending.stage != "committed" or pending.message_id is None:
                raise RuntimeError("attachment operation state is invalid")

            try:
                if target_kind == "agent":
                    message = await self.direct.send_attachment(
                        identity,
                        target_did,
                        committed.attachment,
                        normalized_caption,
                        pending,
                    )
                    message_id = message.message_id
                else:
                    group_message: GroupMessage = await self.groups.send_attachment(
                        identity,
                        target_did,
                        committed.attachment,
                        normalized_caption,
                        pending,
                    )
                    message_id = group_message.message_id
            except JsonRpcFailure:
                self.store.abandon_operation(pending)
                raise
            self.store.complete_operation(pending)
            return message_id, committed.attachment.attachment_id

    async def download(
        self,
        identity: AuthenticatedIdentity,
        message_id: str,
        attachment_id: str,
        output_dir: Path,
    ) -> Path:
        if not message_id or not attachment_id:
            raise ValueError("message and attachment identifiers must not be empty")
        context = self.store.load_attachment_context(message_id, attachment_id)
        with self.destination_preparer(output_dir, context.attachment.filename) as destination:
            ticket = await self.attachments.get_download_ticket(identity, context)
            return await self.attachments.download(ticket, context.attachment, destination)


def _target(recipient_did: str | None, group_did: str | None) -> tuple[str, str, str]:
    if (recipient_did is None) == (group_did is None):
        raise ValueError("choose exactly one of --to and --group")
    if recipient_did is not None:
        return "agent", validate_wba_did(recipient_did), "direct.attachment.send"
    assert group_did is not None
    return "group", validate_wba_did(group_did, field="group DID"), "group.attachment.send"


def _input_digest(value: dict[str, str]) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def _stable_values(
    sender_did: str, kind: str, target_did: str, input_digest: str
) -> dict[str, str]:
    base = f"awiki-lite:v0.2:{sender_did}:{kind}:{target_did}:{input_digest}"
    return {
        "attachment_id": "att-" + str(uuid5(NAMESPACE_URL, base + ":attachment")),
        "create_operation_id": str(uuid5(NAMESPACE_URL, base + ":create")),
        "commit_operation_id": str(uuid5(NAMESPACE_URL, base + ":commit")),
        "abort_operation_id": str(uuid5(NAMESPACE_URL, base + ":abort")),
    }
