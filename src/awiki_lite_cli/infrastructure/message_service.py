"""Plain Direct Message Service payloads and RPC adapter."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import httpx

from awiki_lite_cli.domain.models import (
    AttachmentRef,
    AuthenticatedIdentity,
    ChatMessage,
    PendingOperation,
    UnlockedIdentity,
)
from awiki_lite_cli.infrastructure.anp_sdk import generate_origin_proof
from awiki_lite_cli.infrastructure.attachment_manifest import (
    MANIFEST_CONTENT_TYPE,
    build_manifest,
    parse_manifest,
)
from awiki_lite_cli.infrastructure.rpc import ProtocolResponseError, call_json_rpc
from awiki_lite_cli.infrastructure.validation import validate_wba_did

ORIGIN_SCHEME = "anp-rfc9421-origin-proof-v1"


def validate_did(value: str) -> str:
    return validate_wba_did(value, field="recipient")


def build_direct_send(
    identity: UnlockedIdentity,
    recipient_did: str,
    text: str,
    *,
    operation_id: str | None = None,
    message_id: str | None = None,
    created_at: str | None = None,
    proof_created: int | None = None,
    proof_nonce: str | None = None,
) -> dict[str, Any]:
    recipient = validate_did(recipient_did)
    if not text or not text.strip():
        raise ValueError("message text must not be empty")
    if len(text.encode()) > 64 * 1024:
        raise ValueError("message text is too large")
    meta = {
        "profile": "anp.direct.base.v1",
        "security_profile": "transport-protected",
        "sender_did": identity.identity.did,
        "target": {"kind": "agent", "did": recipient},
        "operation_id": operation_id or str(uuid4()),
        "message_id": message_id or str(uuid4()),
        "created_at": created_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "content_type": "text/plain",
    }
    body = {"text": text}
    proof = generate_origin_proof(
        "direct.send",
        meta,
        body,
        identity.device_signing_private_key,
        identity.identity.verification_method,
        created=proof_created,
        nonce=proof_nonce,
    )
    return {"meta": meta, "auth": {"scheme": ORIGIN_SCHEME, "origin_proof": proof}, "body": body}


def build_direct_attachment_send(
    identity: UnlockedIdentity,
    recipient_did: str,
    attachment: AttachmentRef,
    caption: str | None,
    pending: PendingOperation,
) -> dict[str, Any]:
    recipient = validate_did(recipient_did)
    if (
        pending.kind != "direct.attachment.send"
        or pending.target_did != recipient
        or pending.message_id is None
    ):
        raise ValueError("pending operation does not match the Direct attachment request")
    meta = {
        "profile": "anp.direct.base.v1",
        "security_profile": "transport-protected",
        "sender_did": identity.identity.did,
        "target": {"kind": "agent", "did": recipient},
        "operation_id": pending.operation_id,
        "message_id": pending.message_id,
        "created_at": pending.created_at,
        "content_type": MANIFEST_CONTENT_TYPE,
    }
    body = {"payload": build_manifest(attachment, caption)}
    proof = generate_origin_proof(
        "direct.send",
        meta,
        body,
        identity.device_signing_private_key,
        identity.identity.verification_method,
        created=pending.proof_created,
        nonce=pending.proof_nonce,
    )
    return {"meta": meta, "auth": {"scheme": ORIGIN_SCHEME, "origin_proof": proof}, "body": body}


def build_mark_read(did: str, message_ids: list[str]) -> dict[str, Any]:
    if not message_ids or any(not value for value in message_ids):
        raise ValueError("message_ids must not be empty")
    return _local_params("anp.inbox.local.v1", did, {"user_did": did, "message_ids": message_ids})


def build_sync_delta(did: str, since_event_seq: str, limit: int = 100) -> dict[str, Any]:
    _validate_decimal_cursor(since_event_seq, "since_event_seq")
    return _sync_params(
        did,
        {"user_did": did, "since_event_seq": since_event_seq, "limit": limit},
    )


def build_sync_thread_after(
    did: str, peer_did: str, after_server_seq: str, limit: int = 100
) -> dict[str, Any]:
    _validate_decimal_cursor(after_server_seq, "after_server_seq")
    return _sync_params(
        did,
        {
            "user_did": did,
            "thread": {"kind": "direct", "peer_did": validate_did(peer_did)},
            "after_server_seq": after_server_seq,
            "limit": limit,
        },
    )


def build_capabilities(did: str) -> dict[str, Any]:
    return {
        "meta": {
            "profile": "anp.core.binding.v1",
            "security_profile": "transport-protected",
            "sender_did": did,
            "operation_id": str(uuid4()),
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        },
        "body": {},
    }


def _local_params(profile: str, did: str, body: dict[str, Any]) -> dict[str, Any]:
    if not 1 <= int(body.get("limit", 1)) <= 100:
        raise ValueError("limit must be between 1 and 100")
    if not isinstance(body.get("skip", 0), int) or isinstance(body.get("skip", 0), bool):
        raise ValueError("skip must be a non-negative integer")
    if int(body.get("skip", 0)) < 0:
        raise ValueError("skip must be a non-negative integer")
    return {
        "meta": {"profile": profile, "security_profile": "transport-protected", "sender_did": did},
        "body": body,
    }


def _sync_params(did: str, body: dict[str, Any]) -> dict[str, Any]:
    limit = body.get("limit")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    return {
        "meta": {
            "profile": "anp.sync.local.v1",
            "security_profile": "transport-protected",
            "sender_did": did,
            "operation_id": f"op-{uuid4()}",
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        },
        "body": body,
    }


def _validate_decimal_cursor(value: str, field: str) -> None:
    if not value.isdecimal():
        raise ValueError(f"{field} must be a non-negative decimal string")


class MessageService:
    def __init__(self, client: httpx.AsyncClient, base_url: str) -> None:
        self.client = client
        self.endpoint = base_url.rstrip("/") + "/im/rpc"

    async def ensure_direct_base(self, identity: AuthenticatedIdentity | UnlockedIdentity) -> None:
        result = _object(
            await call_json_rpc(
                self.client,
                self.endpoint,
                "anp.get_capabilities",
                build_capabilities(identity.identity.did),
                access_token=identity.session.access_token,
            )
        )
        requirements = {
            "supported_profiles": "anp.direct.base.v1",
            "supported_security_profiles": "transport-protected",
            "supported_content_types": "text/plain",
        }
        for field, required in requirements.items():
            advertised = result.get(field)
            if not isinstance(advertised, list) or required not in advertised:
                raise RuntimeError(f"message service does not advertise required {required}")
        policies = result.get("proof_policies")
        if not isinstance(policies, dict) or policies.get("direct_base_origin_proof") != "required":
            raise RuntimeError("message service does not advertise the required Direct Base proof")

    async def send(
        self,
        identity: UnlockedIdentity,
        recipient: str,
        text: str,
        *,
        operation_id: str | None = None,
        message_id: str | None = None,
        created_at: str | None = None,
        proof_created: int | None = None,
        proof_nonce: str | None = None,
        preflight: bool = True,
    ) -> ChatMessage:
        if preflight:
            await self.ensure_direct_base(identity)
        params = build_direct_send(
            identity,
            recipient,
            text,
            operation_id=operation_id,
            message_id=message_id,
            created_at=created_at,
            proof_created=proof_created,
            proof_nonce=proof_nonce,
        )
        for attempt in range(2):
            try:
                result = await call_json_rpc(
                    self.client,
                    self.endpoint,
                    "direct.send",
                    params,
                    access_token=identity.session.access_token,
                )
                break
            except httpx.TransportError:
                if attempt == 1:
                    raise
        else:  # pragma: no cover
            raise RuntimeError("direct.send retry loop ended unexpectedly")
        value = _object(result)
        meta = params["meta"]
        required = {"accepted", "message_id", "operation_id", "target_did", "accepted_at"}
        if not required.issubset(value) or value["accepted"] is not True:
            raise RuntimeError("service returned an invalid direct.send result")
        if (
            value["message_id"] != meta["message_id"]
            or value["operation_id"] != meta["operation_id"]
            or value["target_did"] != recipient
        ):
            raise RuntimeError("service returned mismatched direct.send identifiers")
        return ChatMessage(
            str(value["message_id"]),
            identity.identity.did,
            recipient,
            text,
            str(value["accepted_at"]),
        )

    async def send_attachment(
        self,
        identity: UnlockedIdentity,
        recipient: str,
        attachment: AttachmentRef,
        caption: str | None,
        pending: PendingOperation,
    ) -> ChatMessage:
        params = build_direct_attachment_send(identity, recipient, attachment, caption, pending)
        value = await self._send_params(identity, recipient, params)
        return ChatMessage(
            str(value["message_id"]),
            identity.identity.did,
            recipient,
            "",
            str(value["accepted_at"]),
            attachments=(attachment,),
            caption=caption,
        )

    async def _send_params(
        self, identity: UnlockedIdentity, recipient: str, params: dict[str, Any]
    ) -> dict[str, Any]:
        for attempt in range(2):
            try:
                result = await call_json_rpc(
                    self.client,
                    self.endpoint,
                    "direct.send",
                    params,
                    access_token=identity.session.access_token,
                )
                break
            except httpx.TransportError:
                if attempt == 1:
                    raise
        else:  # pragma: no cover
            raise RuntimeError("direct.send retry loop ended unexpectedly")
        value = _object(result)
        meta = params["meta"]
        required = {"accepted", "message_id", "operation_id", "target_did", "accepted_at"}
        if not required.issubset(value) or value["accepted"] is not True:
            raise RuntimeError("service returned an invalid direct.send result")
        if (
            value["message_id"] != meta["message_id"]
            or value["operation_id"] != meta["operation_id"]
            or value["target_did"] != recipient
        ):
            raise RuntimeError("service returned mismatched direct.send identifiers")
        return value

    async def inbox(
        self, identity: AuthenticatedIdentity | UnlockedIdentity, limit: int, skip: int = 0
    ) -> tuple[list[ChatMessage], bool]:
        peers = await self._direct_peers(identity)
        messages: list[ChatMessage] = []
        for peer in peers:
            thread_messages, _ = await self._thread_messages(identity, peer, None)
            messages.extend(
                item for item in thread_messages if item.target_did == identity.identity.did
            )
        messages = list({item.message_id: item for item in messages}.values())
        messages.sort(key=lambda item: (item.created_at or "", item.message_id), reverse=True)
        end = skip + limit
        return messages[skip:end], len(messages) > end

    async def mark_read(
        self, identity: AuthenticatedIdentity | UnlockedIdentity, ids: list[str]
    ) -> int:
        result = await call_json_rpc(
            self.client,
            self.endpoint,
            "inbox.mark_read",
            build_mark_read(identity.identity.did, ids),
            access_token=identity.session.access_token,
        )
        page = _object(result)
        count = page.get("updated_count", 0)
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ProtocolResponseError("service returned an invalid updated_count")
        return count

    async def history(
        self,
        identity: AuthenticatedIdentity | UnlockedIdentity,
        peer: str,
        limit: int,
        skip: int = 0,
    ) -> tuple[list[ChatMessage], bool]:
        messages, remote_has_more = await self._thread_messages(identity, peer, skip + limit + 1)
        end = skip + limit
        return messages[skip:end], remote_has_more or len(messages) > end

    async def _direct_peers(self, identity: AuthenticatedIdentity | UnlockedIdentity) -> list[str]:
        cursor = "0"
        peers: set[str] = set()
        while True:
            page = _object(
                await call_json_rpc(
                    self.client,
                    self.endpoint,
                    "sync.delta",
                    build_sync_delta(identity.identity.did, cursor),
                    access_token=identity.session.access_token,
                )
            )
            if _required_bool(page, "snapshot_required", default=False):
                raise RuntimeError("message sync history is no longer available from the beginning")
            events = page.get("events")
            if not isinstance(events, list):
                raise ProtocolResponseError("service returned an invalid sync event page")
            for event in events:
                payload = _object(event).get("payload")
                if not isinstance(payload, dict):
                    continue
                thread = payload.get("thread")
                if not isinstance(thread, dict) or thread.get("kind") != "direct":
                    continue
                peer = thread.get("peer_did")
                if not isinstance(peer, str):
                    raise ProtocolResponseError("service returned an invalid direct thread")
                try:
                    peers.add(validate_did(peer))
                except ValueError as exc:
                    raise ProtocolResponseError(
                        "service returned an invalid direct thread"
                    ) from exc
            if not _required_bool(page, "has_more", default=False):
                return sorted(peers)
            next_cursor = _required_str(page, "next_event_seq")
            _validate_remote_cursor(next_cursor, "next_event_seq")
            if int(next_cursor) <= int(cursor):
                raise ProtocolResponseError("sync.delta did not advance its cursor")
            cursor = next_cursor

    async def _thread_messages(
        self,
        identity: AuthenticatedIdentity | UnlockedIdentity,
        peer: str,
        requested: int | None,
    ) -> tuple[list[ChatMessage], bool]:
        cursor = "0"
        messages: list[ChatMessage] = []
        has_more = False
        while requested is None or len(messages) < requested:
            page = _object(
                await call_json_rpc(
                    self.client,
                    self.endpoint,
                    "sync.thread_after",
                    build_sync_thread_after(identity.identity.did, peer, cursor),
                    access_token=identity.session.access_token,
                )
            )
            messages.extend(_parse_page(page, identity.identity.did))
            has_more = _required_bool(page, "has_more", default=False)
            if not has_more:
                break
            next_cursor = _required_str(page, "next_after_server_seq")
            _validate_remote_cursor(next_cursor, "next_after_server_seq")
            if int(next_cursor) <= int(cursor):
                raise ProtocolResponseError("sync.thread_after did not advance its cursor")
            cursor = next_cursor
        return messages, has_more


def _parse_page(page: dict[str, Any], fallback_target: str | None = None) -> list[ChatMessage]:
    messages = page.get("messages")
    if not isinstance(messages, list):
        raise RuntimeError("service returned an invalid message page")
    output: list[ChatMessage] = []
    for item in messages:
        row = _object(item)
        content_type = row.get("content_type")
        if content_type == MANIFEST_CONTENT_TYPE:
            attachment, caption = parse_manifest(row.get("content", row.get("payload")))
            output.append(
                ChatMessage(
                    _message_id(row),
                    _response_did(row, "sender_did"),
                    _message_target(row, fallback_target),
                    "",
                    _optional_timestamp(row),
                    _required_bool(row, "is_read", default=False),
                    (attachment,),
                    caption,
                )
            )
            continue
        if content_type != "text/plain":
            continue
        output.append(
            ChatMessage(
                _message_id(row),
                _response_did(row, "sender_did"),
                _message_target(row, fallback_target),
                _message_text(row),
                _optional_timestamp(row),
                _required_bool(row, "is_read", default=False),
            )
        )
    return output


def _object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProtocolResponseError("service returned an invalid result")
    return value


def _required_str(value: dict[str, Any], field: str, *, allow_empty: bool = False) -> str:
    result = value.get(field)
    if not isinstance(result, str) or (not allow_empty and not result):
        raise ProtocolResponseError(f"service returned an invalid {field}")
    return result


def _required_bool(value: dict[str, Any], field: str, *, default: bool | None = None) -> bool:
    result = value.get(field, default)
    if not isinstance(result, bool):
        raise ProtocolResponseError(f"service returned an invalid {field}")
    return result


def _optional_timestamp(value: dict[str, Any]) -> str:
    result = value.get("sent_at", value.get("created_at", ""))
    if not isinstance(result, str):
        raise ProtocolResponseError("service returned an invalid message timestamp")
    return result


def _response_did(value: dict[str, Any], field: str) -> str:
    try:
        return validate_did(_required_str(value, field))
    except ValueError as exc:
        raise ProtocolResponseError(f"service returned an invalid {field}") from exc


def _message_id(value: dict[str, Any]) -> str:
    for field in ("id", "message_id"):
        result = value.get(field)
        if isinstance(result, str) and result:
            return result
    raise ProtocolResponseError("service returned an invalid message id")


def _message_target(value: dict[str, Any], fallback: str | None) -> str:
    for field in ("receiver_did", "target_did"):
        if field in value:
            return _response_did(value, field)
    if fallback is None:
        raise ProtocolResponseError("service returned an invalid receiver_did")
    try:
        return validate_did(fallback)
    except ValueError as exc:  # pragma: no cover - local identity is validated on registration
        raise ProtocolResponseError("service returned an invalid receiver_did") from exc


def _message_text(value: dict[str, Any]) -> str:
    for field in ("content", "text"):
        if field in value:
            return _required_str(value, field, allow_empty=True)
    raise ProtocolResponseError("service returned invalid message content")


def _validate_remote_cursor(value: str, field: str) -> None:
    try:
        _validate_decimal_cursor(value, field)
    except ValueError as exc:
        raise ProtocolResponseError(f"service returned an invalid {field}") from exc
