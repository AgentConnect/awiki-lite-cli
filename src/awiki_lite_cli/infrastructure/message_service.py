"""Plain Direct Message Service payloads and RPC adapter."""

from __future__ import annotations

import re
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
from awiki_lite_cli.infrastructure.rpc import call_json_rpc

ORIGIN_SCHEME = "anp-rfc9421-origin-proof-v1"
DID_RE = re.compile(r"^did:wba:[A-Za-z0-9.-]+(?::[^\s]+)?$")


def validate_did(value: str) -> str:
    did = value.strip()
    if not DID_RE.fullmatch(did):
        raise ValueError("recipient must be an exact did:wba identifier")
    return did


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


def build_inbox(did: str, limit: int, skip: int = 0) -> dict[str, Any]:
    return _local_params("anp.inbox.local.v1", did, {"user_did": did, "limit": limit, "skip": skip})


def build_mark_read(did: str, message_ids: list[str]) -> dict[str, Any]:
    if not message_ids or any(not value for value in message_ids):
        raise ValueError("message_ids must not be empty")
    return _local_params("anp.inbox.local.v1", did, {"user_did": did, "message_ids": message_ids})


def build_history(did: str, peer_did: str, limit: int, skip: int = 0) -> dict[str, Any]:
    return _local_params(
        "anp.direct.local.v1",
        did,
        {"user_did": did, "peer_did": validate_did(peer_did), "limit": limit, "skip": skip},
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
    return {
        "meta": {"profile": profile, "security_profile": "transport-protected", "sender_did": did},
        "body": body,
    }


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
        self, identity: AuthenticatedIdentity | UnlockedIdentity, limit: int
    ) -> tuple[list[ChatMessage], bool]:
        result = await call_json_rpc(
            self.client,
            self.endpoint,
            "inbox.get",
            build_inbox(identity.identity.did, limit),
            access_token=identity.session.access_token,
        )
        return _parse_page(result), bool(_object(result).get("has_more", False))

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
        return int(_object(result).get("updated_count", 0))

    async def history(
        self, identity: AuthenticatedIdentity | UnlockedIdentity, peer: str, limit: int
    ) -> tuple[list[ChatMessage], bool]:
        result = await call_json_rpc(
            self.client,
            self.endpoint,
            "direct.get_history",
            build_history(identity.identity.did, peer, limit),
            access_token=identity.session.access_token,
        )
        return _parse_page(result), bool(_object(result).get("has_more", False))


def _parse_page(value: Any) -> list[ChatMessage]:
    page = _object(value)
    messages = page.get("messages")
    if not isinstance(messages, list):
        raise RuntimeError("service returned an invalid message page")
    output: list[ChatMessage] = []
    for item in messages:
        row = _object(item)
        if row.get("type") == "attachment_manifest":
            if row.get("content_type") != MANIFEST_CONTENT_TYPE:
                raise RuntimeError("service returned an invalid attachment projection")
            attachment, caption = parse_manifest(row.get("content"))
            output.append(
                ChatMessage(
                    str(row["id"]),
                    str(row["sender_did"]),
                    str(row["receiver_did"]),
                    "",
                    str(row.get("sent_at") or row.get("created_at") or ""),
                    bool(row.get("is_read")),
                    (attachment,),
                    caption,
                )
            )
            continue
        if row.get("content_type") != "text/plain" or row.get("type") != "text":
            continue
        output.append(
            ChatMessage(
                str(row["id"]),
                str(row["sender_did"]),
                str(row["receiver_did"]),
                str(row["content"]),
                str(row.get("sent_at") or row.get("created_at") or ""),
                bool(row.get("is_read")),
            )
        )
    return output


def _object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError("service returned an invalid result")
    return value
