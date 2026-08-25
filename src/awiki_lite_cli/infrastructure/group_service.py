"""Ordinary transport-protected Group Base v1 and local-view adapter."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from awiki_lite_cli.domain.models import (
    AttachmentRef,
    AuthenticatedIdentity,
    GroupMember,
    GroupMessage,
    GroupSummary,
    PendingOperation,
    UnlockedIdentity,
)
from awiki_lite_cli.domain.validation import validate_wba_did
from awiki_lite_cli.infrastructure.anp_sdk import generate_origin_proof
from awiki_lite_cli.infrastructure.attachment_manifest import (
    MANIFEST_CONTENT_TYPE,
    build_manifest,
    parse_manifest,
)
from awiki_lite_cli.infrastructure.message_service import build_capabilities, validate_did
from awiki_lite_cli.infrastructure.rpc import ProtocolResponseError, call_json_rpc

GROUP_PROFILE = "anp.group.base.v1"
GROUP_LOCAL_PROFILE = "anp.group.local.v1"
TRANSPORT_PROTECTED = "transport-protected"
ORIGIN_SCHEME = "anp-rfc9421-origin-proof-v1"


@dataclass(frozen=True, slots=True)
class GroupCapabilities:
    service_did: str
    max_group_message_bytes: int | None
    max_members: int | None


def validate_group_did(value: str) -> str:
    return validate_wba_did(value, field="group DID")


def build_group_create(
    identity: UnlockedIdentity,
    service_did: str,
    display_name: str,
    max_members: int,
    pending: PendingOperation,
) -> dict[str, Any]:
    name = display_name.strip()
    if not name or len(name) > 128:
        raise ValueError("group name must contain 1-128 characters")
    body = {
        "group_profile": {"display_name": name, "discoverability": "private"},
        "group_policy": {
            "message_security_profile": TRANSPORT_PROTECTED,
            "bootstrap_security_profile": TRANSPORT_PROTECTED,
            "admission_mode": "admin-add",
            "permissions": {
                "send": "member",
                "add": "admin",
                "remove": "admin",
                "update_profile": "admin",
                "update_policy": "owner",
            },
            "attachments_allowed": True,
            "max_members": str(max_members),
        },
    }
    return _signed_group_params(
        identity,
        "group.create",
        "service",
        validate_did(service_did),
        "application/json",
        body,
        pending,
    )


def build_group_add(
    identity: UnlockedIdentity,
    group_did: str,
    member_did: str,
    pending: PendingOperation,
) -> dict[str, Any]:
    return _signed_group_params(
        identity,
        "group.add",
        "group",
        validate_group_did(group_did),
        "application/json",
        {"member_did": validate_did(member_did), "role": "member"},
        pending,
    )


def build_group_send_text(
    identity: UnlockedIdentity,
    group_did: str,
    text: str,
    pending: PendingOperation,
) -> dict[str, Any]:
    if not text or not text.strip():
        raise ValueError("message text must not be empty")
    return _signed_group_params(
        identity,
        "group.send",
        "group",
        validate_group_did(group_did),
        "text/plain",
        {"text": text},
        pending,
    )


def build_group_send_attachment(
    identity: UnlockedIdentity,
    group_did: str,
    attachment: AttachmentRef,
    caption: str | None,
    pending: PendingOperation,
) -> dict[str, Any]:
    if pending.kind != "group.attachment.send":
        raise ValueError("pending operation does not match the Group attachment request")
    return _signed_group_params(
        identity,
        "group.send",
        "group",
        validate_group_did(group_did),
        MANIFEST_CONTENT_TYPE,
        {"payload": build_manifest(attachment, caption)},
        pending,
        pending_kind="group.attachment.send",
    )


def _signed_group_params(
    identity: UnlockedIdentity,
    method: str,
    target_kind: str,
    target_did: str,
    content_type: str,
    body: dict[str, Any],
    pending: PendingOperation,
    *,
    pending_kind: str | None = None,
) -> dict[str, Any]:
    if pending.kind != (pending_kind or method) or pending.target_did != target_did:
        raise ValueError("pending operation does not match the Group request")
    meta: dict[str, Any] = {
        "profile": GROUP_PROFILE,
        "security_profile": TRANSPORT_PROTECTED,
        "sender_did": identity.identity.did,
        "target": {"kind": target_kind, "did": target_did},
        "operation_id": pending.operation_id,
        "created_at": pending.created_at,
        "content_type": content_type,
    }
    if method == "group.send":
        if pending.message_id is None:
            raise ValueError("Group send requires a message id")
        meta["message_id"] = pending.message_id
    proof = generate_origin_proof(
        method,
        meta,
        body,
        identity.device_signing_private_key,
        identity.identity.verification_method,
        created=pending.proof_created,
        nonce=pending.proof_nonce,
    )
    return {"meta": meta, "auth": {"scheme": ORIGIN_SCHEME, "origin_proof": proof}, "body": body}


def build_group_info(did: str, group_did: str) -> dict[str, Any]:
    return {
        "meta": _group_meta(GROUP_PROFILE, did, group_did),
        "body": {"include_policy": True, "include_member_list": False},
    }


def build_group_list(did: str, limit: int, cursor: str | None = None) -> dict[str, Any]:
    body = _page_body(limit, cursor)
    return {"meta": _group_meta(GROUP_LOCAL_PROFILE, did), "body": body}


def build_group_members(
    did: str, group_did: str, limit: int, cursor: str | None = None
) -> dict[str, Any]:
    group = validate_group_did(group_did)
    body = {"group_did": group, **_page_body(limit, cursor)}
    return {"meta": _group_meta(GROUP_LOCAL_PROFILE, did, group), "body": body}


def build_group_messages(
    did: str, group_did: str, limit: int, since_seq: int | None = None
) -> dict[str, Any]:
    group = validate_group_did(group_did)
    if since_seq is not None and since_seq < 0:
        raise ValueError("since-seq must not be negative")
    body: dict[str, Any] = {"group_did": group, "limit": _limit(limit)}
    if since_seq is not None:
        body["since_seq"] = since_seq
    return {"meta": _group_meta(GROUP_LOCAL_PROFILE, did, group), "body": body}


def _group_meta(profile: str, did: str, group_did: str | None = None) -> dict[str, Any]:
    meta: dict[str, Any] = {
        "profile": profile,
        "security_profile": TRANSPORT_PROTECTED,
        "sender_did": validate_did(did),
    }
    if group_did is not None:
        meta["target"] = {"kind": "group", "did": validate_group_did(group_did)}
    return meta


def _page_body(limit: int, cursor: str | None) -> dict[str, Any]:
    body: dict[str, Any] = {"limit": _limit(limit)}
    if cursor is not None:
        if not cursor or len(cursor) > 4096:
            raise ValueError("cursor must contain 1-4096 characters")
        body["cursor"] = cursor
    return body


def _limit(value: int) -> int:
    if not 1 <= value <= 100:
        raise ValueError("limit must be between 1 and 100")
    return value


class GroupService:
    def __init__(self, client: httpx.AsyncClient, base_url: str) -> None:
        self.client = client
        self.endpoint = base_url.rstrip("/") + "/im/rpc"

    async def capabilities(
        self, identity: AuthenticatedIdentity | UnlockedIdentity
    ) -> GroupCapabilities:
        result = _object(
            await call_json_rpc(
                self.client,
                self.endpoint,
                "anp.get_capabilities",
                build_capabilities(identity.identity.did),
                access_token=identity.session.access_token,
            )
        )
        _require_advertised(result, "supported_profiles", GROUP_PROFILE)
        _require_advertised(result, "supported_security_profiles", TRANSPORT_PROTECTED)
        _require_advertised(result, "supported_content_types", "text/plain")
        service_did = result.get("service_did")
        if not isinstance(service_did, str):
            raise RuntimeError("message service did is unavailable")
        service_did = validate_did(service_did)
        limits = result.get("limits")
        maximum = _optional_positive_int(limits, "max_group_message_bytes")
        features = result.get("features")
        participant = features.get("group_participant") if isinstance(features, dict) else None
        return GroupCapabilities(
            service_did,
            maximum,
            _optional_positive_int(participant, "max_members"),
        )

    async def create(
        self,
        identity: UnlockedIdentity,
        service_did: str,
        display_name: str,
        max_members: int,
        pending: PendingOperation,
    ) -> GroupSummary:
        result = await self._mutate(
            identity,
            "group.create",
            build_group_create(identity, service_did, display_name, max_members, pending),
        )
        return _parse_group_summary(result)

    async def add(
        self,
        identity: UnlockedIdentity,
        group_did: str,
        member_did: str,
        pending: PendingOperation,
    ) -> str:
        group = validate_group_did(group_did)
        member = validate_did(member_did)
        result = await self._mutate(
            identity, "group.add", build_group_add(identity, group, member, pending)
        )
        if result.get("group_did") != group or result.get("member_did") != member:
            raise RuntimeError("service returned mismatched group.add identifiers")
        return member

    async def send_text(
        self,
        identity: UnlockedIdentity,
        group_did: str,
        text: str,
        pending: PendingOperation,
    ) -> GroupMessage:
        group = validate_group_did(group_did)
        result = await self._mutate(
            identity, "group.send", build_group_send_text(identity, group, text, pending)
        )
        if (
            result.get("group_did") != group
            or result.get("message_id") != pending.message_id
            or result.get("operation_id") != pending.operation_id
        ):
            raise RuntimeError("service returned mismatched group.send identifiers")
        return GroupMessage(
            message_id=_required_str(result, "message_id"),
            group_did=group,
            sender_did=identity.identity.did,
            message_type="text",
            content=text,
            content_type="text/plain",
            group_event_seq=_positive_int(result.get("group_event_seq"), "group_event_seq"),
            created_at=_required_str(result, "accepted_at"),
        )

    async def send_attachment(
        self,
        identity: UnlockedIdentity,
        group_did: str,
        attachment: AttachmentRef,
        caption: str | None,
        pending: PendingOperation,
    ) -> GroupMessage:
        group = validate_group_did(group_did)
        result = await self._mutate(
            identity,
            "group.send",
            build_group_send_attachment(identity, group, attachment, caption, pending),
        )
        if (
            result.get("group_did") != group
            or result.get("message_id") != pending.message_id
            or result.get("operation_id") != pending.operation_id
        ):
            raise RuntimeError("service returned mismatched group.send identifiers")
        return GroupMessage(
            message_id=_required_str(result, "message_id"),
            group_did=group,
            sender_did=identity.identity.did,
            message_type="attachment_manifest",
            content=build_manifest(attachment, caption),
            content_type=MANIFEST_CONTENT_TYPE,
            group_event_seq=_positive_int(result.get("group_event_seq"), "group_event_seq"),
            created_at=_required_str(result, "accepted_at"),
        )

    async def list_groups(
        self, identity: AuthenticatedIdentity, limit: int, cursor: str | None = None
    ) -> tuple[list[GroupSummary], str | None]:
        result = await self._read(
            identity, "group.list", build_group_list(identity.identity.did, limit, cursor)
        )
        rows = _list(result, "groups")
        return [
            _parse_group_summary(_object(row)) for row in rows if _is_plain_group(_object(row))
        ], _next_cursor(result)

    async def info(self, identity: AuthenticatedIdentity, group_did: str) -> GroupSummary:
        result = await self._read(
            identity,
            "group.get_info",
            build_group_info(identity.identity.did, group_did),
        )
        if not _is_plain_group(result):
            raise RuntimeError("group does not use the supported transport-protected profile")
        return _parse_group_summary(result)

    async def members(
        self,
        identity: AuthenticatedIdentity,
        group_did: str,
        limit: int,
        cursor: str | None = None,
    ) -> tuple[list[GroupMember], str | None]:
        result = await self._read(
            identity,
            "group.list_members",
            build_group_members(identity.identity.did, group_did, limit, cursor),
        )
        if result.get("group_did") != validate_group_did(group_did):
            raise RuntimeError("service returned mismatched group member identifiers")
        members: list[GroupMember] = []
        for raw in _list(result, "members"):
            row = _object(raw)
            members.append(
                GroupMember(
                    _response_did(row, "agent_did"),
                    _required_str(row, "role"),
                    _required_str(row, "status"),
                )
            )
        return members, _next_cursor(result)

    async def messages(
        self,
        identity: AuthenticatedIdentity,
        group_did: str,
        limit: int,
        since_seq: int | None = None,
    ) -> tuple[list[GroupMessage], int | None]:
        result = await self._read(
            identity,
            "group.list_messages",
            build_group_messages(identity.identity.did, group_did, limit, since_seq),
        )
        messages: list[GroupMessage] = []
        for raw in _list(result, "messages"):
            row = _object(raw)
            if row.get("type") not in {"text", "attachment_manifest"}:
                continue
            if row.get("group_did") != validate_group_did(group_did):
                raise RuntimeError("service returned a message for a different group")
            content = row.get("content")
            if row.get("type") == "attachment_manifest":
                if row.get("content_type") != MANIFEST_CONTENT_TYPE:
                    raise RuntimeError("service returned an invalid attachment projection")
                # Parse now so unsupported multi-file/E2EE manifests never enter local state.
                parse_manifest(content)
            elif row.get("content_type") != "text/plain" or not isinstance(content, str):
                raise RuntimeError("service returned an invalid Group text projection")
            messages.append(
                GroupMessage(
                    message_id=_required_str(row, "message_id"),
                    group_did=_response_did(row, "group_did"),
                    sender_did=_response_did(row, "sender_did"),
                    message_type=_required_str(row, "type"),
                    content=content,
                    content_type=_required_str(row, "content_type"),
                    group_event_seq=_positive_int(row.get("group_event_seq"), "group_event_seq"),
                    created_at=_optional_timestamp(row),
                )
            )
        raw_next = result.get("next_since_seq")
        next_seq = _positive_int(raw_next, "next_since_seq") if raw_next is not None else None
        return messages, next_seq

    async def _mutate(
        self, identity: UnlockedIdentity, method: str, params: dict[str, Any]
    ) -> dict[str, Any]:
        result: Any = None
        for attempt in range(2):
            try:
                result = await call_json_rpc(
                    self.client,
                    self.endpoint,
                    method,
                    params,
                    access_token=identity.session.access_token,
                )
                break
            except httpx.TransportError:
                if attempt == 1:
                    raise
        value = _object(result)
        accepted = value.get("accepted")
        if accepted is not True and (
            accepted is not None
            or method not in {"group.create", "group.add"}
            or value.get("group_receipt") is None
        ):
            raise RuntimeError(f"service returned an invalid {method} result")
        _validate_mutation_result(method, params, value)
        return value

    async def _read(
        self, identity: AuthenticatedIdentity, method: str, params: dict[str, Any]
    ) -> dict[str, Any]:
        return _object(
            await call_json_rpc(
                self.client,
                self.endpoint,
                method,
                params,
                access_token=identity.session.access_token,
            )
        )


def _parse_group_summary(value: dict[str, Any]) -> GroupSummary:
    group_did = _response_did(value, "group_did")
    profile = value.get("group_profile")
    name = value.get("name")
    if isinstance(profile, dict):
        name = profile.get("display_name", name)
    if not isinstance(name, str) or not name:
        raise RuntimeError("service returned a group without a display name")
    state_version = str(_positive_int(value.get("group_state_version"), "group_state_version"))
    member_count = _nonnegative_int(value.get("member_count", 1), "member_count")
    return GroupSummary(
        group_did=group_did,
        display_name=name,
        group_state_version=state_version,
        member_count=member_count,
        my_role=_optional_str(value, "my_role"),
        membership_status=_optional_str(value, "membership_status"),
        updated_at=_optional_str(value, "updated_at"),
    )


def _is_plain_group(value: dict[str, Any]) -> bool:
    required = value.get("required_security_profile")
    if required is not None and required != TRANSPORT_PROTECTED:
        return False
    policy = value.get("group_policy")
    return (
        not isinstance(policy, dict)
        or policy.get("message_security_profile", TRANSPORT_PROTECTED) == TRANSPORT_PROTECTED
    )


def _validate_mutation_result(method: str, params: dict[str, Any], result: dict[str, Any]) -> None:
    meta = _object(params.get("meta"))
    group_did = result.get("group_did")
    if not isinstance(group_did, str) or not group_did:
        raise RuntimeError(f"service returned an invalid {method} group identifier")
    _positive_int(result.get("group_state_version"), "group_state_version")
    _positive_int(result.get("group_event_seq"), "group_event_seq")
    receipt = result.get("group_receipt")
    if receipt is None:
        return
    receipt = _object(receipt)
    if receipt.get("e2ee") is not None:
        raise RuntimeError("ordinary Group receipt contains E2EE material")
    if (
        receipt.get("subject_method") != method
        or receipt.get("group_did") != group_did
        or receipt.get("operation_id") != meta.get("operation_id")
    ):
        raise RuntimeError("service returned a mismatched Group receipt")
    if meta.get("message_id") is not None and receipt.get("message_id") != meta.get("message_id"):
        raise RuntimeError("service returned a mismatched Group message receipt")
    proof = receipt.get("proof")
    if proof is not None and not isinstance(proof, dict):
        raise RuntimeError("service returned an invalid Group receipt proof")


def _require_advertised(result: dict[str, Any], field: str, required: str) -> None:
    advertised = result.get(field)
    if not isinstance(advertised, list) or required not in advertised:
        raise RuntimeError(f"message service does not advertise required {required}")


def _optional_positive_int(value: Any, field: str) -> int | None:
    if not isinstance(value, dict) or value.get(field) is None:
        return None
    return _positive_int(value[field], field)


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        parsed = value
    elif isinstance(value, str) and value.isascii() and value.isdecimal():
        if len(value) > 1 and value.startswith("0"):
            raise ProtocolResponseError(f"service returned invalid {field}")
        parsed = int(value)
    else:
        raise ProtocolResponseError(f"service returned invalid {field}")
    if parsed <= 0:
        raise ProtocolResponseError(f"service returned invalid {field}")
    return parsed


def _next_cursor(value: dict[str, Any]) -> str | None:
    raw_has_more = value.get("has_more")
    if not isinstance(raw_has_more, bool):
        raise ProtocolResponseError("service returned invalid has_more")
    has_more = raw_has_more
    cursor = value.get("next_cursor")
    if has_more and (not isinstance(cursor, str) or not cursor):
        raise RuntimeError("service omitted the next group cursor")
    if not has_more and cursor is not None:
        raise RuntimeError("service returned a cursor for a terminal group page")
    return cursor if isinstance(cursor, str) else None


def _list(value: dict[str, Any], field: str) -> list[Any]:
    result = value.get(field)
    if not isinstance(result, list):
        raise RuntimeError(f"service returned invalid {field}")
    return result


def _object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProtocolResponseError("service returned an invalid Group result")
    return value


def _nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        parsed = value
    elif isinstance(value, str) and value.isascii() and value.isdecimal():
        if len(value) > 1 and value.startswith("0"):
            raise ProtocolResponseError(f"service returned invalid {field}")
        parsed = int(value)
    else:
        raise ProtocolResponseError(f"service returned invalid {field}")
    if parsed < 0:
        raise ProtocolResponseError(f"service returned invalid {field}")
    return parsed


def _required_str(value: dict[str, Any], field: str) -> str:
    result = value.get(field)
    if not isinstance(result, str) or not result:
        raise ProtocolResponseError(f"service returned invalid {field}")
    return result


def _optional_str(value: dict[str, Any], field: str) -> str | None:
    result = value.get(field)
    if result is not None and not isinstance(result, str):
        raise ProtocolResponseError(f"service returned invalid {field}")
    return result


def _optional_timestamp(value: dict[str, Any]) -> str:
    result = value.get("sent_at", value.get("created_at", ""))
    if not isinstance(result, str):
        raise ProtocolResponseError("service returned invalid message timestamp")
    return result


def _response_did(value: dict[str, Any], field: str) -> str:
    try:
        return validate_did(_required_str(value, field))
    except ValueError as exc:
        raise ProtocolResponseError(f"service returned invalid {field}") from exc
