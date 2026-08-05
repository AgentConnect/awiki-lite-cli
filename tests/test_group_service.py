import base64
import hashlib
import json

import httpx
import pytest

from awiki_lite_cli.domain.models import (
    AttachmentRef,
    AuthenticatedIdentity,
    IdentityState,
    PendingOperation,
    SessionState,
    UnlockedIdentity,
)
from awiki_lite_cli.infrastructure.anp_sdk import generate_identity
from awiki_lite_cli.infrastructure.group_service import (
    GroupService,
    build_group_add,
    build_group_create,
    build_group_list,
    build_group_members,
    build_group_messages,
    build_group_send_attachment,
    build_group_send_text,
)

GROUP_DID = "did:wba:groups.example.test:group:fixture:e1_group"
MEMBER_DID = "did:wba:example.test:user:bob:e1_fixture"
SERVICE_DID = "did:wba:message.example.test"


def contexts() -> tuple[UnlockedIdentity, AuthenticatedIdentity]:
    generated = generate_identity("example.test", "alice", "https://example.test")
    public = IdentityState(
        generated.did,
        "alice.example.test",
        generated.device_signing_key_id,
        generated.device_id,
        generated.did_document,
    )
    session = SessionState("fixture-token")
    return (
        UnlockedIdentity(
            public,
            session,
            generated.root_private_key,
            generated.device_signing_private_key,
            generated.device_agreement_private_key,
        ),
        AuthenticatedIdentity(public, session),
    )


def pending(kind: str, target: str, *, message: bool = False) -> PendingOperation:
    return PendingOperation(
        schema_version=2,
        kind=kind,
        target_did=target,
        input_sha256=hashlib.sha256(b"fixture").hexdigest(),
        operation_id=f"operation-{kind}",
        message_id=f"message-{kind}" if message else None,
        created_at="2026-08-06T00:00:00Z",
        proof_created=1785974400,
        proof_nonce=f"nonce-{kind}",
        values={},
    )


def capabilities() -> dict[str, object]:
    return {
        "service_did": SERVICE_DID,
        "supported_profiles": ["anp.group.base.v1", "anp.attachment.v1"],
        "supported_security_profiles": ["transport-protected"],
        "supported_content_types": [
            "text/plain",
            "application/anp-attachment-manifest+json",
        ],
        "limits": {"max_group_message_bytes": "262144"},
    }


def attachment() -> AttachmentRef:
    digest = base64.urlsafe_b64encode(hashlib.sha256(b"payload").digest()).rstrip(b"=").decode()
    return AttachmentRef(
        "att-fixture",
        "https://objects.example.test/object-1",
        "group.txt",
        "text/plain",
        7,
        digest,
    )


def test_group_builders_are_plain_closed_and_deterministic() -> None:
    identity, _ = contexts()
    create_pending = pending("group.create", SERVICE_DID)
    create = build_group_create(identity, SERVICE_DID, "Fixture", create_pending)
    assert create["meta"]["profile"] == "anp.group.base.v1"
    assert create["meta"]["security_profile"] == "transport-protected"
    assert create["meta"]["target"] == {"kind": "service", "did": SERVICE_DID}
    assert create["body"]["group_policy"]["admission_mode"] == "admin-add"
    assert create == build_group_create(identity, SERVICE_DID, "Fixture", create_pending)

    add = build_group_add(identity, GROUP_DID, MEMBER_DID, pending("group.add", GROUP_DID))
    assert add["body"] == {"member_did": MEMBER_DID, "role": "member"}
    send = build_group_send_text(
        identity, GROUP_DID, "hello", pending("group.send", GROUP_DID, message=True)
    )
    assert send["meta"]["content_type"] == "text/plain"
    assert send["body"] == {"text": "hello"}
    assert "e2ee" not in json.dumps({"create": create, "add": add, "send": send}).lower()

    attachment_pending = pending("group.attachment.send", GROUP_DID, message=True)
    attachment_send = build_group_send_attachment(
        identity, GROUP_DID, attachment(), "group file", attachment_pending
    )
    assert attachment_send["meta"]["content_type"] == ("application/anp-attachment-manifest+json")
    assert attachment_send["body"]["payload"]["attachments"][0]["encryption_info"] == {
        "mode": "none"
    }


def test_group_local_builders_preserve_cursor_and_since_seq() -> None:
    did = contexts()[0].identity.did
    assert build_group_list(did, 20, "opaque")["body"] == {
        "limit": 20,
        "cursor": "opaque",
    }
    assert build_group_members(did, GROUP_DID, 10, "member-cursor")["body"] == {
        "group_did": GROUP_DID,
        "limit": 10,
        "cursor": "member-cursor",
    }
    assert build_group_messages(did, GROUP_DID, 30, 12)["body"] == {
        "group_did": GROUP_DID,
        "limit": 30,
        "since_seq": 12,
    }
    with pytest.raises(ValueError, match="negative"):
        build_group_messages(did, GROUP_DID, 20, -1)


@pytest.mark.asyncio
async def test_group_mutations_preflight_and_validate_identifiers() -> None:
    unlocked, authenticated = contexts()
    methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer fixture-token"
        body = json.loads(request.content)
        methods.append(body["method"])
        if body["method"] == "anp.get_capabilities":
            result = capabilities()
        elif body["method"] == "group.create":
            result = {
                "accepted": True,
                "group_did": GROUP_DID,
                "group_state_version": "1",
                "group_event_seq": "1",
                "created_at": "now",
                "creator_did": unlocked.identity.did,
                "group_profile": {"display_name": "Fixture"},
            }
        elif body["method"] == "group.add":
            result = {
                "accepted": True,
                "group_did": GROUP_DID,
                "member_did": MEMBER_DID,
                "membership_status": "active",
                "group_state_version": "2",
                "group_event_seq": "2",
            }
        else:
            meta = body["params"]["meta"]
            result = {
                "accepted": True,
                "group_did": GROUP_DID,
                "message_id": meta["message_id"],
                "operation_id": meta["operation_id"],
                "group_state_version": "2",
                "group_event_seq": "3",
                "accepted_at": "now",
            }
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        service = GroupService(client, "https://example.test")
        caps = await service.capabilities(authenticated)
        created = await service.create(
            unlocked, caps.service_did, "Fixture", pending("group.create", SERVICE_DID)
        )
        assert created.group_did == GROUP_DID
        assert (
            await service.add(unlocked, GROUP_DID, MEMBER_DID, pending("group.add", GROUP_DID))
            == MEMBER_DID
        )
        sent = await service.send_text(
            unlocked, GROUP_DID, "hello", pending("group.send", GROUP_DID, message=True)
        )
        assert sent.group_event_seq == 3
    assert methods == ["anp.get_capabilities", "group.create", "group.add", "group.send"]


@pytest.mark.asyncio
async def test_group_reads_filter_non_plain_messages_and_validate_pages() -> None:
    _, identity = contexts()

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        method = body["method"]
        if method == "group.list":
            result = {
                "groups": [
                    {
                        "group_did": GROUP_DID,
                        "group_state_version": "2",
                        "group_profile": {"display_name": "Fixture"},
                        "member_count": 2,
                        "my_role": "owner",
                    }
                ],
                "total": 1,
                "has_more": True,
                "next_cursor": "next",
            }
        elif method == "group.get_info":
            result = {
                "group_did": GROUP_DID,
                "group_state_version": "2",
                "group_profile": {"display_name": "Fixture"},
                "member_count": 2,
            }
        elif method == "group.list_members":
            result = {
                "group_did": GROUP_DID,
                "group_state_version": "2",
                "members": [
                    {"agent_did": identity.identity.did, "role": "owner", "status": "active"}
                ],
                "total": 1,
                "has_more": False,
            }
        else:
            result = {
                "messages": [
                    {
                        "message_id": "plain",
                        "group_did": GROUP_DID,
                        "sender_did": identity.identity.did,
                        "type": "text",
                        "content": "hello",
                        "content_type": "text/plain",
                        "group_event_seq": "3",
                        "sent_at": "now",
                    },
                    {
                        "message_id": "attachment",
                        "group_did": GROUP_DID,
                        "sender_did": identity.identity.did,
                        "type": "attachment_manifest",
                        "content": build_group_send_attachment(
                            contexts()[0],
                            GROUP_DID,
                            attachment(),
                            None,
                            pending("group.attachment.send", GROUP_DID, message=True),
                        )["body"]["payload"],
                        "content_type": "application/anp-attachment-manifest+json",
                        "group_event_seq": "4",
                        "sent_at": "now",
                    },
                    {
                        "message_id": "cipher",
                        "group_did": GROUP_DID,
                        "sender_did": identity.identity.did,
                        "type": "group_e2ee_cipher",
                        "content": {},
                        "content_type": "application/json",
                        "group_event_seq": "5",
                    },
                ],
                "total": 2,
                "has_more": False,
                "next_since_seq": 5,
            }
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        service = GroupService(client, "https://example.test")
        groups, cursor = await service.list_groups(identity, 20)
        assert groups[0].my_role == "owner" and cursor == "next"
        assert (await service.info(identity, GROUP_DID)).display_name == "Fixture"
        members, _ = await service.members(identity, GROUP_DID, 20)
        assert members[0].role == "owner"
        messages, next_seq = await service.messages(identity, GROUP_DID, 20)
        assert [message.message_id for message in messages] == ["plain", "attachment"]
        assert next_seq == 5


@pytest.mark.asyncio
async def test_group_capability_gate_fails_closed() -> None:
    _, identity = contexts()

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        result = capabilities()
        result["supported_profiles"] = ["anp.group.e2ee.v2"]
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(RuntimeError, match="anp.group.base.v1"):
            await GroupService(client, "https://example.test").capabilities(identity)
