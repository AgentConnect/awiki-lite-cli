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
from awiki_lite_cli.infrastructure.message_service import (
    MessageService,
    build_capabilities,
    build_direct_attachment_send,
    build_direct_send,
    build_mark_read,
    build_sync_delta,
    build_sync_thread_after,
)
from awiki_lite_cli.infrastructure.rpc import ProtocolResponseError


def unlocked() -> UnlockedIdentity:
    generated = generate_identity("example.test", "alice", "https://example.test")
    identity = IdentityState(
        generated.did,
        "alice.example.test",
        generated.device_signing_key_id,
        generated.device_id,
        generated.did_document,
    )
    return UnlockedIdentity(
        identity,
        SessionState("token"),
        generated.root_private_key,
        generated.device_signing_private_key,
        generated.device_agreement_private_key,
    )


def test_direct_builder_is_closed_plain_profile() -> None:
    params = build_direct_send(
        unlocked(),
        "did:wba:example.test:user:bob:e1_fixture",
        "hello",
        operation_id="op",
        message_id="msg",
    )
    assert params["meta"]["profile"] == "anp.direct.base.v1"
    assert params["meta"]["security_profile"] == "transport-protected"
    assert params["meta"]["content_type"] == "text/plain"
    assert params["body"] == {"text": "hello"}
    assert params["auth"]["scheme"] == "anp-rfc9421-origin-proof-v1"


def test_direct_builder_can_rebuild_identical_idempotent_payload() -> None:
    options = {
        "operation_id": "op",
        "message_id": "msg",
        "created_at": "2026-08-06T00:00:00Z",
        "proof_created": 1785974400,
        "proof_nonce": "stable-nonce",
    }
    identity = unlocked()
    first = build_direct_send(
        identity, "did:wba:example.test:user:bob:e1_fixture", "hello", **options
    )
    second = build_direct_send(
        identity, "did:wba:example.test:user:bob:e1_fixture", "hello", **options
    )
    assert first == second


def test_direct_builder_rejects_invalid_inputs() -> None:
    with pytest.raises(ValueError, match="exact"):
        build_direct_send(unlocked(), "@bob", "hello")
    with pytest.raises(ValueError, match="empty"):
        build_direct_send(unlocked(), "did:wba:example.test:user:bob", "   ")


def test_read_builders_use_local_profiles_without_auth() -> None:
    did = "did:wba:example.test:user:alice:e1_fixture"
    assert build_mark_read(did, ["m1"])["body"]["message_ids"] == ["m1"]
    delta = build_sync_delta(did, "0")
    assert delta["meta"]["profile"] == "anp.sync.local.v1"
    assert delta["body"]["since_event_seq"] == "0"
    thread = build_sync_thread_after(did, "did:wba:example.test:user:bob:e1_fixture", "42")
    assert thread["meta"]["profile"] == "anp.sync.local.v1"
    assert thread["body"]["thread"] == {
        "kind": "direct",
        "peer_did": "did:wba:example.test:user:bob:e1_fixture",
    }
    assert thread["body"]["after_server_seq"] == "42"
    assert "auth" not in delta
    capabilities = build_capabilities(did)
    assert capabilities["meta"]["profile"] == "anp.core.binding.v1"
    assert capabilities["meta"]["sender_did"] == did
    assert capabilities["body"] == {}


def attachment() -> AttachmentRef:
    digest = base64.urlsafe_b64encode(hashlib.sha256(b"payload").digest()).rstrip(b"=").decode()
    return AttachmentRef(
        "att-fixture",
        "https://objects.example.test/object-1",
        "report.pdf",
        "application/pdf",
        7,
        digest,
    )


def test_direct_attachment_builder_is_single_plain_manifest_with_stable_proof() -> None:
    identity = unlocked()
    pending = PendingOperation(
        2,
        "direct.attachment.send",
        "did:wba:example.test:user:bob:e1_fixture",
        "a" * 64,
        "op",
        "msg",
        "2026-08-06T00:00:00Z",
        1785974400,
        "stable-nonce",
        {},
        "committed",
    )
    first = build_direct_attachment_send(
        identity, pending.target_did, attachment(), "report", pending
    )
    second = build_direct_attachment_send(
        identity, pending.target_did, attachment(), "report", pending
    )
    assert first == second
    assert first["meta"]["content_type"] == "application/anp-attachment-manifest+json"
    assert first["body"]["payload"]["attachments"] == [
        {
            "attachment_id": "att-fixture",
            "filename": "report.pdf",
            "mime_type": "application/pdf",
            "size": "7",
            "digest": {"alg": "sha-256", "value_b64u": attachment().sha256_b64u},
            "access_info": {"object_uri": "https://objects.example.test/object-1"},
            "encryption_info": {"mode": "none"},
        }
    ]


@pytest.mark.asyncio
async def test_direct_inbox_projects_valid_plain_attachment() -> None:
    public = unlocked()
    authenticated = AuthenticatedIdentity(public.identity, public.session)
    manifest = build_direct_attachment_send(
        public,
        "did:wba:example.test:user:bob:e1_fixture",
        attachment(),
        "report",
        PendingOperation(
            2,
            "direct.attachment.send",
            "did:wba:example.test:user:bob:e1_fixture",
            "a" * 64,
            "op",
            "msg",
            "2026-08-06T00:00:00Z",
            1785974400,
            "nonce",
            {},
            "committed",
        ),
    )["body"]["payload"]

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body["method"] == "sync.delta":
            result = {
                "events": [
                    {
                        "payload": {
                            "thread": {
                                "kind": "direct",
                                "peer_did": "did:wba:example.test:user:bob:e1_fixture",
                            }
                        }
                    }
                ],
                "has_more": False,
                "snapshot_required": False,
            }
        else:
            assert body["method"] == "sync.thread_after"
            result = {
                "messages": [
                    {
                        "id": "msg",
                        "sender_did": "did:wba:example.test:user:bob:e1_fixture",
                        "receiver_did": public.identity.did,
                        "content_type": "application/anp-attachment-manifest+json",
                        "content": manifest,
                        "sent_at": "now",
                        "is_read": False,
                    }
                ],
                "next_after_server_seq": "1",
                "has_more": False,
            }
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        messages, _ = await MessageService(client, "https://example.test").inbox(authenticated, 20)
    assert messages[0].attachments == (attachment(),)
    assert messages[0].caption == "report"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "message,has_more",
    [
        (
            {
                "sender_did": "did:wba:example.test:user:alice",
                "receiver_did": "did:wba:example.test:user:bob",
                "type": "text",
                "content_type": "text/plain",
                "content": "missing id",
            },
            False,
        ),
        (
            {
                "id": "msg",
                "sender_did": "did:wba:example.test:user:alice",
                "receiver_did": "did:wba:example.test:user:bob",
                "type": "text",
                "content_type": "text/plain",
                "content": {"not": "text"},
                "is_read": "false",
            },
            "false",
        ),
    ],
)
async def test_direct_inbox_rejects_malformed_remote_shapes(message, has_more) -> None:  # type: ignore[no-untyped-def]
    identity = unlocked()

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body["method"] == "sync.delta":
            result = {
                "events": [
                    {
                        "payload": {
                            "thread": {
                                "kind": "direct",
                                "peer_did": "did:wba:example.test:user:bob:e1_fixture",
                            }
                        }
                    }
                ],
                "has_more": False,
            }
        else:
            result = {
                "messages": [message],
                "has_more": has_more,
                "next_after_server_seq": "1",
            }
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": result,
            },
        )

    authenticated = AuthenticatedIdentity(identity.identity, identity.session)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ProtocolResponseError):
            await MessageService(client, "https://example.test").inbox(authenticated, 20)
