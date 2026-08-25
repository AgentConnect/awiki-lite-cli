import json

import httpx
import pytest

from awiki_lite_cli.domain.models import (
    AuthenticatedIdentity,
    IdentityState,
    SessionState,
    UnlockedIdentity,
)
from awiki_lite_cli.infrastructure.anp_sdk import generate_identity
from awiki_lite_cli.infrastructure.message_service import MessageService


def capabilities() -> dict[str, object]:
    return {
        "service_did": "did:wba:example.test:service:message",
        "supported_profiles": ["anp.direct.base.v1"],
        "supported_security_profiles": ["transport-protected"],
        "supported_content_types": ["text/plain"],
        "proof_policies": {"direct_base_origin_proof": "required"},
    }


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


@pytest.mark.asyncio
async def test_send_validates_standard_acceptance_and_bearer() -> None:
    unlocked, _ = contexts()

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body["method"] == "anp.get_capabilities":
            return httpx.Response(
                200, json={"jsonrpc": "2.0", "id": body["id"], "result": capabilities()}
            )
        meta = body["params"]["meta"]
        assert request.headers["Authorization"] == "Bearer fixture-token"
        result = {
            "accepted": True,
            "message_id": meta["message_id"],
            "operation_id": meta["operation_id"],
            "target_did": meta["target"]["did"],
            "accepted_at": "2026-08-05T00:00:00Z",
        }
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        message = await MessageService(client, "https://example.test").send(
            unlocked, "did:wba:example.test:user:bob:e1_fixture", "hello"
        )
    assert message.text == "hello"


@pytest.mark.asyncio
async def test_inbox_filters_non_plain_and_mark_read_is_explicit() -> None:
    _, identity = contexts()
    methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        methods.append(body["method"])
        if body["method"] == "inbox.get":
            result = {
                "messages": [
                    {
                        "id": "m1",
                        "sender_did": "did:wba:example.test:user:bob",
                        "receiver_did": identity.identity.did,
                        "content": "hello",
                        "content_type": "text/plain",
                        "type": "text",
                        "sent_at": "now",
                        "is_read": False,
                    },
                    {
                        "id": "cipher",
                        "content_type": "application/anp-direct-cipher+json",
                        "type": "json",
                    },
                ],
                "has_more": False,
            }
        else:
            result = {"updated_count": 1}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        service = MessageService(client, "https://example.test")
        messages, _ = await service.inbox(identity, 20)
        assert methods == ["inbox.get"]
        assert [message.message_id for message in messages] == ["m1"]
        assert await service.mark_read(identity, ["m1"]) == 1
    assert methods == ["inbox.get", "inbox.mark_read"]


@pytest.mark.asyncio
async def test_history_delegates_bounded_pagination_to_service() -> None:
    _, identity = contexts()
    pages: list[tuple[int, int]] = []

    def message(message_id: str, sequence: int) -> dict[str, object]:
        return {
            "id": message_id,
            "server_seq": str(sequence),
            "sender_did": "did:wba:example.test:user:bob",
            "receiver_did": identity.identity.did,
            "content": message_id,
            "content_type": "text/plain",
            "sent_at": f"2026-08-20T00:00:0{sequence}Z",
        }

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["method"] == "direct.get_history"
        page = body["params"]["body"]
        pages.append((page["limit"], page["skip"]))
        result = {"messages": [message("m2", 2)], "has_more": True}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        messages, has_more = await MessageService(client, "https://example.test").history(
            identity, "did:wba:example.test:user:bob", limit=1, skip=1
        )
    assert pages == [(1, 1)]
    assert [item.message_id for item in messages] == ["m2"]
    assert has_more is True


@pytest.mark.asyncio
async def test_send_network_retry_reuses_idempotency_ids() -> None:
    unlocked, _ = contexts()
    metas: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body["method"] == "anp.get_capabilities":
            return httpx.Response(
                200, json={"jsonrpc": "2.0", "id": body["id"], "result": capabilities()}
            )
        metas.append(body["params"]["meta"])
        if len(metas) == 1:
            raise httpx.ReadTimeout("unknown result", request=request)
        meta = metas[-1]
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": {
                    "accepted": True,
                    "message_id": meta["message_id"],
                    "operation_id": meta["operation_id"],
                    "target_did": meta["target"]["did"],
                    "accepted_at": "2026-08-05T00:00:00Z",
                },
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await MessageService(client, "https://example.test").send(
            unlocked, "did:wba:example.test:user:bob:e1_fixture", "hello"
        )
    assert metas[0]["message_id"] == metas[1]["message_id"]
    assert metas[0]["operation_id"] == metas[1]["operation_id"]


@pytest.mark.asyncio
async def test_send_fails_closed_when_plain_capability_is_missing() -> None:
    unlocked, _ = contexts()

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        result = capabilities()
        result["supported_content_types"] = ["application/json"]
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(RuntimeError, match="text/plain"):
            await MessageService(client, "https://example.test").send(
                unlocked, "did:wba:example.test:user:bob:e1_fixture", "hello"
            )
