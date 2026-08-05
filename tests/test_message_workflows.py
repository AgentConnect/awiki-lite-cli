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
                "total": 2,
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
