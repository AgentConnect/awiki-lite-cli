import json
from pathlib import Path

import httpx
import pytest

from awiki_lite_cli.commands.direct import _history_with_sync, _inbox_with_sync
from awiki_lite_cli.domain.models import AuthenticatedIdentity, IdentityState
from awiki_lite_cli.infrastructure.anp_sdk import generate_identity
from awiki_lite_cli.infrastructure.message_service import MessageService
from awiki_lite_cli.infrastructure.state import SecureStateStore


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["inbox", "history"])
async def test_legacy_empty_read_bootstraps_once_and_retries(kind: str, tmp_path: Path) -> None:
    generated = generate_identity("example.test", "alice", "https://example.test")
    public = IdentityState(
        generated.did,
        "alice.example.test",
        generated.device_signing_key_id,
        generated.device_id,
        generated.did_document,
    )
    store = SecureStateStore(tmp_path / kind)
    store.save_registration(
        public,
        "fixture-token",
        {
            "root-key": generated.root_private_key,
            "device-signing": generated.device_signing_private_key,
            "device-agreement": generated.device_agreement_private_key,
        },
        "long passphrase value",
    )
    identity = AuthenticatedIdentity(store.load_public(), store.load_session())
    read_method = "inbox.get" if kind == "inbox" else "direct.get_history"
    methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        method = body["method"]
        methods.append(method)
        if method == "sync.bootstrap":
            result = {
                "mode": "tail_only",
                "account_id": "account-1",
                "device_id": public.device_id,
                "server_time": "2026-08-21T00:00:00Z",
                "cursor": {"stream_epoch": "1", "scan_seq": "7"},
                "read_state_baseline": [],
                "group_state_baseline": [],
                "warnings": [],
            }
        elif methods.count(read_method) == 1:
            result = {"messages": [], "has_more": False}
        else:
            result = {
                "messages": [
                    {
                        "id": "message-after-bootstrap",
                        "sender_did": public.did,
                        "receiver_did": public.did,
                        "content": "visible",
                        "content_type": "text/plain",
                        "sent_at": "2026-08-21T00:00:01Z",
                    }
                ],
                "has_more": False,
            }
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        service = MessageService(client, "https://example.test")
        if kind == "inbox":
            page = await _inbox_with_sync(service, store, identity, 10, 0)
            await _inbox_with_sync(service, store, identity, 10, 0)
        else:
            page = await _history_with_sync(service, store, identity, public.did, 10, 0)
            await _history_with_sync(service, store, identity, public.did, 10, 0)

    assert [item.message_id for item in page[0]] == ["message-after-bootstrap"]
    assert methods[:3] == [read_method, "sync.bootstrap", read_method]
    assert methods[3:] == [read_method]
    installation = store.load_sync(public.did)
    assert installation is not None and installation.bootstrap is not None


@pytest.mark.asyncio
async def test_legacy_empty_later_page_does_not_bootstrap(tmp_path: Path) -> None:
    generated = generate_identity("example.test", "alice", "https://example.test")
    public = IdentityState(
        generated.did,
        "alice.example.test",
        generated.device_signing_key_id,
        generated.device_id,
        generated.did_document,
    )
    store = SecureStateStore(tmp_path / "later-page")
    store.save_registration(
        public,
        "fixture-token",
        {
            "root-key": generated.root_private_key,
            "device-signing": generated.device_signing_private_key,
            "device-agreement": generated.device_agreement_private_key,
        },
        "long passphrase value",
    )
    identity = AuthenticatedIdentity(store.load_public(), store.load_session())
    methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        methods.append(body["method"])
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": {"messages": [], "has_more": False},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await _inbox_with_sync(
            MessageService(client, "https://example.test"), store, identity, 10, 10
        )

    assert methods == ["inbox.get"]
    assert store.load_sync(public.did) is None
