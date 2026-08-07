from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from awiki_lite_cli.domain.models import IdentityState
from awiki_lite_cli.infrastructure.anp_sdk import generate_identity
from awiki_lite_cli.infrastructure.state import SecureStateStore
from awiki_lite_cli.infrastructure.user_service import UserService


@pytest.mark.asyncio
async def test_expired_session_refresh_preserves_did_and_private_key(tmp_path: Path) -> None:
    generated = generate_identity("example.test", "alice", "https://message.example.test")
    identity = IdentityState(
        generated.did,
        "alice.example.test",
        generated.device_signing_key_id,
        generated.device_id,
        generated.did_document,
    )
    store = SecureStateStore(tmp_path / "state")
    store.save_registration(
        identity,
        "expired-token",
        {
            "root-key": generated.root_private_key,
            "device-signing": generated.device_signing_private_key,
            "device-agreement": generated.device_agreement_private_key,
        },
        "long passphrase value",
    )
    original_public = store.load_public()
    original_public_key = (
        store.load_device_signing_key("long passphrase value").public_key().public_bytes_raw()
    )

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["method"] == "get_me"
        assert body["params"] == {}
        assert "authorization" not in request.headers
        assert "signature" in request.headers
        assert "signature-input" in request.headers
        assert "content-digest" in request.headers
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": {"did": identity.did, "access_token": "fresh-token"},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        token = await UserService(client, "https://example.test").refresh_session(
            store.load_public(), store.load_device_signing_key("long passphrase value")
        )
    store.save_session(token)

    assert store.load_session().access_token == "fresh-token"
    assert store.load_public() == original_public
    assert (
        store.load_device_signing_key("long passphrase value").public_key().public_bytes_raw()
        == original_public_key
    )
