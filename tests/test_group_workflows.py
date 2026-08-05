import json
from pathlib import Path

import httpx
import pytest

from awiki_lite_cli.application.groups import GroupWorkflow
from awiki_lite_cli.domain.models import IdentityState
from awiki_lite_cli.infrastructure.anp_sdk import generate_identity
from awiki_lite_cli.infrastructure.group_service import GroupService
from awiki_lite_cli.infrastructure.rpc import JsonRpcFailure
from awiki_lite_cli.infrastructure.state import SecureStateStore

GROUP_DID = "did:wba:groups.example.test:group:fixture:e1_group"
SERVICE_DID = "did:wba:message.example.test"


def unlocked_store(tmp_path: Path):  # type: ignore[no-untyped-def]
    generated = generate_identity("example.test", "alice", "https://example.test")
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
        "fixture-token",
        {
            "root-key": generated.root_private_key,
            "device-signing": generated.device_signing_private_key,
            "device-agreement": generated.device_agreement_private_key,
        },
        "long passphrase value",
    )
    return store, store.unlock("long passphrase value")


def capabilities() -> dict[str, object]:
    return {
        "service_did": SERVICE_DID,
        "supported_profiles": ["anp.group.base.v1"],
        "supported_security_profiles": ["transport-protected"],
        "supported_content_types": ["text/plain"],
        "limits": {"max_group_message_bytes": "1024"},
    }


@pytest.mark.asyncio
async def test_group_send_unknown_result_preserves_exact_retry_state(tmp_path: Path) -> None:
    store, identity = unlocked_store(tmp_path)
    metas: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body["method"] == "anp.get_capabilities":
            return httpx.Response(
                200, json={"jsonrpc": "2.0", "id": body["id"], "result": capabilities()}
            )
        metas.append(body["params"]["meta"])
        raise httpx.ReadTimeout("unknown result", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        workflow = GroupWorkflow(GroupService(client, "https://example.test"), store)
        with pytest.raises(httpx.ReadTimeout):
            await workflow.send(identity, GROUP_DID, "hello")
    assert len(metas) == 2
    assert metas[0] == metas[1]
    raw = json.loads((store.root / "pending-send.json").read_text())
    assert raw["kind"] == "group.send"
    assert "hello" not in json.dumps(raw)


@pytest.mark.asyncio
async def test_group_explicit_rejection_discards_pending_state(tmp_path: Path) -> None:
    store, identity = unlocked_store(tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body["method"] == "anp.get_capabilities":
            result = capabilities()
        else:
            return httpx.Response(
                403,
                json={
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "error": {"code": 3403, "message": "group policy rejected"},
                },
            )
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        workflow = GroupWorkflow(GroupService(client, "https://example.test"), store)
        with pytest.raises(JsonRpcFailure) as caught:
            await workflow.add(identity, GROUP_DID, "did:wba:example.test:user:bob")
    assert caught.value.code == 3403
    assert not (store.root / "pending-send.json").exists()


@pytest.mark.asyncio
async def test_invalid_group_input_does_not_call_network_or_create_pending(tmp_path: Path) -> None:
    store, identity = unlocked_store(tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"unexpected network call: {request.url}")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        workflow = GroupWorkflow(GroupService(client, "https://example.test"), store)
        with pytest.raises(ValueError, match="empty"):
            await workflow.send(identity, GROUP_DID, "   ")
        with pytest.raises(ValueError, match="1-128"):
            await workflow.create(identity, "")
        with pytest.raises(ValueError, match="did:wba"):
            await workflow.add(identity, "not-a-group", "not-a-member")
    assert not (store.root / "pending-send.json").exists()
