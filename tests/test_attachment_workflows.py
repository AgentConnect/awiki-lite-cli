import json
from pathlib import Path

import httpx
import pytest

from awiki_lite_cli.application.attachments import AttachmentWorkflow
from awiki_lite_cli.domain.models import IdentityState
from awiki_lite_cli.infrastructure.anp_sdk import generate_identity
from awiki_lite_cli.infrastructure.attachment_service import AttachmentService
from awiki_lite_cli.infrastructure.group_service import GroupService
from awiki_lite_cli.infrastructure.message_service import MessageService
from awiki_lite_cli.infrastructure.state import SecureStateStore

SERVICE_DID = "did:wba:message.example.test"
RECIPIENT_DID = "did:wba:example.test:user:bob:e1_fixture"
GROUP_DID = "did:wba:groups.example.test:group:fixture:e1_group"


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
        "supported_profiles": ["anp.attachment.v1", "anp.direct.base.v1", "anp.group.base.v1"],
        "supported_security_profiles": ["transport-protected"],
        "supported_content_types": [
            "text/plain",
            "application/anp-attachment-manifest+json",
        ],
        "proof_policies": {"direct_base_origin_proof": "required"},
        "limits": {"max_object_bytes": "1024", "max_group_message_bytes": "1024"},
    }


def workflow(client: httpx.AsyncClient, store: SecureStateStore) -> AttachmentWorkflow:
    return AttachmentWorkflow(
        AttachmentService(client, "https://message.example.test"),
        MessageService(client, "https://message.example.test"),
        GroupService(client, "https://message.example.test"),
        store,
    )


@pytest.mark.asyncio
async def test_direct_attachment_unknown_send_resumes_committed_stage_without_reupload(
    tmp_path: Path,
) -> None:
    store, identity = unlocked_store(tmp_path)
    file = tmp_path / "hello.txt"
    file.write_bytes(b"hello attachment")
    puts = 0
    sends = 0
    create_params: list[dict] = []
    commit_params: list[dict] = []
    send_params: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal puts, sends
        if request.method == "PUT":
            puts += 1
            assert request.content == b"hello attachment"
            return httpx.Response(204)
        body = json.loads(request.content)
        method = body["method"]
        if method == "anp.get_capabilities":
            result: object = capabilities()
        elif method == "attachment.create_slot":
            create_params.append(body["params"])
            result = {
                "attachment_id": body["params"]["body"]["attachment_id"],
                "slot_id": "slot-1",
                "upload_uri": "https://objects.example.test/upload/slot-1",
                "upload_headers": {"X-AWiki-Upload-Token": "upload-secret"},
                "object_uri": "https://objects.example.test/object-1",
                "commit_token": "commit-secret",
                "expires_at": "2099-01-01T00:00:00Z",
            }
        elif method == "attachment.commit_object":
            commit_params.append(body["params"])
            result = {
                "committed": True,
                "attachment_id": body["params"]["body"]["attachment_id"],
                "object_uri": "https://objects.example.test/object-1",
                "committed_at": "2026-08-06T00:00:00Z",
            }
        else:
            sends += 1
            send_params.append(body["params"])
            if sends <= 2:
                raise httpx.ReadTimeout("unknown direct result", request=request)
            meta = body["params"]["meta"]
            result = {
                "accepted": True,
                "message_id": meta["message_id"],
                "operation_id": meta["operation_id"],
                "target_did": RECIPIENT_DID,
                "accepted_at": "2026-08-06T00:00:01Z",
            }
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(httpx.ReadTimeout):
            await workflow(client, store).send(
                identity,
                file,
                recipient_did=RECIPIENT_DID,
                group_did=None,
                caption="hello",
            )
        raw = json.loads((store.root / "pending-send.json").read_text())
        assert raw["stage"] == "committed"
        assert "upload-secret" not in json.dumps(raw)
        assert "commit-secret" not in json.dumps(raw)
        message_id, attachment_id = await workflow(client, store).send(
            identity,
            file,
            recipient_did=RECIPIENT_DID,
            group_did=None,
            caption="hello",
        )

    assert puts == 1
    assert create_params[0] == create_params[1]
    assert commit_params[0] == commit_params[1]
    assert send_params[0] == send_params[1] == send_params[2]
    assert message_id == send_params[0]["meta"]["message_id"]
    assert attachment_id.startswith("att-")
    assert not (store.root / "pending-send.json").exists()


@pytest.mark.asyncio
async def test_attachment_target_validation_precedes_network_and_pending(tmp_path: Path) -> None:
    store, identity = unlocked_store(tmp_path)
    file = tmp_path / "hello.txt"
    file.write_bytes(b"hello")

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"unexpected network call: {request.url}")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match="exactly one"):
            await workflow(client, store).send(
                identity,
                file,
                recipient_did=RECIPIENT_DID,
                group_did="did:wba:groups.example.test:group:fixture",
                caption=None,
            )
    assert not (store.root / "pending-send.json").exists()


@pytest.mark.asyncio
async def test_group_attachment_runs_plain_upload_commit_and_manifest_send(tmp_path: Path) -> None:
    store, identity = unlocked_store(tmp_path)
    file = tmp_path / "group.bin"
    file.write_bytes(b"group attachment")
    sent_payload: dict | None = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal sent_payload
        if request.method == "PUT":
            assert request.content == b"group attachment"
            return httpx.Response(204)
        body = json.loads(request.content)
        method = body["method"]
        if method == "anp.get_capabilities":
            result: object = capabilities()
        elif method == "attachment.create_slot":
            result = {
                "attachment_id": body["params"]["body"]["attachment_id"],
                "slot_id": "slot-group",
                "upload_uri": "https://objects.example.test/upload/slot-group",
                "upload_headers": {"X-AWiki-Upload-Token": "upload-secret"},
                "object_uri": "https://objects.example.test/object-group",
                "commit_token": "commit-secret",
                "expires_at": "2099-01-01T00:00:00Z",
            }
        elif method == "attachment.commit_object":
            result = {
                "committed": True,
                "attachment_id": body["params"]["body"]["attachment_id"],
                "object_uri": "https://objects.example.test/object-group",
                "committed_at": "2026-08-06T00:00:00Z",
            }
        else:
            sent_payload = body["params"]
            meta = sent_payload["meta"]
            result = {
                "accepted": True,
                "group_did": GROUP_DID,
                "message_id": meta["message_id"],
                "operation_id": meta["operation_id"],
                "group_state_version": "2",
                "group_event_seq": "3",
                "accepted_at": "2026-08-06T00:00:01Z",
            }
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        message_id, attachment_id = await workflow(client, store).send(
            identity,
            file,
            recipient_did=None,
            group_did=GROUP_DID,
            caption=None,
        )
    assert sent_payload is not None
    assert sent_payload["meta"]["profile"] == "anp.group.base.v1"
    assert sent_payload["meta"]["security_profile"] == "transport-protected"
    assert sent_payload["meta"]["content_type"] == ("application/anp-attachment-manifest+json")
    manifest = sent_payload["body"]["payload"]
    assert len(manifest["attachments"]) == 1
    assert manifest["attachments"][0]["attachment_id"] == attachment_id
    assert manifest["attachments"][0]["encryption_info"] == {"mode": "none"}
    assert message_id == sent_payload["meta"]["message_id"]
    assert not (store.root / "pending-send.json").exists()
