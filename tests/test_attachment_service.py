import base64
import hashlib
import json
import os
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from awiki_lite_cli.domain.models import IdentityState
from awiki_lite_cli.infrastructure.anp_sdk import generate_identity
from awiki_lite_cli.infrastructure.attachment_service import (
    ATTACHMENT_PROFILE,
    AttachmentService,
    AttachmentSlot,
    build_create_slot,
    new_created_at,
    prepare_file,
)
from awiki_lite_cli.infrastructure.state import SecureStateStore

SERVICE_DID = "did:wba:message.example.test"
TARGET_DID = "did:wba:example.test:user:bob:e1_fixture"


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
    return store.unlock("long passphrase value")


def digest(raw: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()


def capability_result() -> dict[str, object]:
    return {
        "service_did": SERVICE_DID,
        "supported_profiles": [ATTACHMENT_PROFILE],
        "supported_security_profiles": ["transport-protected"],
        "supported_content_types": ["application/anp-attachment-manifest+json"],
        "limits": {"max_object_bytes": "1024"},
    }


@pytest.mark.asyncio
async def test_plain_attachment_create_upload_commit_exact_contract(tmp_path: Path) -> None:
    identity = unlocked_store(tmp_path)
    raw = b"plain attachment bytes\x00"
    path = tmp_path / "report.pdf"
    path.write_bytes(raw)
    calls: list[tuple[str, dict[str, object]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT":
            assert str(request.url) == "https://objects.example.test/objects/upload/slot-1"
            assert request.headers["x-awiki-upload-token"] == "upload-secret"
            assert request.content == raw
            return httpx.Response(204)
        body = json.loads(request.content)
        calls.append((body["method"], body["params"]))
        if body["method"] == "anp.get_capabilities":
            result: object = capability_result()
        elif body["method"] == "attachment.create_slot":
            result = {
                "attachment_id": "att-1",
                "slot_id": "slot-1",
                "upload_uri": "https://objects.example.test/objects/upload/slot-1",
                "upload_headers": {"X-AWiki-Upload-Token": "upload-secret"},
                "object_uri": "https://objects.example.test/objects/object-1",
                "commit_token": "commit-secret",
                "expires_at": "2099-08-06T00:05:00Z",
            }
        else:
            result = {
                "committed": True,
                "attachment_id": "att-1",
                "object_uri": "https://objects.example.test/objects/object-1",
                "committed_at": "2026-08-06T00:01:00Z",
            }
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=False
    ) as client:
        service = AttachmentService(client, "https://message.example.test")
        capabilities = await service.capabilities(identity)
        with prepare_file(path, capabilities.max_object_bytes) as prepared:
            slot = await service.create_slot(
                identity,
                capabilities.service_did,
                "att-1",
                prepared,
                "agent",
                TARGET_DID,
                "create-op",
                new_created_at(),
            )
            await service.upload(slot, prepared)
            committed = await service.commit(
                identity, SERVICE_DID, slot, prepared, "commit-op", new_created_at()
            )

    create = calls[1][1]
    assert create["meta"]["profile"] == ATTACHMENT_PROFILE  # type: ignore[index]
    assert "auth" not in create
    assert create["body"] == {  # type: ignore[index]
        "attachment_id": "att-1",
        "expected_size": str(len(raw)),
        "expected_digest": {"alg": "sha-256", "value_b64u": digest(raw)},
        "mime_type": "application/pdf",
        "filename": "report.pdf",
        "intended_message_security_profile": "transport-protected",
        "intended_target": {"kind": "agent", "did": TARGET_DID},
        "object_encryption_mode": "none",
    }
    commit = calls[2][1]["body"]  # type: ignore[index]
    assert commit["commit_token"] == "commit-secret"
    assert commit["object_encryption_mode"] == "none"
    assert committed.attachment.sha256_b64u == digest(raw)
    assert "upload-secret" not in repr(slot)
    assert "commit-secret" not in repr(slot)


def test_prepare_file_accepts_empty_and_rejects_unsafe_or_changed_files(tmp_path: Path) -> None:
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    with prepare_file(empty, 0) as prepared:
        assert prepared.size == 0
        empty.write_bytes(b"changed")
        with pytest.raises(RuntimeError, match="changed"):
            prepared.assert_unchanged()

    oversized = tmp_path / "large.bin"
    oversized.write_bytes(b"12")
    with pytest.raises(ValueError, match="size limit"):
        prepare_file(oversized, 1)

    link = tmp_path / "link.bin"
    link.symlink_to(oversized)
    with pytest.raises(ValueError, match="regular file"):
        prepare_file(link, 100)

    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match="regular file"):
        prepare_file(fifo, 100)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("upload_uri", "headers"),
    [
        ("http://objects.example.test/upload", {"X-AWiki-Upload-Token": "secret"}),
        ("https://127.0.0.1/upload", {"X-AWiki-Upload-Token": "secret"}),
        ("https://objects.example.test/upload?secret=x", {"X-AWiki-Upload-Token": "secret"}),
        ("https://objects.example.test/upload", {"Authorization": "secret"}),
        ("https://objects.example.test/upload", {"X-AWiki-Upload-Token": "bad\r\nvalue"}),
    ],
)
async def test_create_slot_rejects_unsafe_data_plane_values(
    tmp_path: Path, upload_uri: str, headers: dict[str, str]
) -> None:
    identity = unlocked_store(tmp_path)
    path = tmp_path / "safe.bin"
    path.write_bytes(b"safe")

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        result = {
            "attachment_id": "att-1",
            "slot_id": "slot-1",
            "upload_uri": upload_uri,
            "upload_headers": headers,
            "object_uri": "https://objects.example.test/object-1",
            "commit_token": "commit-secret",
            "expires_at": "2099-08-06T00:05:00Z",
        }
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with prepare_file(path, 100) as prepared:
            with pytest.raises(RuntimeError):
                await AttachmentService(client, "https://message.example.test").create_slot(
                    identity,
                    SERVICE_DID,
                    "att-1",
                    prepared,
                    "agent",
                    TARGET_DID,
                    str(uuid4()),
                    new_created_at(),
                )


def test_build_create_slot_rejects_e2ee_and_invalid_target(tmp_path: Path) -> None:
    identity = unlocked_store(tmp_path)
    path = tmp_path / "safe.bin"
    path.write_bytes(b"safe")
    with prepare_file(path, 100) as prepared:
        params = build_create_slot(
            identity.identity.did,
            SERVICE_DID,
            "att-1",
            prepared,
            "agent",
            TARGET_DID,
            "op-1",
            new_created_at(),
        )
        assert params["body"]["object_encryption_mode"] == "none"
        assert "object_key_b64u" not in json.dumps(params)
        with pytest.raises(ValueError, match="kind"):
            build_create_slot(
                identity.identity.did,
                SERVICE_DID,
                "att-1",
                prepared,
                "device",
                TARGET_DID,
                "op-1",
                new_created_at(),
            )


@pytest.mark.asyncio
async def test_control_transport_retry_reuses_exact_params(tmp_path: Path) -> None:
    identity = unlocked_store(tmp_path)
    path = tmp_path / "safe.bin"
    path.write_bytes(b"safe")
    seen: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body["params"])
        if len(seen) == 1:
            raise httpx.ReadTimeout("unknown result", request=request)
        result = {
            "attachment_id": "att-1",
            "slot_id": "slot-1",
            "upload_uri": "https://objects.example.test/upload/slot-1",
            "upload_headers": {"X-AWiki-Upload-Token": "upload-secret"},
            "object_uri": "https://objects.example.test/object-1",
            "commit_token": "commit-secret",
            "expires_at": "2099-08-06T00:05:00Z",
        }
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with prepare_file(path, 100) as prepared:
            await AttachmentService(client, "https://message.example.test").create_slot(
                identity,
                SERVICE_DID,
                "att-1",
                prepared,
                "agent",
                TARGET_DID,
                "stable-operation",
                "2026-08-06T00:00:00Z",
            )
    assert seen[0] == seen[1]


@pytest.mark.asyncio
async def test_upload_redirect_and_commit_mismatch_fail_closed(tmp_path: Path) -> None:
    identity = unlocked_store(tmp_path)
    path = tmp_path / "safe.bin"
    path.write_bytes(b"safe")
    methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT":
            return httpx.Response(307, headers={"Location": "https://elsewhere.example/upload"})
        body = json.loads(request.content)
        methods.append(body["method"])
        if body["method"] == "attachment.commit_object":
            result = {
                "committed": True,
                "attachment_id": "different",
                "object_uri": "https://objects.example.test/object-1",
                "committed_at": "2026-08-06T00:01:00Z",
            }
        else:
            result = {
                "aborted": True,
                "attachment_id": "att-1",
                "aborted_at": "2026-08-06T00:02:00Z",
            }
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    slot = AttachmentSlot(
        "att-1",
        "slot-1",
        "https://objects.example.test/upload/slot-1",
        {"x-awiki-upload-token": "upload-secret"},
        "https://objects.example.test/object-1",
        "commit-secret",
        "2099-08-06T00:05:00Z",
    )
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=True
    ) as client:
        service = AttachmentService(client, "https://message.example.test")
        with prepare_file(path, 100) as prepared:
            with pytest.raises(httpx.HTTPStatusError):
                await service.upload(slot, prepared)
            with pytest.raises(RuntimeError, match="mismatched"):
                await service.commit(
                    identity, SERVICE_DID, slot, prepared, "commit-op", new_created_at()
                )
            await service.best_effort_abort(
                identity, SERVICE_DID, slot, "abort-op", new_created_at()
            )
    assert methods == ["attachment.commit_object", "attachment.abort_object"]


@pytest.mark.asyncio
async def test_expired_upload_slot_is_rejected_before_network(tmp_path: Path) -> None:
    path = tmp_path / "safe.bin"
    path.write_bytes(b"safe")

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"unexpected request: {request.url}")

    slot = AttachmentSlot(
        "att-1",
        "slot-1",
        "https://objects.example.test/upload/slot-1",
        {"x-awiki-upload-token": "upload-secret"},
        "https://objects.example.test/object-1",
        "commit-secret",
        "2000-01-01T00:00:00Z",
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with prepare_file(path, 100) as prepared:
            with pytest.raises(RuntimeError, match="expired"):
                await AttachmentService(client, "https://message.example.test").upload(
                    slot, prepared
                )
