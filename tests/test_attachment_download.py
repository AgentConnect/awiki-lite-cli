import base64
import hashlib
import json
import stat
from pathlib import Path

import httpx
import pytest

from awiki_lite_cli.application.attachments import AttachmentWorkflow
from awiki_lite_cli.domain.models import (
    AttachmentContext,
    AttachmentRef,
    AuthenticatedIdentity,
    IdentityState,
)
from awiki_lite_cli.infrastructure.anp_sdk import generate_identity
from awiki_lite_cli.infrastructure.attachment_manifest import normalize_caption
from awiki_lite_cli.infrastructure.attachment_service import (
    AttachmentService,
    DownloadTicket,
    build_download_ticket,
    prepare_download_destination,
    prepare_file,
)
from awiki_lite_cli.infrastructure.group_service import GroupService
from awiki_lite_cli.infrastructure.message_service import MessageService
from awiki_lite_cli.infrastructure.rpc import JsonRpcFailure
from awiki_lite_cli.infrastructure.state import SecureStateStore, StateError

SERVICE_DID = "did:wba:message.example.test"


async def public_dns(_hostname: str, _port: int) -> list[str]:
    return ["93.184.216.34"]


SENDER_DID = "did:wba:sender.example.test:user:alice:e1_fixture"
RECIPIENT_DID = "did:wba:example.test:user:bob:e1_fixture"
GROUP_DID = "did:wba:groups.example.test:group:fixture:e1_group"


def authenticated_store(tmp_path: Path) -> tuple[SecureStateStore, AuthenticatedIdentity]:
    generated = generate_identity("example.test", "bob", "https://example.test")
    state = IdentityState(
        generated.did,
        "bob.example.test",
        generated.device_signing_key_id,
        generated.device_id,
        generated.did_document,
    )
    store = SecureStateStore(tmp_path / "state")
    store.save_registration(
        state,
        "fixture-token",
        {
            "root-key": generated.root_private_key,
            "device-signing": generated.device_signing_private_key,
            "device-agreement": generated.device_agreement_private_key,
        },
        "long passphrase value",
    )
    return store, AuthenticatedIdentity(store.load_public(), store.load_session())


def context(raw: bytes = b"downloaded bytes", *, group: bool = False) -> AttachmentContext:
    digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()
    return AttachmentContext(
        "message-1",
        SENDER_DID,
        None if group else RECIPIENT_DID,
        GROUP_DID if group else None,
        AttachmentRef(
            "att-1",
            "https://objects.example.test/object-1",
            "download.txt",
            "text/plain",
            len(raw),
            digest,
        ),
    )


def workflow(client: httpx.AsyncClient, store: SecureStateStore, resolver) -> AttachmentWorkflow:  # type: ignore[no-untyped-def]
    return AttachmentWorkflow(
        AttachmentService(
            client,
            "https://message.example.test",
            resolver,
            address_resolver=public_dns,
        ),
        MessageService(client, "https://message.example.test"),
        GroupService(client, "https://message.example.test"),
        store,
        normalize_caption,
        prepare_file,
        prepare_download_destination,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("group", [False, True])
async def test_direct_and_group_download_ticket_and_verified_atomic_publish(
    tmp_path: Path, group: bool
) -> None:
    raw = b"downloaded bytes"
    store, identity = authenticated_store(tmp_path)
    stored = context(raw, group=group)
    store.save_attachment_contexts([stored])
    output = tmp_path / "output"
    output.mkdir()
    ticket_value = "ticket-secret-value"
    seen_target: str | None = None

    async def resolver(sender_did: str) -> str:
        assert sender_did == SENDER_DID
        return SERVICE_DID

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal seen_target
        if request.method == "GET":
            assert request.headers["Authorization"] == f"Bearer {ticket_value}"
            return httpx.Response(200, content=raw, headers={"Content-Type": "text/plain"})
        request_body = json.loads(request.content)
        params = request_body["params"]
        seen_target = params["meta"]["target"]["did"]
        assert params["body"]["requester_did"] == identity.identity.did
        assert params["body"]["message_security_profile"] == "transport-protected"
        if group:
            assert params["body"]["group_did"] == GROUP_DID
            assert "message_target_did" not in params["body"]
        else:
            assert params["body"]["message_target_did"] == RECIPIENT_DID
            assert "group_did" not in params["body"]
        binding = {key: value for key, value in params["body"].items() if key != "one_time"}
        result = {
            "download_ticket_b64u": ticket_value,
            "expires_at": "2099-01-01T00:00:00Z",
            "ticket_binding": binding,
        }
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": request_body["id"], "result": result},
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=True
    ) as client:
        published = await workflow(client, store, resolver).download(
            identity, "message-1", "att-1", output
        )
    assert published == output / "download.txt"
    assert published.read_bytes() == raw
    assert stat.S_IMODE(published.stat().st_mode) == 0o600
    assert list(output.iterdir()) == [published]
    assert seen_target == SERVICE_DID
    assert ticket_value not in repr(DownloadTicket(ticket_value, "2099-01-01T00:00:00Z"))
    assert ticket_value not in json.dumps(
        json.loads((store.root / "attachment-contexts.json").read_text())
    )


@pytest.mark.asyncio
async def test_integrity_failure_and_redirect_leave_no_partial_file(tmp_path: Path) -> None:
    store, identity = authenticated_store(tmp_path)
    store.save_attachment_contexts([context(b"expected")])
    output = tmp_path / "output"
    output.mkdir()
    gets = 0

    async def resolver(_sender_did: str) -> str:
        return SERVICE_DID

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal gets
        if request.method == "GET":
            gets += 1
            if gets == 1:
                return httpx.Response(200, content=b"bad-data")
            return httpx.Response(307, headers={"Location": "https://elsewhere.example/object"})
        request_body = json.loads(request.content)
        params = request_body["params"]
        binding = {key: value for key, value in params["body"].items() if key != "one_time"}
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": request_body["id"],
                "result": {
                    "download_ticket_b64u": f"ticket-{gets}",
                    "expires_at": "2099-01-01T00:00:00Z",
                    "ticket_binding": binding,
                },
            },
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=True
    ) as client:
        current = workflow(client, store, resolver)
        with pytest.raises(RuntimeError, match="integrity|size"):
            await current.download(identity, "message-1", "att-1", output)
        assert not list(output.iterdir())
        with pytest.raises(httpx.HTTPStatusError):
            await current.download(identity, "message-1", "att-1", output)
    assert not list(output.iterdir())


@pytest.mark.asyncio
async def test_missing_context_existing_output_and_symlink_directory_fail_before_network(
    tmp_path: Path,
) -> None:
    store, identity = authenticated_store(tmp_path)
    output = tmp_path / "output"
    output.mkdir()
    stored = context()
    store.save_attachment_contexts([stored])

    async def resolver(_sender_did: str) -> str:
        raise AssertionError("resolver must not run")

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"unexpected request: {request.url}")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        current = workflow(client, store, resolver)
        with pytest.raises(StateError, match="refresh"):
            await current.download(identity, "missing", "att-1", output)
        (output / "download.txt").write_bytes(b"existing")
        with pytest.raises(ValueError, match="already exists"):
            await current.download(identity, "message-1", "att-1", output)
        (output / "download.txt").unlink()
        linked = tmp_path / "linked"
        linked.symlink_to(output, target_is_directory=True)
        with pytest.raises(ValueError, match="symlink"):
            await current.download(identity, "message-1", "att-1", linked)


@pytest.mark.asyncio
async def test_unsafe_object_uri_and_ticket_binding_mismatch_fail_closed(tmp_path: Path) -> None:
    store, identity = authenticated_store(tmp_path)
    unsafe = context()
    unsafe = AttachmentContext(
        unsafe.message_id,
        unsafe.sender_did,
        unsafe.message_target_did,
        unsafe.group_did,
        AttachmentRef(
            unsafe.attachment.attachment_id,
            "https://127.0.0.1/object",
            unsafe.attachment.filename,
            unsafe.attachment.mime_type,
            unsafe.attachment.size,
            unsafe.attachment.sha256_b64u,
        ),
    )
    store.save_attachment_contexts([unsafe])
    output = tmp_path / "output"
    output.mkdir()
    resolutions = 0

    async def resolver(_sender_did: str) -> str:
        nonlocal resolutions
        resolutions += 1
        return SERVICE_DID

    def no_network(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"unexpected request: {request.url}")

    async with httpx.AsyncClient(transport=httpx.MockTransport(no_network)) as client:
        with pytest.raises(RuntimeError, match="unsafe"):
            await workflow(client, store, resolver).download(identity, "message-1", "att-1", output)
    assert resolutions == 0

    safe = context()
    store.save_attachment_contexts([safe])

    def mismatched(request: httpx.Request) -> httpx.Response:
        request_body = json.loads(request.content)
        params = request_body["params"]
        binding = {key: value for key, value in params["body"].items() if key != "one_time"}
        binding["message_id"] = "different"
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": request_body["id"],
                "result": {
                    "download_ticket_b64u": "ticket-secret",
                    "expires_at": "2099-01-01T00:00:00Z",
                    "ticket_binding": binding,
                },
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(mismatched)) as client:
        with pytest.raises(RuntimeError, match="mismatched"):
            await workflow(client, store, resolver).download(identity, "message-1", "att-1", output)
    assert not list(output.iterdir())


def test_download_ticket_builder_is_closed_and_context_bound() -> None:
    direct = build_download_ticket(
        RECIPIENT_DID,
        SERVICE_DID,
        context(),
        "operation-1",
        "2026-08-06T00:00:00Z",
    )
    assert direct["meta"]["profile"] == "anp.attachment.v1"
    assert direct["meta"]["target"] == {"kind": "service", "did": SERVICE_DID}
    assert direct["body"]["message_target_did"] == RECIPIENT_DID
    assert "group_did" not in direct["body"]
    assert direct["body"]["one_time"] is True
    assert "auth" not in direct


@pytest.mark.asyncio
async def test_ticket_denial_and_publish_race_do_not_create_or_overwrite_files(
    tmp_path: Path,
) -> None:
    raw = b"downloaded bytes"
    store, identity = authenticated_store(tmp_path)
    store.save_attachment_contexts([context(raw)])
    output = tmp_path / "output"
    output.mkdir()

    async def resolver(_sender_did: str) -> str:
        return SERVICE_DID

    def denied(request: httpx.Request) -> httpx.Response:
        request_body = json.loads(request.content)
        return httpx.Response(
            403,
            json={
                "jsonrpc": "2.0",
                "id": request_body["id"],
                "error": {"code": 6006, "message": "requester is not authorized"},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(denied)) as client:
        with pytest.raises(JsonRpcFailure) as caught:
            await workflow(client, store, resolver).download(identity, "message-1", "att-1", output)
    assert caught.value.code == 6006
    assert not list(output.iterdir())

    def raced(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            (output / "download.txt").write_bytes(b"racing writer")
            return httpx.Response(200, content=raw)
        request_body = json.loads(request.content)
        params = request_body["params"]
        binding = {key: value for key, value in params["body"].items() if key != "one_time"}
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": request_body["id"],
                "result": {
                    "download_ticket_b64u": "ticket-secret",
                    "expires_at": "2099-01-01T00:00:00Z",
                    "ticket_binding": binding,
                },
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(raced)) as client:
        with pytest.raises(ValueError, match="already exists"):
            await workflow(client, store, resolver).download(identity, "message-1", "att-1", output)
    assert (output / "download.txt").read_bytes() == b"racing writer"
    assert list(output.iterdir()) == [output / "download.txt"]
