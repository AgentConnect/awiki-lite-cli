from pathlib import Path

import httpx
import pytest

from awiki_lite_cli.application.registration import (
    RegistrationWorkflow,
    normalize_handle,
    normalize_phone,
)
from awiki_lite_cli.domain.models import AuthenticatedIdentity, SessionState, SyncBootstrapState
from awiki_lite_cli.infrastructure.anp_sdk import generate_identity
from awiki_lite_cli.infrastructure.rpc import JsonRpcFailure
from awiki_lite_cli.infrastructure.state import SecureStateStore
from awiki_lite_cli.infrastructure.user_service import UserService


class FakeSyncService:
    def __init__(self, failure: Exception | None = None) -> None:
        self.client_instance_ids: list[str] = []
        self.failure = failure

    async def bootstrap_sync(self, identity, client_instance_id):  # type: ignore[no-untyped-def]
        self.client_instance_ids.append(client_instance_id)
        if self.failure is not None:
            raise self.failure
        return SyncBootstrapState(
            "fixture-account",
            identity.identity.device_id,
            "2026-08-21T00:00:00Z",
            "1",
            "0",
        )


class AcceptedRegistrationService:
    base_url = "https://example.test"

    def __init__(self) -> None:
        self.register_dids: list[str] = []

    async def register(self, document, handle, phone, otp):  # type: ignore[no-untyped-def]
        did = str(document["id"])
        self.register_dids.append(did)
        return {"state": "registered", "did": did, "access_token": "fixture-token"}


def test_registration_input_normalization() -> None:
    assert normalize_handle(" @Alice ") == "alice"
    assert normalize_phone("+1 5555550100") == "+15555550100"
    with pytest.raises(ValueError):
        normalize_handle("a")


@pytest.mark.asyncio
async def test_open_server_otp_exemption_requires_all_three_fields() -> None:
    def response(request: httpx.Request, data: dict[str, str]) -> httpx.Response:
        body = __import__("json").loads(request.content)
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "error": {"code": -32010, "message": "unavailable", "data": data},
            },
        )

    complete = {
        "feature": "contact_verification",
        "reason": "email_or_phone_verification_is_not_part_of_open_server_mvp",
    }
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: response(request, complete))
    ) as client:
        assert (
            await UserService(client, "https://example.test").send_registration_otp(
                "alice", "example.test", "+15555550100"
            )
            is False
        )

    incomplete = {"feature": "contact_verification"}
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: response(request, incomplete))
    ) as client:
        with pytest.raises(JsonRpcFailure):
            await UserService(client, "https://example.test").send_registration_otp(
                "alice", "example.test", "+15555550100"
            )


@pytest.mark.asyncio
async def test_open_server_can_defer_handle_availability_to_registration() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = __import__("json").loads(request.content)
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "error": {"code": -32601, "message": "method_not_found"},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await UserService(client, "https://example.test").validate_handle(
            "alice", "example.test"
        )
    assert result == {"available": True, "validation_deferred": True}


@pytest.mark.asyncio
async def test_registration_flow_sends_scoped_otp_and_persists(tmp_path: Path) -> None:
    methods: list[tuple[str, dict]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = __import__("json").loads(request.content)
        methods.append((body["method"], body["params"]))
        if body["method"] == "validate":
            result = {"available": True, "handle": "alice"}
        elif body["method"] == "send_otp":
            result = {"ok": True}
        else:
            result = {
                "state": "registered",
                "did": body["params"]["did_document"]["id"],
                "user_id": "fixture-user",
                "full_handle": "alice.example.test",
            }
        headers = {"Authorization": "Bearer fixture-token"} if body["method"] == "register" else {}
        return httpx.Response(
            200,
            headers=headers,
            json={"jsonrpc": "2.0", "id": body["id"], "result": result, "error": None},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        store = SecureStateStore(tmp_path / "state")
        sync = FakeSyncService()
        flow = RegistrationWorkflow(
            UserService(client, "https://example.test"),
            sync,
            store,
            "https://example.test",
            generate_identity,
        )
        handle, phone, domain, otp_required = await flow.begin("Alice", "+15555550100")
        identity = await flow.finish(handle, phone, domain, "123456", "long passphrase value")

    assert identity.handle == "alice.example.test"
    assert otp_required is True
    assert store.unlock("long passphrase value").session.access_token == "fixture-token"
    installation = store.load_sync(identity.did)
    assert installation is not None and installation.bootstrap is not None
    assert sync.client_instance_ids == [installation.client_instance_id]
    assert methods[1][1]["full_handle"] == "alice.example.test"
    assert methods[1][1]["purpose"] == "awiki.identity.register.v1"
    assert methods[2][1]["otp_code"] == "123456"


@pytest.mark.asyncio
async def test_registration_response_loss_reuses_staged_identity(tmp_path: Path) -> None:
    register_dids: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = __import__("json").loads(request.content)
        if body["method"] == "register":
            did = body["params"]["did_document"]["id"]
            register_dids.append(did)
            if len(register_dids) == 1:
                raise httpx.ReadTimeout("response lost", request=request)
            result = {
                "state": "registered",
                "did": did,
                "user_id": "fixture-user",
                "access_token": "fixture-token",
            }
        else:
            result = {"available": True, "ok": True}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        store = SecureStateStore(tmp_path / "state")
        sync = FakeSyncService()
        flow = RegistrationWorkflow(
            UserService(client, "https://example.test"),
            sync,
            store,
            "https://example.test",
            generate_identity,
        )
        with pytest.raises(httpx.ReadTimeout):
            await flow.finish(
                "alice", "+15555550100", "example.test", "123456", "long passphrase value"
            )
        identity = await flow.finish(
            "alice", "+15555550100", "example.test", "654321", "long passphrase value"
        )

    assert register_dids == [identity.did, identity.did]
    assert len(sync.client_instance_ids) == 1
    assert store.exists


@pytest.mark.asyncio
async def test_sync_failure_leaves_registration_recoverable(tmp_path: Path) -> None:
    store = SecureStateStore(tmp_path / "state")
    service = AcceptedRegistrationService()
    sync = FakeSyncService(TimeoutError("sync timeout"))
    flow = RegistrationWorkflow(
        service,
        sync,
        store,
        "https://example.test",
        generate_identity,  # type: ignore[arg-type]
    )

    with pytest.raises(RuntimeError, match="registered locally.*run id init-sync") as caught:
        await flow.finish(
            "alice", "+15555550100", "example.test", "123456", "long passphrase value"
        )

    assert isinstance(caught.value.__cause__, TimeoutError)
    identity = store.load_public()
    session = store.load_session()
    assert service.register_dids == [identity.did]
    assert session.access_token == "fixture-token"
    assert store.load_pending_identity() is None
    installation = store.load_sync(identity.did)
    assert installation is not None and installation.bootstrap is None

    recovery = FakeSyncService()
    bootstrap = await recovery.bootstrap_sync(
        AuthenticatedIdentity(identity, SessionState(session.access_token)),
        installation.client_instance_id,
    )
    completed = store.complete_sync_bootstrap(installation, bootstrap)
    assert completed.bootstrap == bootstrap
    assert recovery.client_instance_ids == sync.client_instance_ids
