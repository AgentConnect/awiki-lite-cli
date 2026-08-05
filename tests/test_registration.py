from pathlib import Path

import httpx
import pytest

from awiki_lite_cli.application.registration import (
    RegistrationWorkflow,
    normalize_handle,
    normalize_phone,
)
from awiki_lite_cli.infrastructure.state import SecureStateStore
from awiki_lite_cli.infrastructure.user_service import UserService


def test_registration_input_normalization() -> None:
    assert normalize_handle(" @Alice ") == "alice"
    assert normalize_phone("+1 5555550100") == "+15555550100"
    with pytest.raises(ValueError):
        normalize_handle("a")


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
                "access_token": "fixture-token",
            }
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        store = SecureStateStore(tmp_path / "state")
        flow = RegistrationWorkflow(
            UserService(client, "https://example.test"), store, "https://example.test"
        )
        handle, phone, domain = await flow.begin("Alice", "+15555550100")
        identity = await flow.finish(handle, phone, domain, "123456", "long passphrase value")

    assert identity.handle == "alice.example.test"
    assert store.unlock("long passphrase value").session.access_token == "fixture-token"
    assert methods[1][1]["full_handle"] == "alice.example.test"
    assert methods[1][1]["purpose"] == "awiki.identity.register.v1"
    assert methods[2][1]["otp_code"] == "123456"
