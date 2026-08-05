import json

import httpx
import pytest

from awiki_lite_cli.infrastructure.rpc import JsonRpcFailure, call_json_rpc


@pytest.mark.asyncio
async def test_call_json_rpc_returns_result_and_bearer_token() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer secret-token"
        body = json.loads(request.content)
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": body["id"], "result": {"ok": True}},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await call_json_rpc(
            client,
            "https://example.test/rpc",
            "example.call",
            {},
            access_token="secret-token",
        )

    assert result == {"ok": True}


@pytest.mark.asyncio
async def test_call_json_rpc_preserves_error_data_even_on_401() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        return httpx.Response(
            401,
            json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "error": {
                    "code": 1401,
                    "message": "Unauthorized",
                    "data": {"anp_code": "client.session_unauthorized"},
                },
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(JsonRpcFailure) as caught:
            await call_json_rpc(client, "https://example.test/rpc", "example.call", {})

    assert caught.value.code == 1401
    assert caught.value.data == {"anp_code": "client.session_unauthorized"}
