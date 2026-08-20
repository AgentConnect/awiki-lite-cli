"""Minimal JSON-RPC 2.0 transport shared by service adapters."""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

import httpx

from awiki_lite_cli import CLIENT_IDENTIFIER
from awiki_lite_cli.application.errors import JsonRpcFailure, ProtocolResponseError

__all__ = [
    "JsonRpcFailure",
    "ProtocolResponseError",
    "call_json_rpc",
    "decode_json_rpc_response",
    "encode_json_rpc_request",
]


async def call_json_rpc(
    client: httpx.AsyncClient,
    endpoint: str,
    method: str,
    params: dict[str, Any],
    *,
    access_token: str | None = None,
    client_version: str = CLIENT_IDENTIFIER,
) -> Any:
    """Call one RPC method and preserve service error codes without leaking credentials."""
    headers = {"Content-Type": "application/json", "X-AWiki-Client-Version": client_version}
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    request_id = str(uuid4())
    response = await client.post(
        endpoint,
        headers=headers,
        json={"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
    )
    return decode_json_rpc_response(response, request_id)


def encode_json_rpc_request(request_id: str, method: str, params: dict[str, Any]) -> bytes:
    """Encode the exact bytes used by a signed JSON-RPC request."""
    return json.dumps(
        {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
        separators=(",", ":"),
    ).encode()


def decode_json_rpc_response(response: httpx.Response, request_id: str) -> Any:
    """Validate one response against its request identifier."""
    try:
        payload = response.json()
    except ValueError:
        response.raise_for_status()
        raise RuntimeError("service returned a non-JSON response") from None
    if not isinstance(payload, dict):
        raise ProtocolResponseError("service returned an invalid JSON-RPC response")
    if payload.get("jsonrpc") != "2.0" or payload.get("id") != request_id:
        raise ProtocolResponseError("service returned an invalid JSON-RPC envelope")
    error_value = payload.get("error")
    has_error = error_value is not None
    has_result = "result" in payload
    if has_error and has_result and payload["result"] is not None:
        raise ProtocolResponseError("service returned an ambiguous JSON-RPC response")
    if not has_error and not has_result:
        raise ProtocolResponseError("service returned an ambiguous JSON-RPC response")
    if has_error:
        error = error_value
        if not isinstance(error, dict):
            raise ProtocolResponseError("service returned an invalid JSON-RPC error")
        code = error.get("code")
        message = error.get("message")
        if not isinstance(code, int) or isinstance(code, bool) or not isinstance(message, str):
            raise ProtocolResponseError("service returned an invalid JSON-RPC error")
        raise JsonRpcFailure(
            code=code,
            message=message,
            data=error.get("data"),
        )
    response.raise_for_status()
    return payload["result"]
