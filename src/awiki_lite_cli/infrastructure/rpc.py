"""Minimal JSON-RPC 2.0 transport shared by service adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import uuid4

import httpx


@dataclass(frozen=True, slots=True)
class JsonRpcFailure(RuntimeError):
    code: int
    message: str
    data: Any = None

    def __str__(self) -> str:
        # A remote error could reflect credentials or signed payload fields.
        return f"JSON-RPC request failed with code {self.code}"


async def call_json_rpc(
    client: httpx.AsyncClient,
    endpoint: str,
    method: str,
    params: dict[str, Any],
    *,
    access_token: str | None = None,
    client_version: str = "awiki-cli/0714/0.2.0",
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
    try:
        payload = response.json()
    except ValueError:
        response.raise_for_status()
        raise RuntimeError("service returned a non-JSON response") from None
    if isinstance(payload, dict) and isinstance(payload.get("error"), dict):
        error = payload["error"]
        raise JsonRpcFailure(
            code=int(error.get("code", -32603)),
            message=str(error.get("message", "Unknown JSON-RPC error")),
            data=error.get("data"),
        )
    response.raise_for_status()
    if not isinstance(payload, dict) or payload.get("id") != request_id or "result" not in payload:
        raise RuntimeError("service returned an invalid JSON-RPC response")
    return payload["result"]
