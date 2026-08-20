"""User Service registration RPC adapter."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import httpx
from anp.authentication import generate_http_signature_headers  # type: ignore[import-untyped]

from awiki_lite_cli import CLIENT_IDENTIFIER
from awiki_lite_cli.domain.models import IdentityState
from awiki_lite_cli.infrastructure.rpc import (
    call_json_rpc,
    decode_json_rpc_response,
    encode_json_rpc_request,
)


class UserService:
    def __init__(self, client: httpx.AsyncClient, base_url: str) -> None:
        self.client = client
        self.base_url = base_url.rstrip("/")

    async def validate_handle(self, handle: str, domain: str) -> dict[str, Any]:
        result = await call_json_rpc(
            self.client,
            self.base_url + "/user-service/handle/rpc",
            "validate",
            {"handle": handle, "domain": domain},
        )
        return _object(result)

    async def send_registration_otp(self, handle: str, domain: str, phone: str) -> None:
        await call_json_rpc(
            self.client,
            self.base_url + "/user-service/handle/rpc",
            "send_otp",
            {
                "phone": phone,
                "purpose": "awiki.identity.register.v1",
                "handle": handle,
                "domain": domain,
                "full_handle": f"{handle}.{domain}",
            },
        )

    async def register(
        self, did_document: dict[str, Any], handle: str, phone: str, otp_code: str
    ) -> dict[str, Any]:
        endpoint = self.base_url + "/user-service/did-auth/rpc"
        request_id = str(uuid4())
        response = await self.client.post(
            endpoint,
            headers={
                "Content-Type": "application/json",
                "X-AWiki-Client-Version": CLIENT_IDENTIFIER,
            },
            json={
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "register",
                "params": {
                    "did_document": did_document,
                    "handle": handle,
                    "phone": phone,
                    "otp_code": otp_code,
                },
            },
        )
        result = _object(decode_json_rpc_response(response, request_id))
        token = _bearer_token(response.headers.get("Authorization"))
        if token and not result.get("access_token"):
            result = {**result, "access_token": token}
        return result

    async def refresh_session(self, identity: IdentityState, signing_key: Any) -> str:
        """Obtain a bearer token with DID HTTP signatures, not the old bearer token."""
        endpoint = self.base_url + "/user-service/did-auth/rpc"
        request_id = str(uuid4())
        body = encode_json_rpc_request(request_id, "get_me", {})
        headers = {
            "Content-Type": "application/json",
            "X-AWiki-Client-Version": CLIENT_IDENTIFIER,
        }

        def sign(payload: bytes, _algorithm: str) -> bytes:
            return bytes(signing_key.sign(payload))

        headers.update(
            generate_http_signature_headers(
                identity.did_document,
                endpoint,
                "POST",
                sign,
                headers=headers,
                body=body,
                keyid=identity.verification_method,
            )
        )
        response = await self.client.post(endpoint, headers=headers, content=body)
        result = _object(decode_json_rpc_response(response, request_id))
        token = result.get("access_token") or _bearer_token(response.headers.get("Authorization"))
        if not isinstance(token, str) or not token.strip():
            raise RuntimeError("DID authentication returned no access token")
        if result.get("did") is not None and result.get("did") != identity.did:
            raise RuntimeError("DID authentication returned a mismatched identity")
        return token


def _object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError("service returned an invalid result")
    return value


def _bearer_token(value: str | None) -> str | None:
    if value is None or not value.lower().startswith("bearer "):
        return None
    token = value[7:].strip()
    return token or None
