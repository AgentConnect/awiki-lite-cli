"""User Service registration RPC adapter."""

from __future__ import annotations

from typing import Any

import httpx

from awiki_lite_cli.infrastructure.rpc import call_json_rpc


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
        result = await call_json_rpc(
            self.client,
            self.base_url + "/user-service/did-auth/rpc",
            "register",
            {
                "did_document": did_document,
                "handle": handle,
                "phone": phone,
                "otp_code": otp_code,
            },
        )
        return _object(result)


def _object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError("service returned an invalid result")
    return value
