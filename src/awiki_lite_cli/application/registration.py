"""Single-identity registration workflow."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from awiki_lite_cli.domain.models import IdentityState
from awiki_lite_cli.infrastructure.anp_sdk import generate_identity
from awiki_lite_cli.infrastructure.state import SecureStateStore, StateError
from awiki_lite_cli.infrastructure.user_service import UserService

HANDLE_RE = re.compile(r"^[a-z][a-z0-9_-]{2,31}$")


def normalize_handle(value: str) -> str:
    handle = value.strip().removeprefix("@").lower()
    if not HANDLE_RE.fullmatch(handle):
        raise ValueError("handle must be 3-32 lowercase letters, digits, '_' or '-'")
    return handle


def normalize_phone(value: str) -> str:
    phone = value.strip().replace(" ", "")
    if not re.fullmatch(r"\+?[0-9]{7,20}", phone):
        raise ValueError("phone must contain 7-20 digits with an optional leading '+'")
    return phone


class RegistrationWorkflow:
    def __init__(self, service: UserService, store: SecureStateStore, message_url: str) -> None:
        self.service = service
        self.store = store
        self.message_url = message_url

    async def begin(self, handle_input: str, phone_input: str) -> tuple[str, str, str]:
        if self.store.exists:
            raise StateError("a local identity already exists")
        handle = normalize_handle(handle_input)
        phone = normalize_phone(phone_input)
        domain = urlparse(self.service.base_url).hostname
        if domain is None:
            raise ValueError("User Service URL has no hostname")
        validation = await self.service.validate_handle(handle, domain)
        if validation.get("available") is not True:
            raise ValueError(str(validation.get("message") or "handle is unavailable"))
        await self.service.send_registration_otp(handle, domain, phone)
        return handle, phone, domain

    async def finish(
        self, handle: str, phone: str, domain: str, otp_code: str, passphrase: str
    ) -> IdentityState:
        if not re.fullmatch(r"[0-9]{4,10}", otp_code.strip()):
            raise ValueError("OTP must contain 4-10 digits")
        generated = generate_identity(domain, handle, self.message_url)
        self.store.save_pending({"did": generated.did, "handle": handle, "domain": domain})
        result = await self.service.register(
            generated.did_document, handle, phone, otp_code.strip()
        )
        if result.get("state") != "registered" or result.get("did") != generated.did:
            raise RuntimeError("registration returned an unexpected identity state")
        token = result.get("access_token")
        if not isinstance(token, str) or not token:
            raise RuntimeError("registration did not return a device access token")
        identity = IdentityState(
            generated.did,
            str(result.get("full_handle") or f"{handle}.{domain}"),
            generated.device_signing_key_id,
            generated.device_id,
            generated.did_document,
        )
        self.store.save_registration(
            identity,
            token,
            {
                "root-key": generated.root_private_key,
                "device-signing": generated.device_signing_private_key,
                "device-agreement": generated.device_agreement_private_key,
            },
            passphrase,
        )
        self.store.clear_pending()
        return identity
