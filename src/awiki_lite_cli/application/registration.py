"""Single-identity registration workflow."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from awiki_lite_cli.application.ports import RegistrationServicePort, StateStorePort
from awiki_lite_cli.domain.models import IdentityState

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
    def __init__(
        self,
        service: RegistrationServicePort,
        store: StateStorePort,
        message_url: str,
        identity_generator: Callable[[str, str, str], Any],
    ) -> None:
        self.service = service
        self.store = store
        self.message_url = message_url
        self.identity_generator = identity_generator

    async def begin(self, handle_input: str, phone_input: str) -> tuple[str, str, str]:
        if self.store.exists:
            raise RuntimeError("a local identity already exists")
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
        expected_handle = f"{handle}.{domain}"
        pending = self.store.load_pending_identity()
        if pending is not None and pending.handle == expected_handle:
            identity = pending
            self.store.unlock_pending_keys(passphrase)
        else:
            generated = self.identity_generator(domain, handle, self.message_url)
            identity = IdentityState(
                generated.did,
                expected_handle,
                generated.device_signing_key_id,
                generated.device_id,
                generated.did_document,
            )
            self.store.stage_registration(
                identity,
                {
                    "root-key": generated.root_private_key,
                    "device-signing": generated.device_signing_private_key,
                    "device-agreement": generated.device_agreement_private_key,
                },
                passphrase,
            )
        result = await self.service.register(identity.did_document, handle, phone, otp_code.strip())
        if result.get("state") != "registered" or result.get("did") != identity.did:
            raise RuntimeError("registration returned an unexpected identity state")
        token = result.get("access_token")
        if not isinstance(token, str) or not token:
            raise RuntimeError("registration did not return a device access token")
        self.store.finalize_registration(identity, token)
        return identity
