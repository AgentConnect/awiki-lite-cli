"""Resolve human handles to verified WBA DIDs without local contact state."""

from __future__ import annotations

from typing import Any

import httpx
from anp.authentication.did_resolver import (  # type: ignore[import-untyped]
    build_did_resolution_url,
)
from anp.wns import build_resolution_url, validate_handle  # type: ignore[import-untyped]

from awiki_lite_cli.infrastructure.anp_sdk import verify_resolved_document
from awiki_lite_cli.infrastructure.safe_network import (
    AddressResolver,
    pin_https_url,
    pinned_headers,
    resolve_public_addresses,
)
from awiki_lite_cli.infrastructure.validation import validate_public_hostname, validate_wba_did


def normalize_peer_reference(value: str, owner_handle: str) -> tuple[str, bool]:
    raw = value.strip()
    if raw.startswith("did:"):
        return validate_wba_did(raw, field="peer"), True
    if raw.startswith("@"):
        raw = raw[1:]
    if "." not in raw:
        _, separator, default_domain = owner_handle.partition(".")
        if not separator:
            raise ValueError("local identity handle has no domain")
        raw = f"{raw}.{validate_public_hostname(default_domain, field='handle domain')}"
    try:
        local_part, domain = validate_handle(raw.lower())
    except Exception:
        raise ValueError("peer must be a DID, full handle, or handle local-part") from None
    return f"{local_part}.{domain}", False


async def resolve_peer_did(
    client: httpx.AsyncClient,
    value: str,
    owner_handle: str,
    *,
    address_resolver: AddressResolver = resolve_public_addresses,
    allow_private_network: bool = False,
) -> str:
    peer, is_did = normalize_peer_reference(value, owner_handle)
    if is_did:
        return peer

    local_part, domain = validate_handle(peer)
    resolution = await _get_public_json(
        client,
        build_resolution_url(local_part, domain),
        "handle resolution URL",
        address_resolver,
        allow_private_network,
    )
    if resolution.get("handle") != peer or resolution.get("status") != "active":
        raise RuntimeError("handle resolution returned an inactive or mismatched handle")
    did = resolution.get("did")
    if not isinstance(did, str):
        raise RuntimeError("handle resolution returned an invalid DID")
    try:
        did = validate_wba_did(did, field="resolved peer DID")
    except ValueError as exc:
        raise RuntimeError("handle resolution returned an invalid DID") from exc
    if did.split(":", 3)[2] != domain:
        raise RuntimeError("handle and DID domains do not match")

    document = await _get_public_json(
        client,
        build_did_resolution_url(did),
        "peer DID URL",
        address_resolver,
        allow_private_network,
    )
    try:
        verify_resolved_document(did, document)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("resolved peer DID document failed verification") from exc
    return did


async def _get_public_json(
    client: httpx.AsyncClient,
    url: str,
    field: str,
    address_resolver: AddressResolver,
    allow_private_network: bool,
) -> dict[str, Any]:
    try:
        target = await pin_https_url(
            url,
            resolver=address_resolver,
            field=field,
            allow_private_network=allow_private_network,
        )
        response = await client.get(
            target.url,
            headers=pinned_headers(target, {"Accept": "application/json"}),
            follow_redirects=False,
            extensions=target.extensions,
        )
        response.raise_for_status()
        value = response.json()
    except (httpx.HTTPError, ValueError):
        raise RuntimeError(f"unable to read {field}") from None
    if not isinstance(value, dict):
        raise RuntimeError(f"{field} returned invalid JSON")
    return value
