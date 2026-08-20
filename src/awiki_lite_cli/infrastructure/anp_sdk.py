"""Narrow adapter around the ANP Python SDK."""

from __future__ import annotations

import base64
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.metadata import version
from typing import Any
from urllib.parse import urlsplit

import httpx
from anp.authentication import (  # type: ignore[import-untyped]
    PROFILE_CORE_BINDING_V1,
    PROFILE_DIRECT_BASE_V1,
    PROFILE_DIRECT_E2EE_V2,
    PROFILE_GROUP_BASE_V1,
    PROFILE_GROUP_E2EE_V2,
    PROFILE_IDENTITY_DISCOVERY_V1,
    DeviceManifestEntry,
    build_vnext_did_document,
    create_did_wba_document,
    validate_device_manifest,
)
from anp.authentication.did_resolver import (  # type: ignore[import-untyped]
    build_did_resolution_url,
)
from anp.authentication.did_wba import (  # type: ignore[import-untyped]
    _extract_public_key,
    _find_verification_method,
    validate_did_document_binding,
)
from anp.proof import (  # type: ignore[import-untyped]
    Rfc9421OriginProofGenerationOptions,
    generate_rfc9421_origin_proof,
    generate_w3c_proof,
    verify_w3c_proof,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from awiki_lite_cli.infrastructure.safe_network import (
    AddressResolver,
    pin_https_url,
    pinned_headers,
    resolve_public_addresses,
)
from awiki_lite_cli.infrastructure.validation import validate_wba_did

CANONICAL_MANIFEST_PROFILES = (
    PROFILE_CORE_BINDING_V1,
    PROFILE_IDENTITY_DISCOVERY_V1,
    PROFILE_DIRECT_BASE_V1,
    PROFILE_DIRECT_E2EE_V2,
    PROFILE_GROUP_BASE_V1,
    PROFILE_GROUP_E2EE_V2,
)
ATTACHMENT_PROFILE = "anp.attachment.v1"
RUNTIME_PROFILES = (
    PROFILE_CORE_BINDING_V1,
    PROFILE_IDENTITY_DISCOVERY_V1,
    PROFILE_DIRECT_BASE_V1,
    PROFILE_GROUP_BASE_V1,
    ATTACHMENT_PROFILE,
)


@dataclass(frozen=True, slots=True)
class AnpSdkInfo:
    version: str
    allowed_profiles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GeneratedIdentity:
    did: str
    did_document: dict[str, Any]
    device_id: str
    root_key_id: str
    device_signing_key_id: str
    device_agreement_key_id: str
    root_private_key: Any
    device_signing_private_key: Any
    device_agreement_private_key: Any


def sdk_info() -> AnpSdkInfo:
    return AnpSdkInfo(version=version("anp"), allowed_profiles=RUNTIME_PROFILES)


def generate_identity(hostname: str, handle: str, message_service_url: str) -> GeneratedIdentity:
    """Generate and root-sign the one-device document required by User Service."""
    challenge = secrets.token_urlsafe(24)
    base_document, root_keys = create_did_wba_document(
        hostname=hostname,
        path_segments=["user", handle],
        services=[
            {
                "id": "#message",
                "type": "ANPMessageService",
                "serviceEndpoint": message_service_url.rstrip("/") + "/im/rpc",
                "serviceDid": _default_service_did(message_service_url),
                "profiles": [
                    PROFILE_CORE_BINDING_V1,
                    PROFILE_DIRECT_BASE_V1,
                    PROFILE_GROUP_BASE_V1,
                    ATTACHMENT_PROFILE,
                ],
                "securityProfiles": ["transport-protected"],
            }
        ],
        proof_purpose="assertionMethod",
        domain=hostname,
        challenge=challenge,
        enable_e2ee=False,
        did_profile="e1",
    )
    did = str(base_document["id"])
    root_key_id = str(base_document["verificationMethod"][0]["id"])
    root_private_key = serialization.load_pem_private_key(root_keys["key-1"][0], password=None)
    signing_key = ed25519.Ed25519PrivateKey.generate()
    agreement_key = x25519.X25519PrivateKey.generate()
    device_id = "dev-" + secrets.token_hex(8)
    signing_key_id = f"{did}#{device_id}-sign"
    agreement_key_id = f"{did}#{device_id}-e2ee"
    signing_method = _okp_jwk_method(signing_key_id, did, "Ed25519", signing_key.public_key())
    agreement_method = _okp_jwk_method(agreement_key_id, did, "X25519", agreement_key.public_key())
    unsigned = build_vnext_did_document(
        {
            key: value
            for key, value in base_document.items()
            if key not in {"proof", "verificationMethod", "authentication", "assertionMethod"}
        },
        root_key_id,
        base_document["verificationMethod"][0],
        DeviceManifestEntry(
            device_id, signing_key_id, agreement_key_id, CANONICAL_MANIFEST_PROFILES
        ),
        signing_method,
        agreement_method,
    )
    signed = generate_w3c_proof(
        unsigned,
        root_private_key,
        root_key_id,
        proof_purpose="assertionMethod",
        proof_type="DataIntegrityProof",
        cryptosuite="eddsa-jcs-2022",
        domain=hostname,
        challenge=challenge,
    )
    validate_device_manifest(signed)
    return GeneratedIdentity(
        did,
        signed,
        device_id,
        root_key_id,
        signing_key_id,
        agreement_key_id,
        root_private_key,
        signing_key,
        agreement_key,
    )


def generate_origin_proof(
    method: str,
    meta: Mapping[str, Any],
    body: Mapping[str, Any],
    private_key: Any,
    key_id: str,
    *,
    created: int | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    """Delegate request canonicalization and RFC 9421 signing to ANP."""
    options = Rfc9421OriginProofGenerationOptions(
        created=created if created is not None else int(time.time()),
        nonce=nonce if nonce is not None else secrets.token_urlsafe(12),
    )
    return dict(
        generate_rfc9421_origin_proof(method, meta, body, private_key, key_id, options=options)
    )


async def resolve_attachment_service_did(
    sender_did: str,
    *,
    client: httpx.AsyncClient | None = None,
    address_resolver: AddressResolver = resolve_public_addresses,
) -> str:
    """Resolve and proof-check the sender's compatible ANPMessageService serviceDid."""
    validate_wba_did(sender_did, field="attachment sender DID")
    resolution_url = build_did_resolution_url(sender_did)
    try:
        target = await pin_https_url(
            resolution_url,
            resolver=address_resolver,
            field="attachment sender DID URL",
        )
        owns_client = client is None
        active_client = client or httpx.AsyncClient(timeout=10.0, trust_env=False)
        try:
            response = await active_client.get(
                target.url,
                headers=pinned_headers(target, {"Accept": "application/json"}),
                follow_redirects=False,
                extensions=target.extensions,
            )
            response.raise_for_status()
            document = response.json()
        finally:
            if owns_client:
                await active_client.aclose()
        verify_resolved_document(sender_did, document)
    except Exception:
        raise RuntimeError("unable to resolve the attachment sender DID document") from None
    return select_attachment_service_did(sender_did, document)


def verify_resolved_document(sender_did: str, document: Any) -> None:
    if not isinstance(document, dict) or document.get("id") != sender_did:
        raise ValueError("DID document ID mismatch")
    if not validate_did_document_binding(document, verify_proof=True):
        raise ValueError("DID document binding verification failed")
    proof = document.get("proof")
    if not isinstance(proof, dict):
        raise ValueError("DID document proof is missing")
    method_id = proof.get("verificationMethod")
    if not isinstance(method_id, str) or not method_id:
        raise ValueError("DID document proof method is missing")
    method = _find_verification_method(document, method_id)
    if not method or not verify_w3c_proof(document, _extract_public_key(method)):
        raise ValueError("DID document proof verification failed")


def select_attachment_service_did(sender_did: str, document: Mapping[str, Any]) -> str:
    if document.get("id") != sender_did:
        raise RuntimeError("resolved attachment sender DID document does not match")
    services = document.get("service")
    if not isinstance(services, list):
        raise RuntimeError("attachment sender DID document has no compatible service")
    candidates: list[tuple[int, int, str]] = []
    for index, raw in enumerate(services):
        if not isinstance(raw, dict) or raw.get("type") != "ANPMessageService":
            continue
        profiles = raw.get("profiles")
        security = raw.get("securityProfiles", raw.get("security_profiles"))
        service_did = raw.get("serviceDid")
        endpoint = raw.get("serviceEndpoint")
        if (
            not isinstance(profiles, list)
            or ATTACHMENT_PROFILE not in profiles
            or not isinstance(security, list)
            or "transport-protected" not in security
            or not isinstance(service_did, str)
            or len(service_did.split(":")) < 3
            or not service_did.startswith("did:wba:")
            or not isinstance(endpoint, str)
            or not _safe_https_endpoint(endpoint)
        ):
            continue
        priority = raw.get("priority")
        rank = priority if isinstance(priority, int) else 2**31 - 1
        candidates.append((rank, index, service_did))
    if not candidates:
        raise RuntimeError("attachment sender DID document has no compatible service")
    candidates.sort()
    return candidates[0][2]


def _default_service_did(message_service_url: str) -> str:
    parsed = urlsplit(message_service_url)
    hostname = parsed.hostname
    if parsed.scheme != "https" or not hostname or parsed.username or parsed.password:
        raise ValueError("Message Service URL must be an authority-safe HTTPS URL")
    return f"did:wba:{hostname}"


def _safe_https_endpoint(value: str) -> bool:
    parsed = urlsplit(value)
    return bool(
        parsed.scheme == "https"
        and parsed.hostname
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
    )


def _okp_jwk_method(key_id: str, did: str, curve: str, public_key: Any) -> dict[str, Any]:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return {
        "id": key_id,
        "type": "JsonWebKey2020",
        "controller": did,
        "publicKeyJwk": {"kty": "OKP", "crv": curve, "x": encoded},
    }
