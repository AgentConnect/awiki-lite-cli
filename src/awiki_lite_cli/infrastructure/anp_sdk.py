"""Narrow adapter around the sibling ANP Python SDK."""

from __future__ import annotations

import base64
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.metadata import version
from typing import Any

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
from anp.proof import (  # type: ignore[import-untyped]
    Rfc9421OriginProofGenerationOptions,
    generate_rfc9421_origin_proof,
    generate_w3c_proof,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

CANONICAL_MANIFEST_PROFILES = (
    PROFILE_CORE_BINDING_V1,
    PROFILE_IDENTITY_DISCOVERY_V1,
    PROFILE_DIRECT_BASE_V1,
    PROFILE_DIRECT_E2EE_V2,
    PROFILE_GROUP_BASE_V1,
    PROFILE_GROUP_E2EE_V2,
)
RUNTIME_PROFILES = (PROFILE_CORE_BINDING_V1, PROFILE_IDENTITY_DISCOVERY_V1, PROFILE_DIRECT_BASE_V1)


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
    root_private_key: object
    device_signing_private_key: object
    device_agreement_private_key: object


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
                "profiles": [PROFILE_CORE_BINDING_V1, PROFILE_DIRECT_BASE_V1],
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
    private_key: object,
    key_id: str,
) -> dict[str, str]:
    """Delegate request canonicalization and RFC 9421 signing to ANP."""
    options = Rfc9421OriginProofGenerationOptions(
        created=int(time.time()), nonce=secrets.token_urlsafe(12)
    )
    return dict(
        generate_rfc9421_origin_proof(method, meta, body, private_key, key_id, options=options)
    )


def _okp_jwk_method(key_id: str, did: str, curve: str, public_key: object) -> dict[str, Any]:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return {
        "id": key_id,
        "type": "JsonWebKey2020",
        "controller": did,
        "publicKeyJwk": {"kty": "OKP", "crv": curve, "x": encoded},
    }
