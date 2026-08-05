from anp.authentication import validate_device_manifest  # type: ignore[import-untyped]
from anp.proof import verify_rfc9421_origin_proof  # type: ignore[import-untyped]

from awiki_lite_cli.infrastructure.anp_sdk import (
    CANONICAL_MANIFEST_PROFILES,
    generate_identity,
    generate_origin_proof,
    sdk_info,
)


def test_sdk_runtime_surface_excludes_e2ee_and_group() -> None:
    info = sdk_info()
    assert info.version == "0.9.1"
    assert all(
        "e2ee" not in profile and "group" not in profile for profile in info.allowed_profiles
    )


def test_generated_identity_has_one_server_compatible_device() -> None:
    generated = generate_identity("example.test", "alice", "https://example.test")
    manifest = validate_device_manifest(generated.did_document)
    assert manifest is not None
    assert len(manifest.devices) == 1
    assert manifest.devices[0].profiles == CANONICAL_MANIFEST_PROFILES
    assert generated.did.startswith("did:wba:example.test:user:alice:e1_")


def test_origin_proof_is_generated_and_verified_by_anp() -> None:
    generated = generate_identity("example.test", "alice", "https://example.test")
    meta = {
        "profile": "anp.direct.base.v1",
        "security_profile": "transport-protected",
        "sender_did": generated.did,
        "target": {"kind": "agent", "did": "did:wba:example.test:user:bob:e1_fixture"},
        "operation_id": "op",
        "message_id": "msg",
        "created_at": "2026-08-05T00:00:00Z",
        "content_type": "text/plain",
    }
    body = {"text": "hello"}
    proof = generate_origin_proof(
        "direct.send",
        meta,
        body,
        generated.device_signing_private_key,
        generated.device_signing_key_id,
    )
    result = verify_rfc9421_origin_proof(
        proof, "direct.send", meta, body, did_document=generated.did_document
    )
    assert result.verification_method["id"] == generated.device_signing_key_id
