
import pytest

from awiki_lite_cli.domain.models import IdentityState, SessionState, UnlockedIdentity
from awiki_lite_cli.infrastructure.anp_sdk import generate_identity
from awiki_lite_cli.infrastructure.message_service import (
    build_direct_send,
    build_history,
    build_inbox,
    build_mark_read,
)


def unlocked() -> UnlockedIdentity:
    generated = generate_identity("example.test", "alice", "https://example.test")
    identity = IdentityState(
        generated.did,
        "alice.example.test",
        generated.device_signing_key_id,
        generated.device_id,
        generated.did_document,
    )
    return UnlockedIdentity(
        identity,
        SessionState("token"),
        generated.root_private_key,
        generated.device_signing_private_key,
        generated.device_agreement_private_key,
    )


def test_direct_builder_is_closed_plain_profile() -> None:
    params = build_direct_send(
        unlocked(),
        "did:wba:example.test:user:bob:e1_fixture",
        "hello",
        operation_id="op",
        message_id="msg",
    )
    assert params["meta"]["profile"] == "anp.direct.base.v1"
    assert params["meta"]["security_profile"] == "transport-protected"
    assert params["meta"]["content_type"] == "text/plain"
    assert params["body"] == {"text": "hello"}
    assert params["auth"]["scheme"] == "anp-rfc9421-origin-proof-v1"


def test_direct_builder_rejects_invalid_inputs() -> None:
    with pytest.raises(ValueError, match="exact"):
        build_direct_send(unlocked(), "@bob", "hello")
    with pytest.raises(ValueError, match="empty"):
        build_direct_send(unlocked(), "did:wba:example.test:user:bob", "   ")


def test_read_builders_use_local_profiles_without_auth() -> None:
    did = "did:wba:example.test:user:alice:e1_fixture"
    assert build_inbox(did, 20)["meta"]["profile"] == "anp.inbox.local.v1"
    assert build_mark_read(did, ["m1"])["body"]["message_ids"] == ["m1"]
    assert (
        build_history(did, "did:wba:example.test:user:bob:e1_fixture", 20)["meta"]["profile"]
        == "anp.direct.local.v1"
    )
    assert "auth" not in build_inbox(did, 20)
