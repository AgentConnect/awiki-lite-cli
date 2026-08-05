import json
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "contracts"


def test_registration_fixture_freezes_server_canonical_profiles() -> None:
    fixture = json.loads((FIXTURES / "registration.json").read_text())
    assert fixture["client_version"] == "awiki-cli/0714/0.2.0"
    assert fixture["otp"]["params"]["purpose"] == "awiki.identity.register.v1"
    assert len(fixture["manifest_profiles"]) == 6
    assert fixture["register_result"]["access_token"] == "<redacted>"


def test_direct_fixture_is_plain_text_only() -> None:
    fixture = json.loads((FIXTURES / "direct.json").read_text())
    send = fixture["send"]
    assert send["meta"]["profile"] == "anp.direct.base.v1"
    assert send["meta"]["security_profile"] == "transport-protected"
    assert send["meta"]["content_type"] == "text/plain"
    assert "e2ee" not in json.dumps(send).lower()


def test_group_fixture_freezes_plain_group_base_only() -> None:
    fixture = json.loads((FIXTURES / "group.json").read_text())
    create = fixture["create"]
    assert create["meta"]["profile"] == "anp.group.base.v1"
    assert create["meta"]["security_profile"] == "transport-protected"
    assert create["body"]["group_policy"]["admission_mode"] == "admin-add"
    assert create["body"]["group_policy"]["attachments_allowed"] is True
    assert fixture["add"]["body"] == {
        "member_did": "did:wba:example.test:user:bob:e1_fixture",
        "role": "member",
    }
    assert "group.e2ee" not in json.dumps(fixture).lower()


def test_attachment_fixture_freezes_plain_p7_v1_only() -> None:
    fixture = json.loads((FIXTURES / "attachment.json").read_text())
    assert fixture["profile"] == "anp.attachment.v1"
    assert fixture["create_slot"]["body"]["object_encryption_mode"] == "none"
    assert fixture["manifest"]["attachments"][0]["encryption_info"] == {"mode": "none"}
    assert fixture["create_slot_result"]["upload_headers"] == "<redacted>"
    assert fixture["download_ticket"]["result"]["download_ticket_b64u"] == "<redacted>"
    assert "object-e2ee" not in json.dumps(fixture).lower()
