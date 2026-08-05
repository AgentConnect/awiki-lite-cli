import json
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "contracts"


def test_registration_fixture_freezes_server_canonical_profiles() -> None:
    fixture = json.loads((FIXTURES / "registration.json").read_text())
    assert fixture["client_version"] == "awiki-cli/0714/0.1.0"
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
