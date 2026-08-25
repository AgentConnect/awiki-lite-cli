import pytest

from awiki_lite_cli.domain.validation import validate_wba_did


def test_validate_wba_did_rejects_mixed_case_hosts() -> None:
    with pytest.raises(ValueError, match="canonical lowercase"):
        validate_wba_did("did:wba:Example.com:user:bob")


def test_validate_wba_did_accepts_canonical_hosts() -> None:
    did = "did:wba:example.com:user:bob:e1_fixture"
    assert validate_wba_did(did) == did
