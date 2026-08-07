"""Compatibility exports for identifier validation now owned by the domain."""

from awiki_lite_cli.domain.validation import validate_public_hostname, validate_wba_did

__all__ = ["validate_public_hostname", "validate_wba_did"]
