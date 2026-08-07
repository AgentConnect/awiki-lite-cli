"""Strict validation for network-bearing AWiki identifiers."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote

_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_PATH_SEGMENT = re.compile(r"^[A-Za-z0-9._~-]+$")
_PERCENT_ESCAPE = re.compile(r"%(?:[0-9A-Fa-f]{2})")


def validate_wba_did(value: str, *, field: str = "DID") -> str:
    """Validate a canonical public did:wba without URL or numeric-host ambiguity."""
    if not isinstance(value, str) or value != value.strip() or not value.startswith("did:wba:"):
        raise ValueError(f"{field} must be an exact did:wba identifier")
    parts = value.split(":")
    if len(parts) < 3:
        raise ValueError(f"{field} must be an exact did:wba identifier")
    encoded_host = parts[2]
    _validate_percent_encoding(encoded_host, field)
    hostname = unquote(encoded_host).lower().rstrip(".")
    validate_public_hostname(hostname, field=field)
    if encoded_host.lower().rstrip(".") != hostname:
        raise ValueError(f"{field} hostname must use canonical lowercase ASCII")
    for encoded_segment in parts[3:]:
        _validate_percent_encoding(encoded_segment, field)
        segment = unquote(encoded_segment)
        if (
            not segment
            or segment in {".", ".."}
            or _PATH_SEGMENT.fullmatch(segment) is None
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in segment)
        ):
            raise ValueError(f"{field} contains an invalid path segment")
    return value


def validate_public_hostname(hostname: str, *, field: str = "hostname") -> str:
    """Reject local, malformed, IDN-ambiguous, and non-standard numeric hosts."""
    if (
        not hostname
        or len(hostname) > 253
        or not hostname.isascii()
        or hostname != hostname.lower()
        or hostname == "localhost"
        or hostname.endswith(".localhost")
    ):
        raise ValueError(f"{field} is not a safe public hostname")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        if re.fullmatch(r"[0-9.]+", hostname) or hostname.startswith("0x"):
            raise ValueError(f"{field} uses an ambiguous numeric address") from None
        labels = hostname.split(".")
        if any(_DOMAIN_LABEL.fullmatch(label) is None for label in labels):
            raise ValueError(f"{field} is not a valid DNS hostname") from None
    else:
        if not address.is_global or getattr(address, "ipv4_mapped", None) is not None:
            raise ValueError(f"{field} is not a public IP address")
    return hostname


def _validate_percent_encoding(value: str, field: str) -> None:
    remainder = _PERCENT_ESCAPE.sub("", value)
    if "%" in remainder:
        raise ValueError(f"{field} contains invalid percent encoding")
