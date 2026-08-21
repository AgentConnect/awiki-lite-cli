"""DNS-pinned HTTPS requests for server-supplied network locations."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit, urlunsplit

from awiki_lite_cli.infrastructure.validation import validate_public_hostname

AddressResolver = Callable[[str, int], Awaitable[Sequence[str]]]


@dataclass(frozen=True, slots=True)
class PinnedHttpsTarget:
    """One validated HTTPS origin pinned to an audited address."""

    url: str
    host_header: str
    server_hostname: str

    @property
    def extensions(self) -> dict[str, str]:
        return {"sni_hostname": self.server_hostname}


async def resolve_public_addresses(hostname: str, port: int) -> Sequence[str]:
    """Resolve in a worker thread and return all unique TCP addresses."""

    def resolve() -> list[str]:
        rows = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        return list(dict.fromkeys(str(row[4][0]) for row in rows))

    return await asyncio.to_thread(resolve)


async def pin_https_url(
    value: str,
    *,
    resolver: AddressResolver = resolve_public_addresses,
    field: str = "URL",
    allow_private_network: bool = False,
) -> PinnedHttpsTarget:
    """Validate an HTTPS URL and bind this request to one public DNS answer."""
    parsed = urlsplit(value)
    hostname = parsed.hostname
    try:
        explicit_port = parsed.port
    except ValueError as exc:
        raise RuntimeError(f"unsafe {field}") from exc
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or explicit_port is not None
        and not 1 <= explicit_port <= 65535
    ):
        raise RuntimeError(f"unsafe {field}")
    hostname = hostname.lower().rstrip(".")
    try:
        validate_public_hostname(hostname, field=field)
    except ValueError as exc:
        raise RuntimeError(f"unsafe {field}") from exc
    port = explicit_port or 443
    try:
        raw_addresses = await resolver(hostname, port)
    except (OSError, socket.gaierror) as exc:
        raise RuntimeError(f"unable to resolve {field}") from exc
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    try:
        addresses = [ipaddress.ip_address(raw) for raw in raw_addresses]
    except ValueError as exc:
        raise RuntimeError(f"unsafe DNS response for {field}") from exc
    if not addresses or (
        not allow_private_network
        and any(
            not address.is_global or getattr(address, "ipv4_mapped", None) is not None
            for address in addresses
        )
    ):
        raise RuntimeError(f"unsafe DNS response for {field}")
    selected = sorted(addresses, key=lambda item: (item.version, item.packed))[0]
    literal = f"[{selected}]" if selected.version == 6 else str(selected)
    netloc = literal if port == 443 else f"{literal}:{port}"
    authority = hostname if port == 443 else f"{hostname}:{port}"
    pinned = SplitResult(parsed.scheme, netloc, parsed.path or "/", "", "")
    return PinnedHttpsTarget(urlunsplit(pinned), authority, hostname)


def pinned_headers(target: PinnedHttpsTarget, headers: dict[str, str]) -> dict[str, str]:
    """Add an authoritative Host header without allowing caller replacement."""
    return {**headers, "Host": target.host_header}
