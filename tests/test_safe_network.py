from __future__ import annotations

import pytest

from awiki_lite_cli.infrastructure.safe_network import pin_https_url
from awiki_lite_cli.infrastructure.validation import validate_public_hostname


@pytest.mark.parametrize("hostname", ["2130706433", "127.1", "0x7f000001", "017700000001"])
def test_nonstandard_ipv4_forms_are_rejected(hostname: str) -> None:
    with pytest.raises(ValueError, match="ambiguous"):
        validate_public_hostname(hostname)


@pytest.mark.asyncio
async def test_dns_pin_rejects_any_private_or_mapped_answer() -> None:
    async def mixed(_hostname: str, _port: int) -> list[str]:
        return ["93.184.216.34", "10.0.0.1"]

    async def mapped(_hostname: str, _port: int) -> list[str]:
        return ["::ffff:127.0.0.1"]

    with pytest.raises(RuntimeError, match="unsafe DNS"):
        await pin_https_url("https://objects.example/path", resolver=mixed)
    with pytest.raises(RuntimeError, match="unsafe DNS"):
        await pin_https_url("https://objects.example/path", resolver=mapped)


@pytest.mark.asyncio
async def test_dns_pin_connects_to_checked_ip_but_preserves_tls_authority() -> None:
    async def public(_hostname: str, _port: int) -> list[str]:
        return ["2606:2800:220:1:248:1893:25c8:1946", "93.184.216.34"]

    target = await pin_https_url("https://objects.example:8443/a", resolver=public)
    assert target.url == "https://93.184.216.34:8443/a"
    assert target.host_header == "objects.example:8443"
    assert target.extensions == {"sni_hostname": "objects.example"}


@pytest.mark.asyncio
async def test_private_network_requires_explicit_opt_in() -> None:
    async def private(_hostname: str, _port: int) -> list[str]:
        return ["10.0.0.8"]

    with pytest.raises(RuntimeError, match="unsafe DNS"):
        await pin_https_url("https://objects.internal/file", resolver=private)
    target = await pin_https_url(
        "https://objects.internal/file",
        resolver=private,
        allow_private_network=True,
    )
    assert target.url == "https://10.0.0.8/file"
