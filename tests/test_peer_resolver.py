import json

import httpx
import pytest

from awiki_lite_cli.infrastructure.anp_sdk import generate_identity
from awiki_lite_cli.infrastructure.peer_resolver import (
    normalize_peer_reference,
    resolve_peer_did,
)


async def public_address(_hostname: str, _port: int) -> list[str]:
    return ["93.184.216.34"]


def test_peer_reference_accepts_bare_full_and_did() -> None:
    did = "did:wba:awiki.test:user:bob:e1_fixture"
    assert normalize_peer_reference("bob", "alice.awiki.test") == ("bob.awiki.test", False)
    assert normalize_peer_reference("@bob", "alice.awiki.test") == (
        "bob.awiki.test",
        False,
    )
    assert normalize_peer_reference("bob.awiki.test", "alice.awiki.test") == (
        "bob.awiki.test",
        False,
    )
    assert normalize_peer_reference(did, "alice.awiki.test") == (did, True)


@pytest.mark.asyncio
async def test_exact_did_bypasses_network_resolution() -> None:
    did = "did:wba:awiki.test:user:bob:e1_fixture"

    def handler(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("exact DID must not trigger a network request")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await resolve_peer_did(client, did, "alice.awiki.test")

    assert result == did


@pytest.mark.asyncio
async def test_resolve_peer_did_verifies_handle_and_did_document() -> None:
    generated = generate_identity("awiki.test", "bob", "https://awiki.test")
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        assert request.headers["Host"] == "awiki.test"
        if request.url.path == "/.well-known/handle/bob":
            value = {
                "handle": "bob.awiki.test",
                "did": generated.did,
                "status": "active",
                "binding_generation": "1",
            }
        else:
            value = generated.did_document
        return httpx.Response(200, content=json.dumps(value).encode())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await resolve_peer_did(
            client,
            "bob",
            "alice.awiki.test",
            address_resolver=public_address,
        )

    assert result == generated.did
    assert paths == [
        "/.well-known/handle/bob",
        f"/user/bob/{generated.did.rsplit(':', 1)[1]}/did.json",
    ]


@pytest.mark.asyncio
async def test_resolve_peer_did_rejects_mismatched_handle() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "handle": "mallory.awiki.test",
                "did": "did:wba:awiki.test:user:bob:e1_fixture",
                "status": "active",
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(RuntimeError, match="mismatched"):
            await resolve_peer_did(
                client,
                "bob",
                "alice.awiki.test",
                address_resolver=public_address,
            )


@pytest.mark.asyncio
async def test_resolve_peer_did_rejects_inactive_handle() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "handle": "bob.awiki.test",
                "did": "did:wba:awiki.test:user:bob:e1_fixture",
                "status": "inactive",
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(RuntimeError, match="inactive"):
            await resolve_peer_did(
                client,
                "bob",
                "alice.awiki.test",
                address_resolver=public_address,
            )


@pytest.mark.asyncio
async def test_resolve_peer_did_rejects_failed_document_signature() -> None:
    generated = generate_identity("awiki.test", "bob", "https://awiki.test")
    tampered = json.loads(json.dumps(generated.did_document))
    tampered["service"][0]["serviceEndpoint"] = "https://attacker.example/im/rpc"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/handle/bob":
            return httpx.Response(
                200,
                json={
                    "handle": "bob.awiki.test",
                    "did": generated.did,
                    "status": "active",
                },
            )
        return httpx.Response(200, json=tampered)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(RuntimeError, match="failed verification"):
            await resolve_peer_did(
                client,
                "bob",
                "alice.awiki.test",
                address_resolver=public_address,
            )


@pytest.mark.asyncio
async def test_resolve_peer_did_rejects_not_found_handle() -> None:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _request: httpx.Response(404))
    ) as client:
        with pytest.raises(RuntimeError, match="unable to read handle resolution URL"):
            await resolve_peer_did(
                client,
                "bob",
                "alice.awiki.test",
                address_resolver=public_address,
            )
