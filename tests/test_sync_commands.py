import asyncio
from pathlib import Path

import pytest
from typer.testing import CliRunner

from awiki_lite_cli.cli import app
from awiki_lite_cli.commands import direct
from awiki_lite_cli.commands.identity import _init_sync
from awiki_lite_cli.config import Settings
from awiki_lite_cli.domain.models import (
    AuthenticatedIdentity,
    IdentityState,
    SyncBootstrapState,
)
from awiki_lite_cli.infrastructure.anp_sdk import generate_identity
from awiki_lite_cli.infrastructure.message_service import MessageService
from awiki_lite_cli.infrastructure.state import SecureStateStore


@pytest.mark.parametrize("kind", ["inbox", "history"])
def test_empty_legacy_reads_do_not_start_sync_migration(
    kind: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    generated = generate_identity("example.test", "alice", "https://example.test")
    identity = IdentityState(
        generated.did,
        "alice.example.test",
        generated.device_signing_key_id,
        generated.device_id,
        generated.did_document,
    )
    store = SecureStateStore(tmp_path / kind)
    store.save_registration(
        identity,
        "fixture-token",
        {
            "root-key": generated.root_private_key,
            "device-signing": generated.device_signing_private_key,
            "device-agreement": generated.device_agreement_private_key,
        },
        "long passphrase value",
    )
    methods: list[str] = []

    class FakeService:
        client = object()

        async def inbox(self, _identity, _limit, _skip):  # type: ignore[no-untyped-def]
            methods.append("inbox.get")
            return [], False

        async def history(self, _identity, _peer, _limit, _skip):  # type: ignore[no-untyped-def]
            methods.append("direct.get_history")
            return [], False

    def run(action):  # type: ignore[no-untyped-def]
        return asyncio.run(action(FakeService(), store))

    async def resolve(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        return identity.did

    monkeypatch.setattr(direct, "_run", run)
    monkeypatch.setattr(direct, "resolve_peer_did", resolve)
    args = ["msg", "inbox"] if kind == "inbox" else ["msg", "history", "--with", "bob"]

    result = CliRunner().invoke(app, args)

    assert result.exit_code == 0
    assert methods == ["inbox.get" if kind == "inbox" else "direct.get_history"]
    assert store.load_sync(identity.did) is None


@pytest.mark.asyncio
async def test_explicit_sync_initialization_is_retry_safe(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    generated = generate_identity("example.test", "alice", "https://example.test")
    public = IdentityState(
        generated.did,
        "alice.example.test",
        generated.device_signing_key_id,
        generated.device_id,
        generated.did_document,
    )
    store = SecureStateStore(tmp_path / "explicit")
    store.save_registration(
        public,
        "fixture-token",
        {
            "root-key": generated.root_private_key,
            "device-signing": generated.device_signing_private_key,
            "device-agreement": generated.device_agreement_private_key,
        },
        "long passphrase value",
    )
    identity = AuthenticatedIdentity(store.load_public(), store.load_session())
    client_ids: list[str] = []

    async def bootstrap(_service, authenticated, client_id):  # type: ignore[no-untyped-def]
        client_ids.append(client_id)
        return SyncBootstrapState(
            "account-1",
            authenticated.identity.device_id,
            "2026-08-21T00:00:00Z",
            "1",
            "7",
        )

    monkeypatch.setattr(MessageService, "bootstrap_sync", bootstrap)
    settings = Settings("https://example.test", "https://example.test", store.root)

    first = await _init_sync(settings, store, identity)
    second = await _init_sync(settings, store, identity)

    assert first == second
    assert len(client_ids) == 1
    saved = store.load_sync(public.did)
    assert saved is not None and saved.bootstrap == first
