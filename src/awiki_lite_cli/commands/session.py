"""Bearer-session recovery commands."""

from __future__ import annotations

import asyncio

import httpx
import typer

from awiki_lite_cli.config import Settings
from awiki_lite_cli.infrastructure.rpc import JsonRpcFailure
from awiki_lite_cli.infrastructure.state import SecureStateStore, StateError
from awiki_lite_cli.infrastructure.user_service import UserService

app = typer.Typer(help="Recover the bearer session without replacing the identity.")


@app.command("refresh")
def refresh() -> None:
    """Refresh the session using the existing encrypted device signing key."""
    passphrase = typer.prompt("Local key passphrase", hide_input=True)
    try:
        did = asyncio.run(_refresh(passphrase))
    except JsonRpcFailure as exc:
        typer.echo(f"Session refresh was rejected (JSON-RPC code {exc.code}).", err=True)
        raise typer.Exit(1) from None
    except (StateError, RuntimeError, ValueError, httpx.HTTPError) as exc:
        typer.echo(f"Session refresh failed: {exc}", err=True)
        raise typer.Exit(1) from None
    typer.echo(f"Session refreshed for {did}")


async def _refresh(passphrase: str) -> str:
    settings = Settings.from_env()
    store = SecureStateStore(settings.state_dir)
    identity = store.load_public()
    signing_key = store.load_device_signing_key(passphrase)
    async with httpx.AsyncClient(timeout=20.0, trust_env=False) as client:
        token = await UserService(client, settings.user_service_url).refresh_session(
            identity, signing_key
        )
    store.save_session(token)
    return identity.did
