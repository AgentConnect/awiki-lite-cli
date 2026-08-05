"""Plain direct-message commands."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import TypeVar

import httpx
import typer

from awiki_lite_cli.config import Settings
from awiki_lite_cli.domain.models import AuthenticatedIdentity, ChatMessage
from awiki_lite_cli.infrastructure.message_service import MessageService, validate_did
from awiki_lite_cli.infrastructure.rpc import JsonRpcFailure
from awiki_lite_cli.infrastructure.state import SecureStateStore, StateError

app = typer.Typer(help="Send and read transport-protected direct messages.")
T = TypeVar("T")


@app.command("send")
def send(recipient_did: str, text: str) -> None:
    """Send a plain text message to one exact DID."""

    async def action(service: MessageService, store: SecureStateStore) -> ChatMessage:
        recipient = validate_did(recipient_did)
        if not text or not text.strip():
            raise ValueError("message text must not be empty")
        if len(text.encode()) > 64 * 1024:
            raise ValueError("message text is too large")
        passphrase = typer.prompt("Local key passphrase", hide_input=True)
        identity = store.unlock(passphrase)
        await service.ensure_direct_base(identity)
        pending = store.prepare_send(recipient, text)
        try:
            message = await service.send(
                identity,
                recipient,
                text,
                operation_id=pending.operation_id,
                message_id=pending.message_id,
                created_at=pending.created_at,
                proof_created=pending.proof_created,
                proof_nonce=pending.proof_nonce,
                preflight=False,
            )
        except JsonRpcFailure:
            store.abandon_send(pending)
            raise
        store.complete_send(pending)
        return message

    message = _run(action)
    typer.echo(f"Sent {message.message_id} to {message.target_did}")


@app.command("inbox")
def inbox(
    limit: int = typer.Option(20, min=1, max=100),
    mark_read: bool = typer.Option(False, "--mark-read", help="Mark displayed messages read."),
) -> None:
    """Read the local plain-message inbox."""

    async def action(
        service: MessageService, store: SecureStateStore
    ) -> tuple[list[ChatMessage], bool, int]:
        identity = AuthenticatedIdentity(store.load_public(), store.load_session())
        messages, has_more = await service.inbox(identity, limit)
        updated = (
            await service.mark_read(identity, [item.message_id for item in messages])
            if mark_read and messages
            else 0
        )
        return messages, has_more, updated

    messages, has_more, updated = _run(action)
    _render(messages)
    if updated:
        typer.echo(f"Marked {updated} message(s) read.")
    if has_more:
        typer.echo("More messages are available; increase --limit.")


@app.command("history")
def history(peer_did: str, limit: int = typer.Option(20, min=1, max=100)) -> None:
    """Read plain-message history with one exact DID."""

    async def action(
        service: MessageService, store: SecureStateStore
    ) -> tuple[list[ChatMessage], bool]:
        identity = AuthenticatedIdentity(store.load_public(), store.load_session())
        return await service.history(identity, peer_did, limit)

    messages, has_more = _run(action)
    _render(messages)
    if has_more:
        typer.echo("More messages are available; increase --limit.")


def _run(action: Callable[[MessageService, SecureStateStore], Awaitable[T]]) -> T:
    settings = Settings.from_env()
    store = SecureStateStore(settings.state_dir)

    async def invoke() -> T:
        async with httpx.AsyncClient(timeout=20.0, trust_env=False) as client:
            return await action(MessageService(client, settings.message_service_url), store)

    try:
        return asyncio.run(invoke())
    except ValueError as exc:
        typer.echo(f"Invalid input: {exc}", err=True)
        raise typer.Exit(2) from None
    except JsonRpcFailure as exc:
        if exc.code in {401, 1401} or "unauthorized" in exc.message.lower():
            store.clear_session()
            typer.echo("Session expired; register again in this v0.1 client.", err=True)
        else:
            typer.echo(
                f"Message service rejected the request (JSON-RPC code {exc.code}).", err=True
            )
        raise typer.Exit(1) from None
    except (StateError, RuntimeError, httpx.HTTPError) as exc:
        typer.echo(f"Messaging failed: {exc}", err=True)
        raise typer.Exit(1) from None


def _render(messages: list[ChatMessage]) -> None:
    if not messages:
        typer.echo("No plain direct messages.")
        return
    for message in messages:
        timestamp = f"[{message.created_at}] " if message.created_at else ""
        typer.echo(f"{timestamp}{message.sender_did} -> {message.target_did}: {message.text}")
