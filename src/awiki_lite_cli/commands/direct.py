"""Plain direct-message commands."""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Awaitable, Callable
from typing import Annotated, TypeVar

import httpx
import typer

from awiki_lite_cli.config import Settings
from awiki_lite_cli.domain.models import AttachmentContext, AuthenticatedIdentity, ChatMessage
from awiki_lite_cli.infrastructure.message_service import MessageService
from awiki_lite_cli.infrastructure.peer_resolver import resolve_peer_did
from awiki_lite_cli.infrastructure.rpc import JsonRpcFailure
from awiki_lite_cli.infrastructure.state import SecureStateStore, StateError
from awiki_lite_cli.presentation import terminal_text

app = typer.Typer(help="Send and read transport-protected direct messages.")
T = TypeVar("T")


@app.command("send")
def send(
    recipient_did: str,
    text: str | None = typer.Argument(None),
    stdin: bool = typer.Option(False, "--stdin", help="Read message text from standard input."),
) -> None:
    """Send a plain text message to one DID or handle."""
    settings = Settings.from_env()
    if stdin and text is not None:
        typer.echo("Invalid input: TEXT and --stdin are mutually exclusive", err=True)
        raise typer.Exit(2)
    text_value = sys.stdin.read() if stdin else text
    if text_value is None:
        text_value = typer.prompt("Message")

    async def action(service: MessageService, store: SecureStateStore) -> ChatMessage:
        recipient = await resolve_peer_did(
            service.client,
            recipient_did,
            store.load_public().handle,
            allow_private_network=settings.allow_private_network,
        )
        if not text_value or not text_value.strip():
            raise ValueError("message text must not be empty")
        if len(text_value.encode()) > 64 * 1024:
            raise ValueError("message text is too large")
        passphrase = typer.prompt("Local key passphrase", hide_input=True)
        identity = store.unlock(passphrase)
        await service.ensure_direct_base(identity)
        pending = store.prepare_send(recipient, text_value)
        try:
            message = await service.send(
                identity,
                recipient,
                text_value,
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
    skip: int = typer.Option(
        0,
        min=0,
        help="Skip messages from the start of the result set.",
        hidden=True,
    ),
    mark_read: bool = typer.Option(False, "--mark-read", help="Mark displayed messages read."),
) -> None:
    """Read the plain-message inbox."""

    async def action(
        service: MessageService, store: SecureStateStore
    ) -> tuple[list[ChatMessage], bool, int]:
        identity = AuthenticatedIdentity(store.load_public(), store.load_session())
        messages, has_more = await _inbox_with_sync(service, store, identity, limit, skip)
        _save_attachment_contexts(store, messages)
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
        typer.echo(f"More messages are available; use --skip {skip + limit}.")


@app.command("history")
def history(
    peer_did: Annotated[str, typer.Option("--with", help="Direct peer DID or handle.")],
    limit: int = typer.Option(50, min=1, max=100),
    skip: int = typer.Option(
        0,
        min=0,
        help="Skip messages from the start of the result set.",
        hidden=True,
    ),
) -> None:
    """Read plain-message history with one DID or handle."""
    settings = Settings.from_env()

    async def action(
        service: MessageService, store: SecureStateStore
    ) -> tuple[list[ChatMessage], bool]:
        identity = AuthenticatedIdentity(store.load_public(), store.load_session())
        peer = await resolve_peer_did(
            service.client,
            peer_did,
            identity.identity.handle,
            allow_private_network=settings.allow_private_network,
        )
        messages, has_more = await _history_with_sync(service, store, identity, peer, limit, skip)
        _save_attachment_contexts(store, messages)
        return messages, has_more

    messages, has_more = _run(action)
    _render(messages)
    if has_more:
        typer.echo(f"More messages are available; use --skip {skip + limit}.")


def _run(action: Callable[[MessageService, SecureStateStore], Awaitable[T]]) -> T:
    settings = Settings.from_env()
    store = SecureStateStore(settings.state_dir)

    async def invoke() -> T:
        async with httpx.AsyncClient(
            timeout=20.0, trust_env=False, verify=settings.tls_context()
        ) as client:
            return await action(MessageService(client, settings.message_service_url), store)

    try:
        return asyncio.run(invoke())
    except ValueError as exc:
        typer.echo(f"Invalid input: {exc}", err=True)
        raise typer.Exit(2) from None
    except JsonRpcFailure as exc:
        if exc.code in {401, 1401} or "unauthorized" in exc.message.lower():
            typer.echo("Session expired; run `awiki-lite id refresh-token`.", err=True)
        else:
            typer.echo(
                f"Message service rejected the request (JSON-RPC code {exc.code}).", err=True
            )
        raise typer.Exit(1) from None
    except (StateError, RuntimeError, httpx.HTTPError) as exc:
        typer.echo(f"Messaging failed: {exc}", err=True)
        raise typer.Exit(1) from None


async def _bootstrap_tracked_installation(
    service: MessageService,
    store: SecureStateStore,
    identity: AuthenticatedIdentity,
) -> None:
    installation = store.load_sync(identity.identity.did)
    if installation is None or installation.bootstrap is not None:
        return
    bootstrap = await service.bootstrap_sync(identity, installation.client_instance_id)
    store.complete_sync_bootstrap(installation, bootstrap)


async def _inbox_with_sync(
    service: MessageService,
    store: SecureStateStore,
    identity: AuthenticatedIdentity,
    limit: int,
    skip: int,
) -> tuple[list[ChatMessage], bool]:
    await _bootstrap_tracked_installation(service, store, identity)
    messages, has_more = await service.inbox(identity, limit, skip)
    if (
        skip == 0
        and not messages
        and not has_more
        and store.load_sync(identity.identity.did) is None
    ):
        await _bootstrap_legacy_installation(service, store, identity)
        return await service.inbox(identity, limit, skip)
    return messages, has_more


async def _history_with_sync(
    service: MessageService,
    store: SecureStateStore,
    identity: AuthenticatedIdentity,
    peer: str,
    limit: int,
    skip: int,
) -> tuple[list[ChatMessage], bool]:
    await _bootstrap_tracked_installation(service, store, identity)
    messages, has_more = await service.history(identity, peer, limit, skip)
    if (
        skip == 0
        and not messages
        and not has_more
        and store.load_sync(identity.identity.did) is None
    ):
        await _bootstrap_legacy_installation(service, store, identity)
        return await service.history(identity, peer, limit, skip)
    return messages, has_more


async def _bootstrap_legacy_installation(
    service: MessageService,
    store: SecureStateStore,
    identity: AuthenticatedIdentity,
) -> None:
    installation = store.initialize_sync(identity.identity.did)
    if installation.bootstrap is not None:
        return
    bootstrap = await service.bootstrap_sync(identity, installation.client_instance_id)
    store.complete_sync_bootstrap(installation, bootstrap)


def _render(messages: list[ChatMessage]) -> None:
    if not messages:
        typer.echo("No plain direct messages.")
        return
    for message in messages:
        timestamp = f"[{message.created_at}] " if message.created_at else ""
        if message.attachments:
            attachment = message.attachments[0]
            caption = f" caption={terminal_text(message.caption)}" if message.caption else ""
            typer.echo(
                f"{terminal_text(timestamp)}{terminal_text(message.sender_did)} -> "
                f"{terminal_text(message.target_did)}: "
                f"[attachment {terminal_text(attachment.filename)} "
                f"id={terminal_text(attachment.attachment_id)} "
                f"message={terminal_text(message.message_id)}]{caption}"
            )
        else:
            typer.echo(
                f"{terminal_text(timestamp)}{terminal_text(message.sender_did)} -> "
                f"{terminal_text(message.target_did)}: {terminal_text(message.text)}"
            )


def _save_attachment_contexts(store: SecureStateStore, messages: list[ChatMessage]) -> None:
    contexts = [
        AttachmentContext(
            message.message_id,
            message.sender_did,
            message.target_did,
            None,
            attachment,
        )
        for message in messages
        for attachment in message.attachments
    ]
    store.save_attachment_contexts(contexts)
