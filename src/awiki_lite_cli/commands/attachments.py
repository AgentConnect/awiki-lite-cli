"""Plain single-attachment commands."""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import Annotated, Any, TypeVar

import httpx
import typer

from awiki_lite_cli.application.attachments import AttachmentWorkflow
from awiki_lite_cli.config import Settings
from awiki_lite_cli.domain.models import AuthenticatedIdentity
from awiki_lite_cli.infrastructure.attachment_manifest import normalize_caption
from awiki_lite_cli.infrastructure.attachment_service import (
    AttachmentService,
    prepare_download_destination,
    prepare_file,
)
from awiki_lite_cli.infrastructure.group_service import GroupService
from awiki_lite_cli.infrastructure.message_service import MessageService
from awiki_lite_cli.infrastructure.peer_resolver import resolve_peer_did
from awiki_lite_cli.infrastructure.rpc import JsonRpcFailure
from awiki_lite_cli.infrastructure.state import SecureStateStore, StateError

app = typer.Typer(help="Send and download one plain transport-protected attachment.")
T = TypeVar("T")


@app.command("send")
def send(
    file: Path,
    recipient_did: str | None = typer.Option(None, "--to", help="Direct peer DID or handle."),
    group_did: str | None = typer.Option(None, "--group"),
    caption: str | None = typer.Option(None, "--caption"),
    caption_stdin: bool = typer.Option(
        False, "--caption-stdin", help="Read the optional caption from standard input."
    ),
) -> None:
    """Upload and send one file to exactly one direct or ordinary Group target."""
    if (recipient_did is None) == (group_did is None):
        typer.echo("Invalid input: choose exactly one of --to and --group", err=True)
        raise typer.Exit(2)
    if caption_stdin and caption is not None:
        typer.echo("Invalid input: --caption and --caption-stdin are mutually exclusive", err=True)
        raise typer.Exit(2)
    caption_value = sys.stdin.read() if caption_stdin else caption
    passphrase = typer.prompt("Local key passphrase", hide_input=True)
    message_id, attachment_id = _run_send(file, recipient_did, group_did, caption_value, passphrase)
    typer.echo(f"Sent attachment {attachment_id} in message {message_id}")


@app.command("download")
def download(
    message_id: Annotated[str, typer.Option("--message-id")],
    attachment_id: Annotated[str, typer.Option("--attachment-id")],
    output: Annotated[Path, typer.Option("--output")],
) -> None:
    """Download one attachment from a previously refreshed authenticated message."""
    result = _run_download(message_id, attachment_id, output)
    typer.echo(f"Downloaded attachment to {result}")


def _run_send(
    file: Path,
    recipient_did: str | None,
    group_did: str | None,
    caption: str | None,
    passphrase: str,
) -> tuple[str, str]:
    settings = Settings.from_env()
    store = SecureStateStore(settings.state_dir)

    async def invoke() -> tuple[str, str]:
        async with httpx.AsyncClient(
            timeout=20.0, trust_env=False, follow_redirects=False
        ) as client:
            identity = store.unlock(passphrase)
            resolved_recipient = (
                await resolve_peer_did(client, recipient_did, identity.identity.handle)
                if recipient_did is not None
                else None
            )
            workflow = AttachmentWorkflow(
                AttachmentService(client, settings.message_service_url),
                MessageService(client, settings.message_service_url),
                GroupService(client, settings.message_service_url),
                store,
                normalize_caption,
                prepare_file,
                prepare_download_destination,
            )
            return await workflow.send(
                identity,
                file,
                recipient_did=resolved_recipient,
                group_did=group_did,
                caption=caption,
            )

    return _invoke_with_errors(store, invoke)


def _run_download(message_id: str, attachment_id: str, output: Path) -> Path:
    settings = Settings.from_env()
    store = SecureStateStore(settings.state_dir)

    async def invoke() -> Path:
        async with httpx.AsyncClient(
            timeout=20.0, trust_env=False, follow_redirects=False
        ) as client:
            workflow = AttachmentWorkflow(
                AttachmentService(client, settings.message_service_url),
                MessageService(client, settings.message_service_url),
                GroupService(client, settings.message_service_url),
                store,
                normalize_caption,
                prepare_file,
                prepare_download_destination,
            )
            return await workflow.download(
                AuthenticatedIdentity(store.load_public(), store.load_session()),
                message_id,
                attachment_id,
                output,
            )

    return _invoke_with_errors(store, invoke)


def _invoke_with_errors(store: SecureStateStore, invoke: Callable[[], Coroutine[Any, Any, T]]) -> T:
    try:
        return asyncio.run(invoke())
    except ValueError as exc:
        typer.echo(f"Invalid input: {exc}", err=True)
        raise typer.Exit(2) from None
    except JsonRpcFailure as exc:
        if exc.code in {401, 1401} or "unauthorized" in exc.message.lower():
            typer.echo("Session expired; run `awiki-lite id refresh-token`.", err=True)
        else:
            typer.echo(f"Attachment operation was rejected (JSON-RPC code {exc.code}).", err=True)
        raise typer.Exit(1) from None
    except (StateError, RuntimeError, httpx.HTTPError) as exc:
        typer.echo(f"Attachment operation failed: {exc}", err=True)
        raise typer.Exit(1) from None
