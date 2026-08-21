"""Ordinary transport-protected Group commands."""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Awaitable, Callable
from typing import Annotated, TypeVar

import httpx
import typer

from awiki_lite_cli.application.groups import GroupWorkflow
from awiki_lite_cli.config import Settings
from awiki_lite_cli.domain.models import GroupMember, GroupMessage, GroupSummary
from awiki_lite_cli.infrastructure.attachment_manifest import parse_manifest
from awiki_lite_cli.infrastructure.group_service import GroupService
from awiki_lite_cli.infrastructure.peer_resolver import resolve_peer_did
from awiki_lite_cli.infrastructure.rpc import JsonRpcFailure
from awiki_lite_cli.infrastructure.state import SecureStateStore, StateError
from awiki_lite_cli.presentation import terminal_text

app = typer.Typer(help="Create and use transport-protected ordinary groups.")
T = TypeVar("T")


@app.command("create")
def create(name: Annotated[str, typer.Option("--name")]) -> None:
    """Create a private admin-add group."""

    async def action(
        workflow: GroupWorkflow, store: SecureStateStore, _client: httpx.AsyncClient
    ) -> GroupSummary:
        passphrase = typer.prompt("Local key passphrase", hide_input=True)
        return await workflow.create(store.unlock(passphrase), name)

    group = _run(action)
    typer.echo(f"Created {group.display_name}: {group.group_did}")


@app.command("list")
def list_groups(
    limit: int = typer.Option(50, min=1, max=100),
    cursor: str | None = typer.Option(None, hidden=True),
) -> None:
    """List ordinary groups visible to the current identity."""
    groups, next_cursor = _run(
        lambda workflow, _store, _client: workflow.list_groups(limit, cursor)
    )
    _render_groups(groups)
    if next_cursor:
        typer.echo(f"Next cursor: {next_cursor}")


@app.command("get")
def info(group_did: Annotated[str, typer.Option("--group")]) -> None:
    """Show one ordinary group's profile and current membership summary."""
    group = _run(lambda workflow, _store, _client: workflow.info(group_did))
    _render_groups([group])


@app.command("members")
def members(
    group_did: Annotated[str, typer.Option("--group")],
    limit: int = typer.Option(100, min=1, max=100),
    cursor: str | None = typer.Option(None, hidden=True),
) -> None:
    """List active membership records for one group."""
    rows, next_cursor = _run(
        lambda workflow, _store, _client: workflow.members(group_did, limit, cursor)
    )
    _render_members(rows)
    if next_cursor:
        typer.echo(f"Next cursor: {next_cursor}")


@app.command("add")
def add(
    group_did: Annotated[str, typer.Option("--group")],
    member_did: Annotated[str, typer.Option("--member", help="Member DID or handle.")],
) -> None:
    """Add one DID or handle as a member."""
    settings = Settings.from_env()

    async def action(
        workflow: GroupWorkflow, store: SecureStateStore, client: httpx.AsyncClient
    ) -> str:
        member = await resolve_peer_did(
            client,
            member_did,
            store.load_public().handle,
            allow_private_network=settings.allow_private_network,
        )
        passphrase = typer.prompt("Local key passphrase", hide_input=True)
        return await workflow.add(store.unlock(passphrase), group_did, member)

    added = _run(action)
    typer.echo(f"Added {added} to {group_did}")


def send(
    group_did: str,
    text: str | None = typer.Argument(None),
    stdin: bool = typer.Option(False, "--stdin", help="Read message text from standard input."),
) -> None:
    """Send one plain text message to an ordinary group."""
    if stdin and text is not None:
        typer.echo("Invalid input: TEXT and --stdin are mutually exclusive", err=True)
        raise typer.Exit(2)
    text_value = sys.stdin.read() if stdin else text
    if text_value is None:
        text_value = typer.prompt("Message")

    async def action(
        workflow: GroupWorkflow, store: SecureStateStore, _client: httpx.AsyncClient
    ) -> GroupMessage:
        passphrase = typer.prompt("Local key passphrase", hide_input=True)
        return await workflow.send(store.unlock(passphrase), group_did, text_value)

    message = _run(action)
    typer.echo(f"Sent {message.message_id} to {message.group_did}")


@app.command("messages")
def messages(
    group_did: Annotated[str, typer.Option("--group")],
    limit: int = typer.Option(50, min=1, max=100),
    since_seq: int | None = typer.Option(None, "--since-seq", min=0, hidden=True),
) -> None:
    """Read ordinary Group Base messages after an optional group-local sequence."""
    rows, next_since_seq = _run(
        lambda workflow, _store, _client: workflow.messages(group_did, limit, since_seq)
    )
    _render_messages(rows)
    if next_since_seq is not None:
        typer.echo(f"Next since-seq: {next_since_seq}")


def _run(
    action: Callable[[GroupWorkflow, SecureStateStore, httpx.AsyncClient], Awaitable[T]],
) -> T:
    settings = Settings.from_env()
    store = SecureStateStore(settings.state_dir)

    async def invoke() -> T:
        async with httpx.AsyncClient(
            timeout=20.0,
            trust_env=False,
            follow_redirects=False,
            verify=settings.tls_context(),
        ) as client:
            workflow = GroupWorkflow(
                GroupService(client, settings.message_service_url), store, parse_manifest
            )
            return await action(workflow, store, client)

    try:
        return asyncio.run(invoke())
    except ValueError as exc:
        typer.echo(f"Invalid input: {exc}", err=True)
        raise typer.Exit(2) from None
    except JsonRpcFailure as exc:
        if exc.code in {401, 1401} or "unauthorized" in exc.message.lower():
            typer.echo("Session expired; run `awiki-lite id refresh-token`.", err=True)
        else:
            typer.echo(f"Group service rejected the request (JSON-RPC code {exc.code}).", err=True)
        raise typer.Exit(1) from None
    except (StateError, RuntimeError, httpx.HTTPError) as exc:
        typer.echo(f"Group operation failed: {exc}", err=True)
        raise typer.Exit(1) from None


def _render_groups(groups: list[GroupSummary]) -> None:
    if not groups:
        typer.echo("No ordinary groups.")
        return
    for group in groups:
        role = f" role={group.my_role}" if group.my_role else ""
        typer.echo(
            f"{terminal_text(group.display_name)} ({terminal_text(group.group_did)}) "
            f"members={group.member_count}{terminal_text(role)}"
        )


def _render_members(members: list[GroupMember]) -> None:
    if not members:
        typer.echo("No group members.")
        return
    for member in members:
        typer.echo(
            f"{terminal_text(member.agent_did)} role={terminal_text(member.role)} "
            f"status={terminal_text(member.status)}"
        )


def _render_messages(messages: list[GroupMessage]) -> None:
    if not messages:
        typer.echo("No ordinary group messages.")
        return
    for message in messages:
        if message.message_type == "text":
            typer.echo(
                f"[{message.group_event_seq}] {terminal_text(message.sender_did)}: "
                f"{terminal_text(message.content)}"
            )
        else:
            attachment, caption = parse_manifest(message.content)
            suffix = f" caption={terminal_text(caption)}" if caption else ""
            typer.echo(
                f"[{message.group_event_seq}] {terminal_text(message.sender_did)}: [attachment] "
                f"{terminal_text(attachment.filename)} "
                f"id={terminal_text(attachment.attachment_id)} "
                f"message={terminal_text(message.message_id)}{suffix}"
            )
