"""Ordinary transport-protected Group commands."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import TypeVar

import httpx
import typer

from awiki_lite_cli.application.groups import GroupWorkflow
from awiki_lite_cli.config import Settings
from awiki_lite_cli.domain.models import GroupMember, GroupMessage, GroupSummary
from awiki_lite_cli.infrastructure.group_service import GroupService
from awiki_lite_cli.infrastructure.rpc import JsonRpcFailure
from awiki_lite_cli.infrastructure.state import SecureStateStore, StateError

app = typer.Typer(help="Create and use transport-protected ordinary groups.")
T = TypeVar("T")


@app.command("create")
def create(name: str) -> None:
    """Create a private admin-add group."""

    async def action(workflow: GroupWorkflow, store: SecureStateStore) -> GroupSummary:
        passphrase = typer.prompt("Local key passphrase", hide_input=True)
        return await workflow.create(store.unlock(passphrase), name)

    group = _run(action)
    typer.echo(f"Created {group.display_name}: {group.group_did}")


@app.command("list")
def list_groups(
    limit: int = typer.Option(20, min=1, max=100),
    cursor: str | None = typer.Option(None),
) -> None:
    """List ordinary groups visible to the current identity."""
    groups, next_cursor = _run(lambda workflow, _store: workflow.list_groups(limit, cursor))
    _render_groups(groups)
    if next_cursor:
        typer.echo(f"Next cursor: {next_cursor}")


@app.command("info")
def info(group_did: str) -> None:
    """Show one ordinary group's profile and current membership summary."""
    group = _run(lambda workflow, _store: workflow.info(group_did))
    _render_groups([group])


@app.command("members")
def members(
    group_did: str,
    limit: int = typer.Option(20, min=1, max=100),
    cursor: str | None = typer.Option(None),
) -> None:
    """List active membership records for one group."""
    rows, next_cursor = _run(lambda workflow, _store: workflow.members(group_did, limit, cursor))
    _render_members(rows)
    if next_cursor:
        typer.echo(f"Next cursor: {next_cursor}")


@app.command("add")
def add(group_did: str, member_did: str) -> None:
    """Add one exact DID as a member."""

    async def action(workflow: GroupWorkflow, store: SecureStateStore) -> str:
        passphrase = typer.prompt("Local key passphrase", hide_input=True)
        return await workflow.add(store.unlock(passphrase), group_did, member_did)

    added = _run(action)
    typer.echo(f"Added {added} to {group_did}")


@app.command("send")
def send(group_did: str, text: str) -> None:
    """Send one plain text message to an ordinary group."""

    async def action(workflow: GroupWorkflow, store: SecureStateStore) -> GroupMessage:
        passphrase = typer.prompt("Local key passphrase", hide_input=True)
        return await workflow.send(store.unlock(passphrase), group_did, text)

    message = _run(action)
    typer.echo(f"Sent {message.message_id} to {message.group_did}")


@app.command("messages")
def messages(
    group_did: str,
    limit: int = typer.Option(20, min=1, max=100),
    since_seq: int | None = typer.Option(None, "--since-seq", min=0),
) -> None:
    """Read ordinary Group Base messages after an optional group-local sequence."""
    rows, next_since_seq = _run(
        lambda workflow, _store: workflow.messages(group_did, limit, since_seq)
    )
    _render_messages(rows)
    if next_since_seq is not None:
        typer.echo(f"Next since-seq: {next_since_seq}")


def _run(action: Callable[[GroupWorkflow, SecureStateStore], Awaitable[T]]) -> T:
    settings = Settings.from_env()
    store = SecureStateStore(settings.state_dir)

    async def invoke() -> T:
        async with httpx.AsyncClient(
            timeout=20.0, trust_env=False, follow_redirects=False
        ) as client:
            workflow = GroupWorkflow(GroupService(client, settings.message_service_url), store)
            return await action(workflow, store)

    try:
        return asyncio.run(invoke())
    except ValueError as exc:
        typer.echo(f"Invalid input: {exc}", err=True)
        raise typer.Exit(2) from None
    except JsonRpcFailure as exc:
        if exc.code in {401, 1401} or "unauthorized" in exc.message.lower():
            store.clear_session()
            typer.echo("Session expired; register again in this v0.2 client.", err=True)
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
        typer.echo(f"{group.display_name} ({group.group_did}) members={group.member_count}{role}")


def _render_members(members: list[GroupMember]) -> None:
    if not members:
        typer.echo("No group members.")
        return
    for member in members:
        typer.echo(f"{member.agent_did} role={member.role} status={member.status}")


def _render_messages(messages: list[GroupMessage]) -> None:
    if not messages:
        typer.echo("No ordinary group messages.")
        return
    for message in messages:
        if message.message_type == "text":
            typer.echo(f"[{message.group_event_seq}] {message.sender_did}: {message.content}")
        else:
            typer.echo(
                f"[{message.group_event_seq}] {message.sender_did}: [attachment] "
                f"{message.message_id}"
            )
