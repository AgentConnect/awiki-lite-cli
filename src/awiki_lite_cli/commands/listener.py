"""Long-running WebSocket listener commands."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated

import typer

from awiki_lite_cli.config import Settings
from awiki_lite_cli.infrastructure.listener import (
    ListenerAuthenticationError,
    ListenerError,
    SyncChanged,
    listen,
    websocket_url,
)
from awiki_lite_cli.infrastructure.listener_service import (
    ListenerServiceError,
    ListenerServiceStatus,
    service_manager,
)
from awiki_lite_cli.infrastructure.state import SecureStateStore, StateError

app = typer.Typer(help="Run the authenticated WebSocket receiving helper.")


@app.command("run")
def run(
    once: bool = typer.Option(False, help="Exit after the first valid notification."),
    json_output: bool = typer.Option(False, "--json", help="Emit stable JSON Lines."),
    service_mode: bool = typer.Option(False, "--service-mode", hidden=True),
    state_dir: Annotated[Path | None, typer.Option("--state-dir", hidden=True)] = None,
    message_service_url: Annotated[
        str | None, typer.Option("--message-service-url", hidden=True)
    ] = None,
) -> None:
    """Listen in the foreground until interrupted with Ctrl-C."""
    settings = Settings.from_env()
    selected_state_dir = state_dir or settings.state_dir
    selected_service_url = message_service_url or settings.message_service_url
    store = SecureStateStore(selected_state_dir)
    try:
        identity = store.load_public()
        session = store.load_session()
        typer.echo(
            f"Listening for {identity.did} on {websocket_url(selected_service_url)}",
            err=json_output,
        )

        def render(event: SyncChanged) -> None:
            if json_output:
                typer.echo(event.to_json())
                return
            domains = ",".join(event.domains)
            sequence = (
                f" scan-seq={event.account_scan_seq_hint}"
                if event.account_scan_seq_hint is not None
                else ""
            )
            typer.echo(f"Changed domains={domains} reason={event.reason}{sequence}")

        def reconnect(delay: float) -> None:
            typer.echo(f"Connection lost; retrying in {delay:g}s.", err=True)

        asyncio.run(
            listen(
                selected_service_url,
                session.access_token,
                render,
                once=once,
                on_reconnect=reconnect,
            )
        )
    except KeyboardInterrupt:
        typer.echo("Listener stopped.", err=json_output)
    except ListenerAuthenticationError:
        typer.echo(
            "Listener session expired; run `awiki-lite id refresh-token`, then restart it.",
            err=True,
        )
        if service_mode:
            return
        raise typer.Exit(1) from None
    except StateError as exc:
        typer.echo(f"Listener failed: {exc}", err=True)
        if service_mode:
            return
        raise typer.Exit(1) from None
    except ListenerError as exc:
        typer.echo(f"Listener failed: {exc}", err=True)
        raise typer.Exit(1) from None


@app.command("install")
def install() -> None:
    """Install the listener with the current user's platform service manager."""
    _service_action("install", require_identity=True)


@app.command("start")
def start() -> None:
    """Install if needed and start the listener service."""
    _service_action("start", require_identity=True)


@app.command("stop")
def stop() -> None:
    """Stop the listener service without removing its definition."""
    _service_action("stop")


@app.command("restart")
def restart() -> None:
    """Restart an installed listener service."""
    _service_action("restart", require_identity=True)


@app.command("status")
def status(json_output: bool = typer.Option(False, "--json", help="Emit stable JSON.")) -> None:
    """Show whether the platform listener service is installed and running."""
    _service_action("status", json_output=json_output)


@app.command("uninstall")
def uninstall() -> None:
    """Stop and remove the listener service definition."""
    _service_action("uninstall")


def _service_action(
    action: str,
    *,
    require_identity: bool = False,
    json_output: bool = False,
) -> None:
    settings = Settings.from_env()
    store = SecureStateStore(settings.state_dir)
    try:
        if require_identity:
            store.load_public()
            store.load_session()
        manager = service_manager(settings.state_dir, settings.message_service_url)
        operation = getattr(manager, action)
        result: ListenerServiceStatus = operation()
    except (ListenerServiceError, StateError) as exc:
        typer.echo(f"Listener service failed: {exc}", err=True)
        raise typer.Exit(1) from None
    _render_service_status(result, json_output)


def _render_service_status(status: ListenerServiceStatus, json_output: bool) -> None:
    value = {
        "platform": status.platform,
        "installed": status.installed,
        "running": status.running,
        "state": status.state,
    }
    if json_output:
        typer.echo(json.dumps(value, separators=(",", ":"), sort_keys=True))
        return
    typer.echo(
        f"Listener service platform={status.platform} installed={str(status.installed).lower()} "
        f"running={str(status.running).lower()} state={status.state}"
    )
