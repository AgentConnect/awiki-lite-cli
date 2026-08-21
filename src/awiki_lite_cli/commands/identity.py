"""Identity registration command."""

from __future__ import annotations

import asyncio

import httpx
import typer

from awiki_lite_cli.application.registration import RegistrationWorkflow
from awiki_lite_cli.config import Settings
from awiki_lite_cli.infrastructure.anp_sdk import generate_identity
from awiki_lite_cli.infrastructure.message_service import MessageService
from awiki_lite_cli.infrastructure.rpc import JsonRpcFailure
from awiki_lite_cli.infrastructure.state import SecureStateStore, StateError
from awiki_lite_cli.infrastructure.user_service import UserService


def register(
    handle: str | None = typer.Option(None, help="Handle local-part to register."),
    phone: str | None = typer.Option(None, help="Phone number used for OTP verification."),
) -> None:
    """Register one local AWiki identity."""
    typer.echo("Warning: losing this state directory or passphrase permanently loses the identity.")
    handle_value = handle or typer.prompt("Handle")
    phone_value = phone or typer.prompt("Phone")
    try:
        identity = asyncio.run(_register(handle_value, phone_value))
    except ValueError as exc:
        typer.echo(f"Invalid input: {exc}", err=True)
        raise typer.Exit(2) from None
    except JsonRpcFailure as exc:
        typer.echo(
            f"Registration service rejected the request (JSON-RPC code {exc.code}).", err=True
        )
        raise typer.Exit(1) from None
    except (StateError, RuntimeError, httpx.HTTPError) as exc:
        typer.echo(f"Registration failed: {exc}", err=True)
        raise typer.Exit(1) from None
    typer.echo(f"Registered {identity.handle} ({identity.did})")


async def _register(handle: str, phone: str):  # type: ignore[no-untyped-def]
    settings = Settings.from_env()
    async with httpx.AsyncClient(
        timeout=20.0, trust_env=False, verify=settings.tls_context()
    ) as client:
        workflow = RegistrationWorkflow(
            UserService(client, settings.user_service_url),
            MessageService(client, settings.message_service_url),
            SecureStateStore(settings.state_dir),
            settings.message_service_url,
            generate_identity,
        )
        canonical_handle, canonical_phone, domain, otp_required = await workflow.begin(
            handle, phone
        )
        if otp_required:
            otp = typer.prompt("OTP", hide_input=True)
        else:
            typer.echo("Open Server does not perform phone verification; continuing locally.")
            otp = "000000"
        passphrase = typer.prompt(
            "New local key passphrase", hide_input=True, confirmation_prompt=True
        )
        return await workflow.finish(canonical_handle, canonical_phone, domain, otp, passphrase)
