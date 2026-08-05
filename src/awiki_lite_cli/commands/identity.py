import typer

from awiki_lite_cli.commands._status import not_implemented


def register(
    handle: str | None = typer.Option(None, help="Handle local-part to register."),
    phone: str | None = typer.Option(None, help="Phone number used for OTP verification."),
) -> None:
    """Register one local AWiki identity."""
    del handle, phone
    not_implemented("Identity registration")
