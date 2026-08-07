"""Top-level command assembly for AWiki Lite CLI."""

import typer

from awiki_lite_cli import __version__
from awiki_lite_cli.commands import attachments, direct, groups, identity, listener, session

app = typer.Typer(
    name="awiki-lite",
    help="Minimal AWiki client for registration, messaging, groups, and attachments.",
    no_args_is_help=True,
)
app.command("register")(identity.register)
app.add_typer(direct.app, name="dm")
app.add_typer(groups.app, name="group")
app.add_typer(attachments.app, name="attachment")
app.add_typer(listener.app, name="listener")
app.add_typer(session.app, name="session")


@app.callback(invoke_without_command=True)
def root(
    version: bool = typer.Option(
        False,
        "--version",
        help="Show the installed version and exit.",
        is_eager=True,
    ),
) -> None:
    """Run AWiki Lite CLI."""
    if version:
        typer.echo(__version__)
        raise typer.Exit()


def main() -> None:
    """Console-script entry point."""
    app()
