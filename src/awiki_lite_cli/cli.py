"""Top-level command assembly for AWiki Lite CLI."""

import typer

from awiki_lite_cli import __version__
from awiki_lite_cli.commands import groups, identity, listener, messages, session

app = typer.Typer(
    name="awiki-lite",
    help="Minimal AWiki client for registration, messaging, groups, and attachments.",
    no_args_is_help=True,
)
identity_app = typer.Typer(help="Manage the local AWiki identity.", no_args_is_help=True)
identity_app.command("register")(identity.register)
identity_app.command("refresh-token")(session.refresh)

runtime_app = typer.Typer(help="Manage the local receiving runtime.", no_args_is_help=True)
runtime_app.add_typer(listener.app, name="listener")

app.add_typer(identity_app, name="id")
app.add_typer(messages.app, name="msg")
app.add_typer(groups.app, name="group")
app.add_typer(runtime_app, name="runtime")
# Keep listener services installed by v0.2 runnable until users reinstall them.
app.add_typer(listener.app, name="listener", hidden=True)


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
