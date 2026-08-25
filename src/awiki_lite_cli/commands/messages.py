"""Rust-CLI-compatible message command surface."""

from pathlib import Path
from typing import Annotated

import typer

from awiki_lite_cli.commands import attachments, direct, groups

app = typer.Typer(help="Send and read transport-protected messages.", no_args_is_help=True)
attachment_app = typer.Typer(help="Download message attachments.", no_args_is_help=True)


@app.command("send")
def send(
    recipient_did: Annotated[
        str | None, typer.Option("--to", help="Direct peer DID or handle.")
    ] = None,
    group_did: Annotated[str | None, typer.Option("--group")] = None,
    text: Annotated[str | None, typer.Option("--text")] = None,
    file: Annotated[Path | None, typer.Option("--file")] = None,
    stdin: bool = typer.Option(
        False,
        "--stdin",
        help="Read the message text or attachment caption from standard input.",
        hidden=True,
    ),
) -> None:
    """Send a direct or ordinary group text message or single attachment."""
    if (recipient_did is None) == (group_did is None):
        typer.echo("Invalid input: choose exactly one of --to and --group", err=True)
        raise typer.Exit(2)
    if file is not None:
        attachments.send(file, recipient_did, group_did, text, stdin)
        return
    if recipient_did is not None:
        direct.send(recipient_did, text, stdin)
        return
    assert group_did is not None
    groups.send(group_did, text, stdin)


app.command("inbox")(direct.inbox)
app.command("history")(direct.history)
attachment_app.command("download")(attachments.download)
app.add_typer(attachment_app, name="attachment")
