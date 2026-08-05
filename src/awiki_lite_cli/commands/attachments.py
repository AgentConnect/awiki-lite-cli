from pathlib import Path
from typing import Annotated

import typer

from awiki_lite_cli.commands._status import not_implemented

app = typer.Typer(help="Send and download transport-protected attachments.")


@app.command("send")
def send(
    file: Path,
    recipient_did: str | None = typer.Option(None, "--to", help="Direct recipient DID."),
    group_did: str | None = typer.Option(None, "--group", help="Target group DID."),
) -> None:
    """Upload a file and send its manifest to exactly one target."""
    if (recipient_did is None) == (group_did is None):
        raise typer.BadParameter("provide exactly one of --to or --group")
    del file, recipient_did, group_did
    not_implemented("Attachment sending")


@app.command("download")
def download(
    message_id: str,
    attachment_id: str,
    output: Annotated[Path, typer.Option("--output", help="Output directory.")] = Path("."),
) -> None:
    """Download and verify one attachment from a message."""
    del message_id, attachment_id, output
    not_implemented("Attachment download")
