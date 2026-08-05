import typer

from awiki_lite_cli.commands._status import not_implemented

app = typer.Typer(help="Send and read transport-protected direct messages.")


@app.command("send")
def send(recipient_did: str, text: str) -> None:
    """Send a plain text message to one DID."""
    del recipient_did, text
    not_implemented("Direct message sending")


@app.command("inbox")
def inbox(limit: int = typer.Option(20, min=1, max=100)) -> None:
    """Read the local direct-message inbox."""
    del limit
    not_implemented("Direct inbox")


@app.command("history")
def history(peer_did: str, limit: int = typer.Option(20, min=1, max=100)) -> None:
    """Read direct-message history with one DID."""
    del peer_did, limit
    not_implemented("Direct message history")
