import typer

from awiki_lite_cli.commands._status import not_implemented

app = typer.Typer(help="Create and use transport-protected groups.")


@app.command("create")
def create(name: str) -> None:
    """Create a private, attachment-capable group."""
    del name
    not_implemented("Group creation")


@app.command("add")
def add(group_did: str, member_did: str) -> None:
    """Add one DID to a group."""
    del group_did, member_did
    not_implemented("Group member addition")


@app.command("send")
def send(group_did: str, text: str) -> None:
    """Send a plain text message to a group."""
    del group_did, text
    not_implemented("Group message sending")


@app.command("messages")
def messages(group_did: str, limit: int = typer.Option(20, min=1, max=100)) -> None:
    """Read messages from a group."""
    del group_did, limit
    not_implemented("Group message history")
