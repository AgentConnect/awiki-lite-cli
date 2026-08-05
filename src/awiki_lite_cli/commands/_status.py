import typer


def not_implemented(feature: str) -> None:
    """Report scaffold status without pretending a remote operation succeeded."""
    typer.echo(
        f"{feature} is part of the v1 implementation plan and is not implemented in this scaffold.",
        err=True,
    )
    raise typer.Exit(code=2)
