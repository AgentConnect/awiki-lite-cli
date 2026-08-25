"""Shared CLI integer parsers that emit the frozen Invalid input contract."""

from __future__ import annotations

import re
from collections.abc import Callable

import typer


def _range_text(minimum: int, maximum: int | None) -> str:
    return f"at least {minimum}" if maximum is None else f"between {minimum} and {maximum}"


def _parse_bounded(value: object, minimum: int, maximum: int | None, field: str) -> int:
    message = f"{field} must be an integer {_range_text(minimum, maximum)}"
    if isinstance(value, bool) or (
        not isinstance(value, int) and not re.fullmatch(r"-?[0-9]+", str(value))
    ):
        typer.echo(f"Invalid input: {message}", err=True)
        raise typer.Exit(2)
    parsed = value if isinstance(value, int) else int(str(value))
    if parsed < minimum or (maximum is not None and parsed > maximum):
        typer.echo(f"Invalid input: {message}", err=True)
        raise typer.Exit(2)
    return parsed


def bounded_int(minimum: int, maximum: int | None, field: str) -> Callable[[object], int]:
    """Parse one integer option and exit 2 with `Invalid input:` on failure."""

    def parser(value: object) -> int:
        return _parse_bounded(value, minimum, maximum, field)

    return parser


def optional_bounded_int(
    minimum: int, maximum: int | None, field: str
) -> Callable[[object], int | None]:
    """Parse an optional integer option; omit the flag to keep `None`."""

    required = bounded_int(minimum, maximum, field)

    def parser(value: object) -> int | None:
        if value is None:
            return None
        return required(value)

    return parser


LIMIT_1_100 = bounded_int(1, 100, "limit")
SKIP_GE_0 = bounded_int(0, None, "skip")
SINCE_SEQ_GE_0 = optional_bounded_int(0, None, "since-seq")
