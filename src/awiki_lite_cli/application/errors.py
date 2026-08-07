"""Application-facing transport and protocol failures."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class JsonRpcFailure(RuntimeError):
    code: int
    message: str
    data: Any = None

    def __str__(self) -> str:
        return f"JSON-RPC request failed with code {self.code}"


class ProtocolResponseError(RuntimeError):
    """A remote response violated the closed protocol or application schema."""
