"""Authenticated WebSocket listener for exact-device sync hints."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable, Mapping
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed, InvalidStatus

from awiki_lite_cli import CLIENT_IDENTIFIER

SYNC_SUBPROTOCOL = "awiki.sync.changed.v2"
PING_INTERVAL_SECONDS = 60.0
PING_TIMEOUT_SECONDS = 15.0
RECONNECT_BASE_SECONDS = 1.0
RECONNECT_MAX_SECONDS = 30.0
MAX_MESSAGE_BYTES = 1024 * 1024
SYNC_TOKEN = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")


class ListenerError(RuntimeError):
    """Safe listener failure that never contains credentials or remote payloads."""


class ListenerAuthenticationError(ListenerError):
    """The saved exact-device session is no longer authorized."""


@dataclass(frozen=True, slots=True)
class SyncChanged:
    """Closed, non-secret projection of an ``awiki.sync.changed.v2`` notification."""

    domains: tuple[str, ...]
    reason: str
    account_scan_seq_hint: str | None
    domain_versions: Mapping[str, str]

    def to_json(self) -> str:
        return json.dumps(
            {
                "event": "sync.changed",
                "domains": list(self.domains),
                "reason": self.reason,
                "account_scan_seq_hint": self.account_scan_seq_hint,
                "domain_versions": dict(self.domain_versions),
            },
            separators=(",", ":"),
            sort_keys=True,
        )


Connect = Callable[..., AbstractAsyncContextManager[ClientConnection]]


def websocket_url(service_base_url: str) -> str:
    """Derive the frozen ``/im/ws`` endpoint used by the Rust CLI."""
    parsed = urlsplit(service_base_url)
    scheme = {"http": "ws", "https": "wss"}.get(parsed.scheme.lower())
    if scheme is None or not parsed.netloc or parsed.username or parsed.password:
        raise ListenerError("message service URL is not a safe HTTP(S) endpoint")
    return urlunsplit((scheme, parsed.netloc, "/im/ws", "", ""))


def parse_sync_changed(raw: str | bytes) -> SyncChanged:
    """Validate one negotiated v2 frame without retaining arbitrary remote fields."""
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ListenerError("websocket notification is not valid JSON") from exc
    if not isinstance(value, dict) or value.get("method") != "sync.changed":
        raise ListenerError("websocket sent an unsupported notification")
    payload = value.get("payload")
    sync = value.get("sync")
    if not isinstance(payload, dict) or not isinstance(sync, dict):
        raise ListenerError("sync.changed notification has an invalid shape")
    domains = payload.get("domains")
    reason = payload.get("reason")
    schema_version = sync.get("schema_version")
    scan_seq = sync.get("account_scan_seq_hint")
    versions = sync.get("domain_versions")
    if (
        not isinstance(domains, list)
        or not domains
        or any(not isinstance(item, str) or SYNC_TOKEN.fullmatch(item) is None for item in domains)
        or not isinstance(reason, str)
        or SYNC_TOKEN.fullmatch(reason) is None
        or schema_version != 2
        or (scan_seq is not None and not _canonical_decimal(scan_seq))
        or not isinstance(versions, dict)
        or any(
            not isinstance(key, str) or not key or not _canonical_decimal(version)
            for key, version in versions.items()
        )
    ):
        raise ListenerError("sync.changed notification has invalid fields")
    return SyncChanged(tuple(domains), reason, scan_seq, dict(versions))


async def listen(
    service_base_url: str,
    access_token: str,
    on_event: Callable[[SyncChanged], None],
    *,
    once: bool = False,
    connect_factory: Connect = connect,
    on_reconnect: Callable[[float], None] | None = None,
) -> None:
    """Consume sync hints until cancelled, reconnecting with bounded backoff."""
    endpoint = websocket_url(service_base_url)
    delay = RECONNECT_BASE_SECONDS
    while True:
        try:
            async with connect_factory(
                endpoint,
                additional_headers={
                    "Authorization": f"Bearer {access_token}",
                    "X-AWiki-Client-Version": CLIENT_IDENTIFIER,
                },
                subprotocols=[SYNC_SUBPROTOCOL],
                ping_interval=PING_INTERVAL_SECONDS,
                ping_timeout=PING_TIMEOUT_SECONDS,
                open_timeout=15.0,
                close_timeout=10.0,
                max_size=MAX_MESSAGE_BYTES,
                max_queue=128,
                proxy=None,
            ) as socket:
                if socket.subprotocol != SYNC_SUBPROTOCOL:
                    raise ListenerError("websocket server did not select awiki.sync.changed.v2")
                async for raw in socket:
                    on_event(parse_sync_changed(raw))
                    # A valid application notification proves that the session was useful,
                    # rather than merely completing a handshake before immediately closing.
                    delay = RECONNECT_BASE_SECONDS
                    if once:
                        return
        except InvalidStatus as exc:
            status = exc.response.status_code
            if status in {401, 403}:
                raise ListenerAuthenticationError("websocket session is unauthorized") from None
        except (ConnectionClosed, OSError, asyncio.TimeoutError):
            pass
        # A clean close is also a disconnected session and must be rate limited.
        await _retry(delay, on_reconnect)
        delay = min(delay * 2, RECONNECT_MAX_SECONDS)


async def _retry(delay: float, notify: Callable[[float], None] | None) -> None:
    if notify is not None:
        notify(delay)
    await asyncio.sleep(delay)


def _canonical_decimal(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value.isascii()
        and value.isdigit()
        and (value == "0" or not value.startswith("0"))
    )
