from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from awiki_lite_cli.cli import app
from awiki_lite_cli.config import Settings
from awiki_lite_cli.infrastructure.listener import (
    SYNC_SUBPROTOCOL,
    ListenerError,
    listen,
    parse_sync_changed,
    websocket_url,
)


def notification() -> str:
    return json.dumps(
        {
            "method": "sync.changed",
            "payload": {"domains": ["message", "group"], "reason": "message_available"},
            "sync": {
                "schema_version": 2,
                "account_scan_seq_hint": "42",
                "domain_versions": {"group": "7"},
            },
        }
    )


def test_websocket_url_matches_rust_listener_derivation() -> None:
    assert websocket_url("http://127.0.0.1:18080/") == "ws://127.0.0.1:18080/im/ws"
    assert websocket_url("https://example.test/base") == "wss://example.test/im/ws"


@pytest.mark.parametrize(
    "url",
    ["ftp://example.test", "https://user:secret@example.test", "not-a-url"],
)
def test_websocket_url_rejects_unsafe_endpoints(url: str) -> None:
    with pytest.raises(ListenerError, match="safe HTTP"):
        websocket_url(url)


def test_parse_sync_changed_returns_closed_projection() -> None:
    event = parse_sync_changed(notification())
    assert event.domains == ("message", "group")
    assert event.reason == "message_available"
    assert event.account_scan_seq_hint == "42"
    assert event.domain_versions == {"group": "7"}
    assert json.loads(event.to_json())["event"] == "sync.changed"


def test_parse_sync_changed_accepts_params_projection() -> None:
    value = json.loads(notification())
    value["params"] = value.pop("payload")

    event = parse_sync_changed(json.dumps(value))

    assert event.domains == ("message", "group")
    assert event.reason == "message_available"


@pytest.mark.parametrize(
    "value",
    [
        "not json",
        '{"method":"direct.incoming"}',
        '{"method":"sync.changed","payload":{},"sync":{}}',
        '{"method":"sync.changed","payload":{},"params":{},"sync":{}}',
        json.dumps(
            {
                "method": "sync.changed",
                "payload": {"domains": ["message"], "reason": "available"},
                "sync": {
                    "schema_version": 2,
                    "account_scan_seq_hint": "01",
                    "domain_versions": {},
                },
            }
        ),
    ],
)
def test_parse_sync_changed_rejects_invalid_or_legacy_frames(value: str) -> None:
    with pytest.raises(ListenerError):
        parse_sync_changed(value)


class FakeSocket:
    subprotocol: str | None = SYNC_SUBPROTOCOL

    def __init__(self, messages: list[str]) -> None:
        self.messages = iter(messages)

    def __aiter__(self) -> FakeSocket:
        return self

    async def __anext__(self) -> str:
        try:
            return next(self.messages)
        except StopIteration:
            raise StopAsyncIteration from None


class FakeConnection:
    def __init__(self, messages: list[str]) -> None:
        self.socket = FakeSocket(messages)

    async def __aenter__(self) -> FakeSocket:
        return self.socket

    async def __aexit__(self, *_args: object) -> None:
        return None


@pytest.mark.asyncio
async def test_listen_authenticates_negotiates_and_stops_after_one_event() -> None:
    calls: list[tuple[str, dict[str, Any]]] = []

    def connect_factory(endpoint: str, **options: Any) -> FakeConnection:
        calls.append((endpoint, options))
        return FakeConnection([notification()])

    events = []
    await listen(
        "https://example.test",
        "fixture-token",
        events.append,
        once=True,
        connect_factory=connect_factory,
    )

    endpoint, options = calls[0]
    assert endpoint == "wss://example.test/im/ws"
    assert options["additional_headers"]["Authorization"] == "Bearer fixture-token"
    assert options["subprotocols"] == [SYNC_SUBPROTOCOL]
    assert options["ping_interval"] == 60.0
    assert options["ping_timeout"] == 15.0
    assert len(events) == 1


@pytest.mark.asyncio
async def test_listen_requires_negotiated_v2_subprotocol() -> None:
    connection = FakeConnection([notification()])
    connection.socket.subprotocol = None

    def connect_factory(_endpoint: str, **_options: Any) -> FakeConnection:
        return connection

    with pytest.raises(ListenerError, match="did not select"):
        await listen(
            "https://example.test",
            "fixture-token",
            lambda _event: None,
            once=True,
            connect_factory=connect_factory,
        )


@pytest.mark.asyncio
async def test_clean_close_uses_growing_reconnect_backoff(monkeypatch) -> None:
    delays: list[float] = []

    def connect_factory(_endpoint: str, **_options: Any) -> FakeConnection:
        return FakeConnection([])

    async def stop_after_three(delay: float) -> None:
        delays.append(delay)
        if len(delays) == 3:
            raise asyncio.CancelledError

    monkeypatch.setattr("awiki_lite_cli.infrastructure.listener.asyncio.sleep", stop_after_three)
    with pytest.raises(asyncio.CancelledError):
        await listen(
            "https://example.test",
            "fixture-token",
            lambda _event: None,
            connect_factory=connect_factory,
        )
    assert delays == [1.0, 2.0, 4.0]


@pytest.mark.asyncio
async def test_valid_event_resets_reconnect_backoff(monkeypatch) -> None:
    delays: list[float] = []
    connections = iter([FakeConnection([]), FakeConnection([notification()])])

    def connect_factory(_endpoint: str, **_options: Any) -> FakeConnection:
        return next(connections)

    async def stop_after_two(delay: float) -> None:
        delays.append(delay)
        if len(delays) == 2:
            raise asyncio.CancelledError

    monkeypatch.setattr("awiki_lite_cli.infrastructure.listener.asyncio.sleep", stop_after_two)
    with pytest.raises(asyncio.CancelledError):
        await listen(
            "https://example.test",
            "fixture-token",
            lambda _event: None,
            connect_factory=connect_factory,
        )
    assert delays == [1.0, 1.0]


def test_json_listener_stdout_contains_json_lines_only(monkeypatch) -> None:
    class FakeStore:
        def load_public(self):  # type: ignore[no-untyped-def]
            return SimpleNamespace(did="did:wba:example.test:user:alice:e1_fixture")

        def load_session(self):  # type: ignore[no-untyped-def]
            return SimpleNamespace(access_token="fixture-token")

    async def emit_one(_url, _token, on_event, **_options):  # type: ignore[no-untyped-def]
        on_event(parse_sync_changed(notification()))

    monkeypatch.setattr(
        "awiki_lite_cli.commands.listener.Settings.from_env",
        lambda: Settings("https://example.test", "https://example.test", Path("state")),
    )
    monkeypatch.setattr(
        "awiki_lite_cli.commands.listener.SecureStateStore", lambda _path: FakeStore()
    )
    monkeypatch.setattr("awiki_lite_cli.commands.listener.listen", emit_one)
    result = CliRunner().invoke(app, ["listener", "run", "--once", "--json"])
    assert result.exit_code == 0
    assert [json.loads(line)["event"] for line in result.stdout.splitlines()] == ["sync.changed"]
    assert "Listening for" in result.stderr
