"""Keep the Python CLI aligned with the shared Python/TypeScript command contract."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from typer.main import get_command

from awiki_lite_cli.cli import app

CONTRACT_PATH = Path(__file__).parent / "fixtures" / "cli-command-contract.json"


def _contract() -> dict[str, dict[str, list[str]]]:
    value: Any = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return cast(dict[str, dict[str, list[str]]], value)


def _command(path: str) -> Any:
    current = get_command(app)
    for part in path.split():
        assert hasattr(current, "commands")
        current = current.commands[part]
    return current


def test_python_command_tree_matches_shared_contract() -> None:
    for path, expected in _contract()["tree"].items():
        command = _command(path)
        assert hasattr(command, "commands")
        actual = [name for name, child in command.commands.items() if not child.hidden]
        assert set(actual) == set(expected), path or "<root>"


def test_python_public_options_match_shared_contract() -> None:
    for path, expected in _contract()["options"].items():
        actual = {
            option
            for parameter in _command(path).params
            if hasattr(parameter, "opts") and not parameter.hidden
            for option in parameter.opts
            if option.startswith("--")
        }
        assert set(expected) <= actual, path
