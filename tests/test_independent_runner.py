from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from awiki_lite_cli.application.attachments import AttachmentWorkflow
from awiki_lite_cli.application.groups import GroupWorkflow
from awiki_lite_cli.infrastructure.state import SecureStateStore
from scripts import remote_group_attachment_e2e, test_all


def test_combined_runner_uses_only_independent_commands(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    calls: list[tuple[str, list[str], Path, dict[str, str]]] = []

    def run(label: str, command: list[str], cwd: Path, env: dict[str, str]) -> int:
        calls.append((label, command, cwd, env))
        return 0

    monkeypatch.setattr(test_all, "_run", run)
    monkeypatch.setattr(test_all.shutil, "which", lambda *_args, **_kwargs: "pnpm")

    assert test_all.main() == 0
    assert [command[1:] for _label, command, _cwd, _env in calls] == [
        ["-m", "pytest"],
        ["test"],
    ]


def test_combined_runner_runs_both_suites_before_reporting_failure(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    statuses = iter([1, 0])
    labels: list[str] = []

    def run(label: str, _command: list[str], _cwd: Path, _env: dict[str, str]) -> int:
        labels.append(label)
        return next(statuses)

    monkeypatch.setattr(test_all, "_run", run)
    monkeypatch.setattr(test_all.shutil, "which", lambda *_args, **_kwargs: "pnpm")

    assert test_all.main() == 1
    assert labels == ["Python independent tests", "TypeScript independent tests"]


@pytest.mark.asyncio
async def test_remote_group_e2e_workflows_follow_production_signatures(tmp_path: Path) -> None:
    store = SecureStateStore(tmp_path / "state")
    async with httpx.AsyncClient() as client:
        assert isinstance(
            remote_group_attachment_e2e._attachments(client, store), AttachmentWorkflow
        )
        assert isinstance(remote_group_attachment_e2e._groups(client, store), GroupWorkflow)
