"""Structural checks for the first dual-language wave artifacts."""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.repo_contract

ROOT = Path(__file__).resolve().parents[1]


def test_cli_ux_contract_freezes_required_rules() -> None:
    text = (ROOT / "docs/contracts/cli-ux-v0.2.md").read_text(encoding="utf-8")
    assert "X-AWiki-Client-Version: awiki-cli/0714/0.2.0" in text
    assert "**not** derived from npm `0.1.0-dev`" in text
    assert r"^[a-z][a-z0-9_-]{2,31}$" in text
    assert "Length `>= 12`" in text
    assert "code == -32010" in text
    assert "feature == contact_verification" in text
    assert "reason == email_or_phone_verification_is_not_part_of_open_server_mvp" in text
    assert 'urlparse(AWIKI_USER_SERVICE_URL.rstrip("/")).hostname' in text
    assert "401 does not delete `session.json`" in text
    assert "--service-mode" in text
    assert "--state-dir" in text
    assert "--message-service-url" in text
    assert "Invalid input" in text


def test_local_state_contract_freezes_required_rules() -> None:
    text = (ROOT / "docs/contracts/local-state-v1.md").read_text(encoding="utf-8")
    assert "awiki-lite-cli-ts" in text
    assert "each implementation owns its state directory" in text
    assert "cross-runtime state sharing is unsupported" in text
    assert "proper-lockfile" in text
    assert "BEGIN ENCRYPTED PRIVATE KEY" in text
    assert "key-name only" in text
    assert "do not delete" in text
    assert "logs/" in text
    assert "Python `cryptography` is the source" in text


def test_ci_has_independent_language_jobs() -> None:
    raw = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "  python:" in raw
    assert "  typescript:" in raw
    assert "needs:" not in raw
    assert "Checkout sibling ANP SDK" not in raw
    assert "Build sibling ANP TypeScript SDK" not in raw
    assert "uv run pytest -m repo_contract tests/test_ts_wave1_contracts.py" in raw
    assert "pnpm install --frozen-lockfile" in raw
    assert "interop-lock" not in raw


def test_typescript_package_pins_published_sdk() -> None:
    package = (ROOT / "typescript/package.json").read_text(encoding="utf-8")
    lock = (ROOT / "typescript/pnpm-lock.yaml").read_text(encoding="utf-8")
    assert '"name": "@awiki/lite-cli"' in package
    assert '"awiki-lite-ts"' in package
    assert '"packageManager": "pnpm@9.15.0"' in package
    assert '"@awiki/anp-typescript-sdk": "0.9.3"' in package
    assert "file:../../anp/anp/typescript/ts_sdk" not in package
    assert "'@awiki/anp-typescript-sdk@0.9.3':" in lock
    assert "specifier: 0.9.3" in lock
    assert "sha512-yFvcVndo9341Va91" in lock
    assert "@anp/typescript-sdk" not in lock
    assert "file:../../anp/anp/typescript/ts_sdk" not in lock
    assert (ROOT / "typescript/src/cli.ts").is_file()
    assert not (ROOT / "package.json").exists()
    assert not (ROOT / "pnpm-workspace.yaml").exists()
    assert not (ROOT / "README.zh.md").exists()


def test_python_packaging_is_unchanged() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'packages = ["src/awiki_lite_cli"]' in pyproject
    assert (ROOT / "src/awiki_lite_cli/cli.py").is_file()


def test_read_commands_never_infer_sync_migration_from_empty_pages() -> None:
    contract = (ROOT / "docs/contracts/v0.1-wire-contract.md").read_text(encoding="utf-8")
    python_direct = (ROOT / "src/awiki_lite_cli/commands/direct.py").read_text(encoding="utf-8")
    typescript_direct = (ROOT / "typescript/src/commands/direct.ts").read_text(encoding="utf-8")
    assert "never infer sync state from an empty inbox/history page" in contract
    assert "bootstrap_sync" not in python_direct
    assert "bootstrapSync" not in typescript_direct


def test_combined_runner_only_orchestrates_independent_suites() -> None:
    runner = (ROOT / "scripts/test_all.py").read_text(encoding="utf-8")
    assert '[sys.executable, "-m", "pytest"]' in runner
    assert '[pnpm, "test"]' in runner
    assert "live" not in runner.lower()
    assert not (ROOT / "tests/test_cross_runtime_cli.py").exists()
    assert not (ROOT / "typescript/tests/interop").exists()
