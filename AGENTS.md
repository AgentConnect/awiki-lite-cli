# Repository Guidelines

## Project Structure & Module Organization

This Python CLI uses a `src` layout:

- `src/awiki_lite_cli/commands/` contains thin Typer command adapters.
- `application/` defines workflows and outbound ports; `domain/` holds dependency-free values.
- `infrastructure/` owns ANP SDK, HTTP JSON-RPC, and persistence adapters.
- `tests/` mirrors behavior by layer; `docs/plan/` records architecture and delivery plans.

Keep dependencies flowing from commands to application to domain. Infrastructure implements application ports; domain code must not import Typer, HTTPX, filesystem APIs, or ANP.

## Build, Test, and Development Commands

The project uses Python 3.10+ and `uv`. The sibling SDK must exist at `../anp/anp`.

- `uv sync --group dev` installs the project and editable local ANP SDK.
- `uv run awiki-lite --help` checks the CLI entry point.
- `uv run pytest` runs the test suite.
- `uv run ruff check .` and `uv run ruff format --check .` enforce style.
- `uv run mypy src` performs strict type checking; `uv build` verifies packaging.

## Coding Style & Naming Conventions

Use four-space indentation, Ruff formatting, and complete type annotations. Name Python modules and functions with `snake_case`, classes with `PascalCase`, and CLI commands/flags with `kebab-case`. Keep modules small and public behavior documented. Do not duplicate identity, proof, or cryptographic logic already provided by the ANP SDK.

## Testing Guidelines

Use pytest files named `test_*.py` and test functions named `test_*`. Add tests with every feature or bug fix. Cover CLI exit codes, invalid arguments, JSON-RPC errors, timeouts, idempotent retries, and secret redaction. Mock unit-level network calls; reserve real `awiki.info` access for explicit integration tests. Keep fixtures deterministic and credential-free.

## Commit & Pull Request Guidelines

Use concise, imperative Conventional Commit subjects such as `feat: implement direct send` or `test: cover expired session`. Keep commits focused.

Pull requests must explain the problem and solution, list verification commands and results, and link issues. Include terminal output for user-visible CLI changes. Call out breaking command, configuration, protocol, or dependency changes.

## Security & Configuration

Never commit API keys, tokens, personal data, or generated credential files. Provide sanitized examples (for example, `.env.example`) and ensure local secrets are ignored. Validate paths and external input, and avoid printing secrets in logs or error messages.
