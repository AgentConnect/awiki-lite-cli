# Repository Guidelines

## Project Structure & Module Organization

This Python CLI uses a `src` layout:

- `src/awiki_lite_cli/commands/` contains thin Typer command adapters.
- `application/` defines workflows and outbound ports; `domain/` holds dependency-free values.
- `infrastructure/` owns ANP SDK, HTTP JSON-RPC, and persistence adapters.
- `tests/` mirrors behavior by layer; `docs/plan/` records architecture and delivery plans.

Keep dependencies flowing from commands to application to domain. Infrastructure implements application ports; domain code must not import Typer, HTTPX, filesystem APIs, or ANP.

## Build, Test, and Development Commands

The project uses Python 3.10+ and `uv`.

- `uv sync --group dev` installs the project and development dependencies.
- `uv run awiki-lite --help` checks the CLI entry point.
- `uv run pytest` runs the test suite.
- `uv run ruff check .` and `uv run ruff format --check .` enforce style.
- `uv run mypy src` performs strict type checking; `uv build` verifies packaging.

A parallel TypeScript package lives in `typescript/` (`@awiki/lite-cli`, binary `awiki-lite-ts`) and uses the same `id`/`msg`/`group`/`runtime` command syntax as Python. There is no root npm/pnpm workspace. The ANP TypeScript SDK is pinned to the published npm package `@awiki/anp-typescript-sdk@0.9.5`; contributors do not need a sibling ANP checkout.

```bash
(cd typescript && pnpm install && pnpm test && pnpm exec awiki-lite-ts --help)
```

`uv run pytest` is the Python-only default suite. `pnpm test` is the TypeScript-only default suite
and must not spawn Python or `uv`.
`uv run python scripts/test_all.py` runs the two independent default suites in sequence without
enabling remote tests; it continues to the second suite after a failure and returns nonzero if
either suite fails.

Python and TypeScript use separate default state directories but share the native listener service
name. Do not point both implementations at the same `AWIKI_LITE_STATE_DIR`; shared local state is
unsupported. Install only one native listener and reinstall it when switching implementations.

Use Node 20.11+ and pnpm 9.15.x (`packageManager` in `typescript/package.json`). `uv build` remains a Python-only wheel of `src/awiki_lite_cli`.

## Coding Style & Naming Conventions

Use four-space indentation, Ruff formatting, and complete type annotations. Name Python modules and functions with `snake_case`, classes with `PascalCase`, and CLI commands/flags with `kebab-case`. Keep modules small and public behavior documented. Do not duplicate identity, proof, or cryptographic logic already provided by the ANP SDK.

## Testing Guidelines

Use pytest files named `test_*.py` and test functions named `test_*`. Add tests with every feature or bug fix. Cover CLI exit codes, invalid arguments, JSON-RPC errors, timeouts, idempotent retries, and secret redaction. Mock unit-level network calls; reserve real service access for explicit integration tests. Keep fixtures deterministic and credential-free.

`tests/fixtures/cli-command-contract.json` is the shared public CLI contract. The root Python test
and `typescript/tests/cli.test.ts` must each validate their own real command tree against it whenever
command names or public options change. The test suites do not start the other implementation.

## Commit & Pull Request Guidelines

Use concise, imperative Conventional Commit subjects such as `feat: implement direct send` or `test: cover expired session`. Keep commits focused.

Pull requests must explain the problem and solution, list verification commands and results, and link issues. Include terminal output for user-visible CLI changes. Call out breaking command, configuration, protocol, or dependency changes.

## Security & Configuration

Never commit API keys, tokens, personal data, or generated credential files. Provide sanitized examples (for example, `.env.example`) and ensure local secrets are ignored. Validate paths and external input, and avoid printing secrets in logs or error messages.
