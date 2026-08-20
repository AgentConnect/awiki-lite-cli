"""Run the independent Python and TypeScript test suites with one command."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(label: str, command: list[str], cwd: Path, env: dict[str, str]) -> int:
    print(f"\n=== {label} ===", flush=True)
    try:
        result = subprocess.run(command, cwd=cwd, env=env, check=False)
    except OSError as exc:
        print(f"Unable to start {label}: {exc}", file=sys.stderr, flush=True)
        return 127
    return result.returncode


def main() -> int:
    env = os.environ.copy()

    python_status = _run(
        "Python independent tests",
        [sys.executable, "-m", "pytest"],
        ROOT,
        env,
    )

    pnpm = shutil.which("pnpm", path=env.get("PATH"))
    if pnpm is None:
        print("\n=== TypeScript independent tests ===", flush=True)
        print("Unable to start TypeScript tests: pnpm is not installed", file=sys.stderr)
        typescript_status = 127
    else:
        typescript_status = _run(
            "TypeScript independent tests",
            [pnpm, "test"],
            ROOT / "typescript",
            env,
        )

    print("\n=== Independent test summary ===", flush=True)
    print(f"Python: {'passed' if python_status == 0 else f'failed ({python_status})'}")
    print(
        "TypeScript: " + ("passed" if typescript_status == 0 else f"failed ({typescript_status})")
    )
    return 0 if python_status == 0 and typescript_status == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
