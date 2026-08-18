"""Hold or contend the Lite state lock for TypeScript interop tests."""

from __future__ import annotations

import argparse
import hashlib
import time
from pathlib import Path

from awiki_lite_cli.infrastructure.state import PendingOperationError, SecureStateStore


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("hold", "prepare", "check"))
    parser.add_argument("state_dir")
    parser.add_argument("--timeout", type=float, default=2.0)
    args = parser.parse_args()
    store = SecureStateStore(Path(args.state_dir))
    if args.mode == "hold":
        with store.lock():
            print("LOCKED", flush=True)
            time.sleep(args.timeout)
        print("RELEASED", flush=True)
        return 0
    if args.mode == "check":
        import fcntl
        import os

        store.initialize()
        path = Path(args.state_dir) / ".lock"
        path.touch(mode=0o600, exist_ok=True)
        fd = os.open(path, os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("BLOCKED", flush=True)
            return 2
        finally:
            os.close(fd)
        print("FREE", flush=True)
        return 0
    digest = hashlib.sha256(b"other-command").hexdigest()
    try:
        store.prepare_operation(
            "group.create", "did:wba:example.com:group:other", digest, needs_message_id=False
        )
    except PendingOperationError as exc:
        print(f"CONFLICT:{exc}", flush=True)
        return 2
    print("PREPARED", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
