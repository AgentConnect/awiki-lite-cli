"""Write or load an encrypted PKCS#8 PEM for TypeScript interop tests."""

from __future__ import annotations

import argparse
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("write", "load"))
    parser.add_argument("path")
    parser.add_argument("passphrase")
    args = parser.parse_args()
    path = Path(args.path)
    if args.mode == "write":
        key = ed25519.Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(args.passphrase.encode()),
        )
        path.write_bytes(pem)
        print(pem.decode(), end="")
        return 0
    pem = path.read_bytes()
    serialization.load_pem_private_key(pem, password=args.passphrase.encode())
    print("UNLOCKED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
