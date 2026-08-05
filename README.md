# AWiki Lite CLI

AWiki Lite CLI is a deliberately small Python client for one local AWiki identity and
transport-protected direct text messages. Version 0.1 does not implement groups, attachments,
E2EE, multiple devices, recovery, daemon mode, or WebSockets.

## Setup

Python 3.10+, `uv`, and the sibling ANP SDK at `../anp/anp` are required.

```bash
uv sync --group dev
uv run awiki-lite --help
```

The default service is `https://awiki.info`. Tests may explicitly override
`AWIKI_USER_SERVICE_URL`, `AWIKI_MESSAGE_SERVICE_URL`, and `AWIKI_LITE_STATE_DIR`.

## Usage

```bash
uv run awiki-lite register --handle alice --phone +15555550100
uv run awiki-lite dm send 'did:wba:example.com:user:bob:e1_...' 'hello'
uv run awiki-lite dm inbox --limit 20
uv run awiki-lite dm inbox --mark-read
uv run awiki-lite dm history 'did:wba:example.com:user:bob:e1_...' --limit 20
```

Registration and message signing prompt for secrets without echoing them. Recipient lookup is not
implemented; `dm send` and `dm history` require an exact DID.

## Local Key Security

Private keys are stored as passphrase-encrypted PKCS#8 PEM files. The CLI does not use Keychain or
another system credential store, does not save the passphrase, and does not cache unlocked keys.
The state directory is mode `0700`; state, token, pending, and key files are mode `0600` and use
atomic writes with symlink checks.

If a send times out with an unknown result, the CLI retains only its IDs, timestamps, proof nonce,
recipient DID, and a SHA-256 content fingerprint in `pending-send.json`. Repeating the exact command
rebuilds the same signed request; different sends are refused until that result is resolved. Message
plaintext and proof signatures are not stored in this file.

Keep the state directory and passphrase safe. Losing either permanently loses control of the
identity because v0.1 has no recovery. This protects keys at rest from ordinary local users and
offline file copies; it does not protect a compromised user/root session, keylogger, weak
passphrase, or process-memory inspection while a key is unlocked.

## Development Gates

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy src
uv run pytest
uv build
```

The destructive remote E2E is opt-in and restricted to the reviewed AWiki testing target. It
requires the sibling service/system-test workspaces and their dedicated test credentials, and it
deletes data belonging to those two test phone scopes before and after execution:

```bash
uv run python scripts/remote_e2e.py --target awiki-info-testing
```

The implementation plan and live execution ledger are in
[`docs/plan/v1-registration-direct.md`](docs/plan/v1-registration-direct.md).
