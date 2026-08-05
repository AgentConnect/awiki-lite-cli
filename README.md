# AWiki Lite CLI

AWiki Lite CLI is a deliberately small Python client for one local AWiki identity, ordinary
transport-protected direct/group messages, and single-file plain attachments. Version 0.2 does not
provide E2EE, MLS, object encryption, multiple devices, recovery, member removal, multi-file
messages, resumable transfer, daemon mode, WebSockets, or reliable sync v2.

## Setup

Python 3.10+, `uv`, and the sibling ANP SDK at `../anp/anp` are required.

```bash
uv sync --group dev
uv run awiki-lite --help
```

The default services are at `https://awiki.info`. Tests may explicitly override
`AWIKI_USER_SERVICE_URL`, `AWIKI_MESSAGE_SERVICE_URL`, and `AWIKI_LITE_STATE_DIR`.

## Commands

```bash
uv run awiki-lite register --handle alice --phone +15555550100
uv run awiki-lite dm send 'did:wba:example.com:user:bob:e1_...' 'hello'
uv run awiki-lite dm inbox --limit 20
uv run awiki-lite dm history 'did:wba:example.com:user:bob:e1_...' --limit 20

uv run awiki-lite group create 'Project room'
uv run awiki-lite group add 'did:wba:...:group:...' 'did:wba:...:user:bob:...'
uv run awiki-lite group send 'did:wba:...:group:...' 'hello group'
uv run awiki-lite group messages 'did:wba:...:group:...' --since-seq 0

uv run awiki-lite attachment send ./report.pdf --to 'did:wba:...:user:bob:...'
uv run awiki-lite attachment send ./report.pdf --group 'did:wba:...:group:...'
uv run awiki-lite attachment download MESSAGE_ID ATTACHMENT_ID --output ./downloads
```

DID arguments are exact `did:wba` identifiers; Handle lookup is not implemented. Refresh the
corresponding inbox/history/group messages before downloading so the CLI has an authenticated
Manifest context. Downloads never overwrite an existing file.

## Key and Transfer Security

Private keys are passphrase-encrypted PKCS#8 PEM files; no Keychain is used, the passphrase is not
saved, and unlocked keys are not cached. State directories are mode `0700`; token, pending, context,
and key files are mode `0600` and use atomic writes with symlink checks.

Unknown-result retries retain stable IDs, timestamps, a proof nonce, lifecycle stage, target DID,
and content fingerprints—but no message/caption plaintext, proof signature, private key, upload
header, commit token, or download ticket. Uploads accept one regular non-symlink file and verify it
through one file descriptor. Downloads use sender-DID-bound one-time tickets, reject redirects,
stream into a `0600` temporary file, verify size and SHA-256, and publish atomically without
overwrite.

Losing the state directory or passphrase permanently loses control of the identity because v0.2
has no recovery. At-rest encryption does not protect a compromised user/root session, keylogger,
weak passphrase, or process memory while a key is unlocked.

## Development Gates

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy src
uv run pytest
uv build
```

The remote E2E is destructive, explicit opt-in, and restricted to the reviewed AWiki testing
target. It uses two dedicated test phone scopes and irreversibly deletes their account, group,
message, and object data before and after execution:

```bash
uv run python scripts/remote_group_attachment_e2e.py --target awiki-info-testing
```

The v0.2 implementation plan and execution ledger are in
[`docs/plan/v2-groups-attachments.md`](docs/plan/v2-groups-attachments.md). The v0.1 record remains
in [`docs/plan/v1-registration-direct.md`](docs/plan/v1-registration-direct.md).
