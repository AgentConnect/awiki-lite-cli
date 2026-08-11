# AWiki Lite CLI

AWiki Lite CLI is a deliberately small Python client for one local AWiki identity, ordinary
transport-protected direct/group messages, and single-file plain attachments. Version 0.2 does not
provide E2EE, MLS, object encryption, multiple devices, identity recovery, member removal,
multi-file messages, resumable transfer, or reliable local sync projection.

## Setup

Python 3.10+ and `uv` are required. The compatible ANP SDK is installed from PyPI.

```bash
uv sync --group dev
uv run awiki-lite --help
```

The default services are at `https://awiki.info`. Tests may explicitly override
`AWIKI_USER_SERVICE_URL`, `AWIKI_MESSAGE_SERVICE_URL`, and `AWIKI_LITE_STATE_DIR`.

## Commands

```bash
uv run awiki-lite id register --handle alice --phone +15555550100
uv run awiki-lite msg send --to 'did:wba:example.com:user:bob:e1_...' --text 'hello'
uv run awiki-lite msg inbox --limit 20
uv run awiki-lite msg history --with 'did:wba:example.com:user:bob:e1_...' --limit 20

uv run awiki-lite group create --name 'Project room'
uv run awiki-lite group add --group 'did:wba:...:group:...' --member 'did:wba:...:user:bob:...'
uv run awiki-lite msg send --group 'did:wba:...:group:...' --text 'hello group'
uv run awiki-lite group messages --group 'did:wba:...:group:...'

uv run awiki-lite msg send --to 'did:wba:...:user:bob:...' --file ./report.pdf
uv run awiki-lite msg send --group 'did:wba:...:group:...' --file ./report.pdf
uv run awiki-lite msg attachment download --message-id MESSAGE_ID --attachment-id ATTACHMENT_ID --output ./downloads
uv run awiki-lite id refresh-token

# Keep this foreground process running for real-time sync hints; Ctrl-C stops it.
uv run awiki-lite runtime listener run
# Emit one JSON event and exit, which is useful for scripts and connection checks.
uv run awiki-lite runtime listener run --once --json

# Install and manage the native platform service.
uv run awiki-lite runtime listener install
uv run awiki-lite runtime listener start
uv run awiki-lite runtime listener status --json
uv run awiki-lite runtime listener restart
uv run awiki-lite runtime listener stop
uv run awiki-lite runtime listener uninstall
```

For private text, avoid shell history and process arguments by using standard input:

```bash
printf '%s' 'private message' | uv run awiki-lite msg send --to 'did:wba:...' --stdin
printf '%s' 'private group message' | uv run awiki-lite msg send --group 'did:wba:...' --stdin
printf '%s' 'private caption' | uv run awiki-lite msg send --to 'did:wba:...' \
  --file ./report.pdf --stdin
```

DID arguments are exact `did:wba` identifiers; Handle lookup is not implemented. Refresh the
corresponding inbox/history/group messages before downloading so the CLI has an authenticated
Manifest context. Downloads never overwrite an existing file.

The listener follows the Rust CLI's `/im/ws` contract: it authenticates with the saved exact-device
Bearer token, requires the `awiki.sync.changed.v2` subprotocol, sends protocol Ping frames every 60
seconds, and reconnects with a bounded 1–30 second exponential delay. It emits change hints only;
use the existing inbox, history, or group commands to fetch authoritative content. The listener is
a foreground process and does not load private keys.

Service commands install the same listener under the native per-user manager: a systemd **user**
unit on Linux, a LaunchAgent on macOS, and an interactive logon task in Windows Task Scheduler.
Installation does not require root or an administrator. `start` installs the definition when
missing, while `restart` requires an existing installation. The generated definition captures the
active Python interpreter, state directory, and message-service URL, but never embeds the session
token, passphrase, or private key.
Reinstall the service after moving/removing the Python environment or changing those paths.

On Linux, the user service normally follows the user-manager lifetime. Keeping it active after
logout may require an administrator to enable lingering with `loginctl enable-linger USER`; the CLI
does not change this system policy. Logs are available through `journalctl --user -u
com.agentconnect.awiki-lite-listener.service`. macOS logs are written below the state directory's
`logs/` folder; Windows state is visible in Task Scheduler under `AgentConnect`.

## Key and Transfer Security

Private keys are passphrase-encrypted PKCS#8 PEM files; no Keychain is used, the passphrase is not
saved, and unlocked keys are not cached. On POSIX, state directories are mode `0700` and files are
mode `0600`; on Windows they use a protected current-user/SYSTEM ACL. Writes are atomic and reject
unsafe symlink targets.

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
