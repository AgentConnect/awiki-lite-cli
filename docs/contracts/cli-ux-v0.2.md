# CLI UX contract v0.2

This document freezes the user-visible command surface shared by Python
`awiki-lite` and TypeScript `awiki-lite-ts`. It is a written contract, not
implementation. Implementers must not invent a second flag set.

Allowed implementation deltas: executable basename, `--version` label, M1
default state directory name, and TypeScript's documented stricter
`redirect: "error"` on all outbound HTTP.

## Client identifier

Every outbound HTTP and WebSocket request sends:

```text
X-AWiki-Client-Version: awiki-cli/0714/0.2.0
```

The token is frozen. It is **not** derived from npm `0.1.0-dev` or from the
Python package version string at runtime. Do not send `awiki-cli/0714/0.1.0`.
Language does not appear in the token.

## Commands and flags

| Command | Flags / arguments | Notes |
|---|---|---|
| `register` | `--handle`, `--phone` | Print the unrecoverable-state warning first |
| `dm send` | `<DID> [TEXT] [--stdin]` | `TEXT` and `--stdin` are mutually exclusive; empty text is rejected; max 64KiB |
| `dm inbox` | `--limit` 1–100, `--skip`, `--mark-read` | Default is read-only |
| `dm history` | `<DID> [--limit] [--skip]` | |
| `group create` | `NAME` | Private admin-add; max 500 members |
| `group list` | `--limit`, `--cursor` | Opaque cursor is echoed unchanged |
| `group info` | `GROUP_DID` | |
| `group members` | `GROUP_DID [--limit] [--cursor]` | |
| `group add` | `GROUP_DID MEMBER_DID` | Role is fixed `member` |
| `group send` | `GROUP_DID [TEXT] [--stdin]` | Same `--stdin` exclusivity as `dm send` |
| `group messages` | `GROUP_DID [--limit] [--since-seq]` | Attachment rows use Manifest rendering |
| `attachment send` | `FILE --to DID` **xor** `FILE --group GROUP_DID`; `--caption` / `--caption-stdin` | |
| `attachment download` | `MESSAGE_ID ATTACHMENT_ID --output PATH` | Never overwrite |
| `session refresh` | none | One-shot DID HTTP signature `get_me` |
| `listener run` | `--once`, `--json`; hidden `--service-mode`, `--state-dir`, `--message-service-url` | |
| `listener install` / `start` / `stop` / `restart` / `status` / `uninstall` | `status --json` | |

M1 TypeScript help must not list `dm`, `group`, `attachment`, or `listener`
until those commands ship.

## Input validation

| Field | Rule |
|---|---|
| Handle | Strip leading `@`, lowercase, then `^[a-z][a-z0-9_-]{2,31}$`. Do **not** use WNS `validateLocalPart`. |
| Phone | Strip spaces, then `^\+?[0-9]{7,20}$` |
| OTP | `^[0-9]{4,10}$` |
| Passphrase | Length `>= 12` **and** `strip()` is non-blank. Register prompts twice. No `--passphrase`. No passphrase environment variable. TypeScript uses `@inquirer/password` and requires a TTY. |
| Registration domain | `urlparse(AWIKI_USER_SERVICE_URL.rstrip("/")).hostname`. **Not** the Message Service host and **not** a hard-coded `awiki.info`. Missing hostname is `Invalid input` (exit 2). |

DID arguments are exact `did:wba` identifiers. Handle lookup is not implemented.

## Exit codes

| Condition | Code | stderr |
|---|---|---|
| Success | 0 | One human-readable line on stdout |
| Invalid argument / `ValueError` | 2 | `Invalid input: ...` |
| Unregistered, local state, network, `RuntimeError` | 1 | `Registration failed` / `Messaging failed` / equivalent |
| JSON-RPC error | 1 | `... rejected the request (JSON-RPC code {n}).` Do **not** echo `message` or `data` |
| HTTP 401 / JSON-RPC 1401 / `"unauthorized"` | 1 | `Session expired; run \`${basename(argv[0])} session refresh\`.` |

**401 does not delete `session.json`.** The process only prints the refresh
hint. Commander will not do this mapping automatically; TypeScript must
centralize it.

`--version`: Python remains exactly `0.2.0`. TypeScript prints
`0.1.0-dev (typescript)` until the first public npm, then `0.1.0 (typescript)`.

## Environment variables

Loaded only from the process environment. No dotenv. Trailing `/` is stripped
from service URLs. `AWIKI_LITE_CA_BUNDLE` must name a readable file.
`AWIKI_LITE_ALLOW_PRIVATE_NETWORK` is on only for `1`, `true`, or `yes`
(case-insensitive).

| Variable | Default |
|---|---|
| `AWIKI_USER_SERVICE_URL` | `https://awiki.info` |
| `AWIKI_MESSAGE_SERVICE_URL` | `https://awiki.info` |
| `AWIKI_LITE_STATE_DIR` | See `local-state-v1.md` (language-specific default until lock interop) |
| `AWIKI_LITE_CA_BUNDLE` | unset |
| `AWIKI_LITE_ALLOW_PRIVATE_NETWORK` | off |

## Open Server OTP exemption

Skip a real OTP **only** when all three conjuncts hold:

```text
code == -32010
AND feature == contact_verification
AND reason == email_or_phone_verification_is_not_part_of_open_server_mvp
```

Then continue locally with OTP `000000`. Missing any conjunct must not skip
real verification.

## Rendering

Human output uses the Python `presentation.terminal_text` rules.
`listener run --json` emits `SyncChanged.to_json()` fields with sorted keys.
Do not add a default JSON mode to `dm inbox`.

## RPC

Timeout 20s. No proxy. TypeScript uses `redirect: "error"` on every outbound
HTTP/WebSocket, including `register`, `session refresh`, and `dm`. That is an
intentional tightening, not Python bug-compatibility.
