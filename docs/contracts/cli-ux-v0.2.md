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
| `id register` | `--handle`, `--phone` | Print the unrecoverable-state warning first |
| `id init-sync` | none | Explicit opt-in for older identities; warn that `tail_only` may omit earlier messages |
| `id refresh-token` | none | One-shot DID HTTP signature `get_me` |
| `msg send` | exactly one of `--to PEER` / `--group GROUP_DID`; optional `--text`, `--file`, hidden `--stdin` | `PEER` is a DID or handle; text and `--stdin` are mutually exclusive; `--file` changes text to the attachment caption |
| `msg inbox` | `--limit` 1–100, hidden `--skip`, `--mark-read` | Default is read-only |
| `msg history` | `--with PEER`, `--limit`, hidden `--skip` | `PEER` is a DID or handle |
| `msg attachment download` | `--message-id`, `--attachment-id`, `--output` | Never overwrite |
| `group create` | `--name` | Private admin-add; max 500 members |
| `group list` | `--limit`, hidden `--cursor` | Opaque cursor is echoed unchanged |
| `group get` | `--group GROUP_DID` | |
| `group members` | `--group GROUP_DID`, `--limit`, hidden `--cursor` | |
| `group add` | `--group GROUP_DID`, `--member PEER` | `PEER` is a DID or handle; role is fixed `member` |
| `group messages` | `--group GROUP_DID`, `--limit`, hidden `--since-seq` | Attachment rows use Manifest rendering |
| `runtime listener run` | `--once`, `--json`; hidden `--service-mode`, `--state-dir`, `--message-service-url`, `--ca-bundle` | |
| `runtime listener install` / `start` / `stop` / `restart` / `status` / `uninstall` | `status --json` | |

The visible root command groups are exactly `id`, `msg`, `group`, and `runtime`.
An old top-level `listener` alias may remain hidden so existing service definitions keep running.

## Input validation

| Field | Rule |
|---|---|
| Handle | Strip leading `@`, lowercase, then `^[a-z][a-z0-9_-]{2,31}$`. Do **not** use WNS `validateLocalPart`. |
| Phone | Strip spaces, then `^\+?[0-9]{7,20}$` |
| OTP | `^[0-9]{4,10}$` |
| Passphrase | Length `>= 12` **and** `strip()` is non-blank. Register prompts twice. No `--passphrase`. No passphrase environment variable. TypeScript uses `@inquirer/password` and requires a TTY. |
| Registration domain | `urlparse(AWIKI_USER_SERVICE_URL.rstrip("/")).hostname`. **Not** the Message Service host and **not** a hard-coded `awiki.info`. Missing hostname is `Invalid input` (exit 2). |

Peer arguments accept an exact `did:wba` identifier, a full handle, or a bare handle with an
optional leading `@`. Bare handles use the current identity's domain. Handle lookup is stateless;
it validates the authoritative WNS response and the resolved DID document. Exact DIDs bypass
lookup.

## Exit codes

| Condition | Code | stderr |
|---|---|---|
| Success | 0 | One human-readable line on stdout |
| Invalid argument / `ValueError` | 2 | `Invalid input: ...` |
| Unregistered, local state, network, `RuntimeError` | 1 | `Registration failed` / `Messaging failed` / equivalent |
| JSON-RPC error | 1 | `... rejected the request (JSON-RPC code {n}).` Do **not** echo `message` or `data` |
| HTTP 401 / JSON-RPC 1401 / `"unauthorized"` | 1 | `Session expired; run \`<executable> id refresh-token\`.` |

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
| `AWIKI_USER_SERVICE_URL` | `https://awiki.ai` |
| `AWIKI_MESSAGE_SERVICE_URL` | `https://awiki.ai` |
| `AWIKI_LITE_STATE_DIR` | See `local-state-v1.md`; each implementation must use its own directory |
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
`runtime listener run --json` emits `SyncChanged.to_json()` fields with sorted keys.
Do not add a default JSON mode to `msg inbox`.

## RPC

Timeout 20s. No proxy. TypeScript uses `redirect: "error"` on every outbound
HTTP/WebSocket, including `id register`, `id refresh-token`, and `msg`. That is an
intentional tightening, not Python bug-compatibility.
