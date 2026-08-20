# Local state contract v1

Python `awiki-lite` and TypeScript `awiki-lite-ts` use equivalent field names
where practical, but each implementation owns its state directory. Pointing
both implementations at the same directory is unsupported.

## Default directories

Resolved with `platformdirs` 4.x `user_state_path(appname, "AgentConnect")`.

| OS | Python `appname=awiki-lite-cli` | TypeScript `appname=awiki-lite-cli-ts` |
|---|---|---|
| Linux | `${XDG_STATE_HOME:-$HOME/.local/state}/awiki-lite-cli` | same algorithm, directory name `awiki-lite-cli-ts` |
| macOS | `~/Library/Application Support/awiki-lite-cli` (appauthor ignored) | `~/Library/Application Support/awiki-lite-cli-ts` |
| Windows | `%LOCALAPPDATA%\AgentConnect\awiki-lite-cli` | `%LOCALAPPDATA%\AgentConnect\awiki-lite-cli-ts` |

The TypeScript appname is permanently `awiki-lite-cli-ts` so its files remain
separate from Python state. `AWIKI_LITE_STATE_DIR` may relocate either
implementation, but it must not point both implementations at the same
directory.

## Layout

```text
<state-dir>/                    # POSIX 0700; reject symlink roots
├── .lock                       # 0600
├── identity.json               # five fields; presence = committed
├── session.json                # only {"access_token"}; 401 does not delete
├── pending-registration.json
├── pending-send.json           # schema_version=2 plus legacy unversioned
├── attachment-contexts.json    # schema_version=1, at most 500
├── logs/                       # created only by the macOS LaunchAgent installer
└── secrets/
    ├── root-key.pem
    ├── device-signing.pem
    └── device-agreement.pem
```

`identity.json` fields: `did`, `handle`, `verification_method`, `device_id`,
`did_document`.

Do not create the TypeScript IM client's plaintext `awiki-im.json`.

`logs/` is not created by `initialize()` on Linux or Windows.

## Passphrase and PKCS#8

- Minimum 12 characters and non-blank after `strip()`.
- Disk files must be `BEGIN ENCRYPTED PRIVATE KEY`.
- Python writes `PrivateFormat.PKCS8` + `BestAvailableEncryption(passphrase)`.
  The cipher name is **not** frozen; Python `cryptography` is the source of
  truth.
- TypeScript reads with `crypto.createPrivateKey({ key, format: "pem", passphrase })`.
- Each implementation must be able to load the encrypted keys it writes.
  Do not freeze a cipher name such as `aes-256-cbc` in the contract.

## Process lock

Python takes an OS advisory lock on `<state-dir>/.lock`: POSIX
`fcntl.flock(..., LOCK_EX)`; Windows writes `\0` if the file is empty, then
`msvcrt.locking(..., LK_LOCK, 1)` on the first byte.

TypeScript uses its own advisory lock for its state directory. If the file is
empty (`st_size == 0`), write `\0` and `fsync` before locking. Do not create
`.lock.lock`.

`proper-lockfile` is not `flock` and must not be used.

Each runtime must enforce locking within its own state directory. Lock
compatibility between Python and TypeScript is not a requirement because
cross-runtime state sharing is unsupported. Without a loaded native lock,
TypeScript write APIs fail closed.

## pending-send.json

`values` prohibition is **key-name only**: reject a key if the name contains
`token`, `secret`, `password`, `passphrase`, `private`, `proof`, or `header`.
Keys are non-empty and ≤64 characters. Values are non-empty and ≤512
characters. Values may legally contain those substrings.

Unversioned files (no `schema_version`) map `recipient_did` / `content_sha256`
to `direct.send`. That legacy branch is mandatory.

The store is a single slot within one implementation's state directory. A
leftover `pending-send.json` blocks that implementation's next different
mutating command. User-facing errors must name `pending-send.json`.

## Session

`session.json` is only `{ "access_token": "..." }`. HTTP 401 / JSON-RPC 1401 /
`"unauthorized"` print the refresh hint and **do not delete** this file.
