# mailferret architecture

Implements `docs/REQUIREMENTS.md` (cited as R§n; bare §n is a section of this file). Threat IDs (`T-nn`) and limits (`L-nn`) live in `docs/SECURITY.md`; tasks live in `docs/PLAN.md`.

## 1. Shape

One Python package (`src/mailferret`) with two entry points: the `mailferret` CLI and `mailferret serve` (an MCP stdio server). One process serves all configured accounts. The MCP layer is async (MCP SDK v2). IMAP I/O is synchronous (`imapclient`) and runs in worker threads, serialized by a per-account lock.

```
MCP client ──stdio──► server/ ──► query/ ──► imap/ (ReadOnlySession) ──TLS──► IMAP server
                         │          │            ▲
                         │          ▼            │ auth/ ◄── credentials/
                         │       content/ (MIME, charset, HTML, PDF worker)
                         ▼          aliases/
                      envelope (untrusted-content wrapping, limits)
CLI ──► config/, credentials/, registration/, doctor (reuses imap/ + credentials/)
```

Dependency rule: arrows point one way. The limits table (`limits.py`, top level) is the one module every layer may import. `content/` and `aliases/` are pure (bytes and str in, models out, no I/O), which keeps them fuzzable and fixture-testable. Only `imap/` touches sockets. Only `credentials/` touches secrets. Only `registration/` writes client config files.

## 2. Modules

| Module | Responsibility | Boundary / key rule |
|---|---|---|
| `config/` | pydantic models, `tomllib` load, `tomlkit` write (comment-preserving), `platformdirs` paths, `MAILFERRET_CONFIG` env and `--config` override (R§6) | The schema rejects any key named like a secret (`password`, `token`, `secret`) and rejects `write.enabled = true` / `smtp.enabled = true` with "not supported in this version" |
| `providers/` | Presets as data: `generic`, `hetzner` (host, port, TLS mode, login is the full address, header quirks such as the alias header priority). User presets go under `[presets.<name>]` | A preset only supplies defaults; explicit account keys win |
| `credentials/` | `CredentialBackend` protocol: `get`, `set`, `delete`, `describe()`. Backends: `keyring` (platform backend) and `command` (user argv). Backend detection, WSL detection, typed errors | The secret is a `Secret` wrapper whose `repr`/`str` is redacted. Entry key = service `mailferret/<account_id>`, username `<login>@<host>` (account-specific per R§11). Both backends bind the secret to `<login>@<host>` (T-11): `keyring` through the entry key, `command` through a binding record written by `auth set` to the data dir and checked before `get` runs |
| `auth/` | `Authenticator` protocol: `authenticate(session, account, backend)`. `PasswordAuth` now (LOGIN; `AUTHENTICATE PLAIN` if LOGIN is unavailable). `XOAuth2Auth` later, via `imapclient.oauth2_login` | Checks `LOGINDISABLED` before loading the secret. A failed login is never retried (R§11) |
| `imap/` | `connect()`: TLS (implicit or STARTTLS), `SocketTimeout(connect, read)`, CAPABILITY logged and parsed into a `Capabilities` value; `ReadOnlySession`; the command guard; read-side size caps; per-account connection cache with an idle timeout | The only module holding an `IMAPClient`. It is never returned to callers (see §6) |
| `query/` | `list_folders` (LIST + STATUS), `search` (criteria builder, SORT when advertised, paging, caps), `fetch` (structure-first), `thread`, alias scans | Criteria are always passed to imapclient as a list (never a raw string), so user text cannot inject IMAP syntax |
| `content/` | `mime.py` (bounded walk), `charset.py` (decode with fallback chain then `errors="replace"`), `headers.py` (RFC 2047/2231, size caps), `html.py` (strip hidden content, then `inscriptis`), `pdf_worker.py` (subprocess, `pypdf`), `truncate.py` | No network, no file writes. Every limit (`L-nn`) is enforced here or in `imap/` |
| `aliases/` | Resolve the recipient alias from configured headers in configured priority; exact and wildcard match; aggregation for `list_aliases` (R§5) | Off when an account has neither alias domains nor a plus separator |
| `server/` | `MCPServer` app, tool functions, pydantic output models, the untrusted-content envelope, `instructions=` text (passed by keyword) | Registers read tools only. There is no code path that registers a write tool in this version |
| `cli/` | `click` app: `setup`, `auth set`, `accounts list`, `doctor`, `register claude-code / claude-desktop [--print]`, `serve` | Secrets are read with `getpass` (TTY) or from stdin with `--stdin`, never from argv |
| `registration/` | Client config discovery, backup, atomic JSON write, duplicate detection | Never writes a secret, writes absolute launcher paths only |
| `limits.py` | The `L-nn` ceilings as one frozen model, merged with `[limits]` (lower only) | Imports nothing from mailferret, so `content/` and `imap/` can enforce limits without depending on `server/` |
| `logging.py` | stderr-only logging (stdout belongs to the MCP protocol), redaction filter | Every secret seen by `credentials/` is added to a process-wide redaction set |

### 2.1 Credentials and the WSL strategy

Resolution per account: `credential_backend = "keyring" | "command"` (default `keyring`).

- `keyring`: the platform backend (macOS Keychain, Windows Credential Locker, Secret Service). `detect.py` rejects the fail, null, chainer-with-no-real-backend and any plaintext backend. On a rejected backend `get` raises `CredentialBackendUnavailable` with a hint to run `doctor`.
- `command`: `credential_command.get = [argv]` prints the secret on stdout. `credential_command.set = [argv]` receives it on stdin. No shell, an absolute path resolved at setup, a timeout (`L-14`), stdin closed for `get` so a pinentry or prompt fails fast instead of hanging, and stderr is captured but never logged verbatim. `auth set` stays the write path (R§7) through `set`.
- The `command` argv lives in the config, so write access to the config means code execution as the user. That is the same-user boundary SECURITY.md places out of scope; `doctor` prints the configured argv so a change is visible.
- No env-var backend (it would end up in client config `env`, R§8). Tests inject an in-memory backend through the same protocol.

On WSL, `setup` detects that no usable keyring exists and proposes `command` with a `pass` recipe (the recommendation, see §11 Open decisions). `doctor` reports the backend in use, whether it is secure, and the result of a timed lookup (found / not found / locked / timeout) without printing the secret.

### 2.2 Connection layer

- TLS modes: `implicit` and `starttls`. There is no plaintext mode. The context comes from `ssl.create_default_context()` (optionally `cafile=` from `ca_file`), with a TLS 1.2 minimum and hostname checking on. No option disables verification (R§9).
- STARTTLS: refuse if not advertised, and discard all pre-TLS capabilities after the upgrade (T-07).
- Capabilities are parsed once per connection into flags (`SORT`, `THREAD=REFERENCES`, `UIDPLUS`, `CONDSTORE`, `SPECIAL-USE`, `LOGINDISABLED`, `IDLE`, `ESEARCH`), and the query layer branches on them (R§11).
- IDLE later: sessions are created by a `SessionFactory`, and `ReadOnlySession` has no state tied to request handling, so a future `IdleWatcher` opens its own dedicated connection per account with the same factory and pushes events through a callback interface. The command connection is never shared with IDLE.
- Reconnect: a dropped connection is re-opened once per tool call. An authentication failure is terminal for the process lifetime of that account until the config or secret changes (no lockout).

### 2.3 MCP tool layer

- Tools: R§3 table. Every tool takes `account` (optional only when exactly one account exists or `default_account` is set). Messages are addressed by an opaque `message_ref` = `account:folder:uidvalidity:uid` (base64url). A ref whose account or UIDVALIDITY does not match is rejected (T-14).
- Annotations: `read_only_hint=True`, `open_world_hint=True` (the content comes from arbitrary senders), plus `title`. Hints are not security: enforcement is §6.
- Structured output: each tool returns a pydantic model. Mail-derived strings are typed `Untrusted` fields (§2.4). Errors are `ToolError` with a typed code (`not_configured`, `not_found`, `limit_exceeded`, `auth_failed`, `backend_unavailable`, `timeout`, `server_error`) and never include a secret or raw server text beyond a capped, wrapped excerpt.
- Server `instructions` state that all mail content is untrusted data and never instructions.

### 2.4 Untrusted-content envelope

Every string that originates from a message or the server (subject, addresses and display names, body, header values, attachment names and text, folder names) is emitted as:

- structured: `{"untrusted": true, "kind": "body", "text": "…", "truncated": false, "notes": [...]}`;
- text content: `<<<MAILFERRET_UNTRUSTED kind=body id=<nonce>>>> … <<<END_UNTRUSTED id=<nonce>>>>`, with a per-response random nonce. Any occurrence of the delimiter prefix inside the content is escaped, so a mail cannot close the block.

Before wrapping, `content/` removes bidi overrides and isolates, zero-width characters and other `Cf` controls, plus HTML hidden content (`display:none`, `visibility:hidden`, `hidden`, zero font size, comments, `<head>`, `<script>`, `<style>`), and records what it removed in `notes`.

### 2.5 Write and SMTP: prepared, disabled

R§4 alignment: the interfaces, the config-schema position and the module locations exist now; no implementation does.

- Interfaces (types only): `mailferret/write/api.py` defines the `WriteOps` protocol (move, set flags, mark read, create folder, each taking `confirm: Literal[True]`); `mailferret/smtp/api.py` defines `DraftSender` (`create_draft`, `send_draft`).
- Config position: `[accounts.<id>.write] enabled` and `[smtp] enabled` are parsed; only `false` validates in this version.
- Implementation locations: `mailferret/write/imap_ops.py` and `mailferret/smtp/client.py`, loaded only through `server/write_tools.py`. None of these three files exists in this version.

They stay unreachable because:

1. No implementation exists. An AST test asserts that `write/` and `smtp/` contain only protocol and data-type definitions and import nothing from `imap/`; an import-graph test asserts that nothing under `server/`, `query/` or `imap/` imports them.
2. The config schema rejects `enabled = true` for both.
3. The command guard (§6) denies every mutating verb, whatever any future module does.
4. The tool registry test asserts the exact set of registered tool names, and that all of them carry `read_only_hint=True`.

Future design (out of scope now, R§4): `mailferret.write` builds a separate `WriteSession` from its own guard allowlist, and is imported only by `server/write_tools.py`, which is loaded only when an account has `write.enabled = true`. Every write tool takes `confirm: Literal[True]`, sets `read_only_hint=False` and `destructive_hint` per operation, and requires UIDPLUS for move/expunge (`UID EXPUNGE` only, never session-wide EXPUNGE). `mailferret.smtp` is draft-first: `create_draft` returns a draft id and only a separately confirmed `send_draft` sends.

## 3. Data flow: `get_message`

1. **MCP** `get_message(account, message_ref, max_chars?)` arrives over stdio. pydantic validates the input. `max_chars` is clamped to `≤ L-03`.
2. **server** decodes the `message_ref` and checks that its account equals the `account` argument. It takes the per-account lock and runs the rest in a worker thread, under a whole-call deadline (`L-13`).
3. **imap** reuses or opens the session: TCP connect (`L-11`) → TLS verify → CAPABILITY → `auth/` (LOGINDISABLED check → `credentials/` get → LOGIN; secret added to the redaction set, local reference dropped) → CAPABILITY again.
4. **query** `EXAMINE folder` (never SELECT) → compare UIDVALIDITY with the ref → `UID FETCH uid (RFC822.SIZE FLAGS INTERNALDATE BODYSTRUCTURE BODY.PEEK[HEADER])`. The header literal is capped on read (`L-05`).
5. **content** parses BODYSTRUCTURE into a bounded tree (`L-06` depth, `L-07` parts) and picks the text part (prefer `text/plain`, else `text/html`).
6. **query** `UID FETCH uid (BODY.PEEK[<section>]<0.L-02>)`. The read side enforces `L-02` regardless of what the server returns (T-08). If BODYSTRUCTURE is unusable, it falls back to `BODY.PEEK[]` only when `RFC822.SIZE ≤ L-01`, otherwise it returns headers plus a `limit_exceeded` note.
7. **content** decodes the transfer encoding → charset chain → for HTML, strips hidden content and converts to text → removes `Cf` controls → truncates at `max_chars` on a codepoint boundary (an incomplete tail from a partial fetch is dropped by an incremental decoder).
8. **aliases** resolves the recipient alias if enabled.
9. **server** builds `MessageResult` (headers, `body: Untrusted`, attachments metadata, `alias`, `truncated`, `notes`), wraps it in the envelope and returns structured plus text content.

`\Seen` is never set (EXAMINE + PEEK only, R§11). This is asserted against GreenMail.

## 4. Extension points

| Point | Mechanism |
|---|---|
| Provider presets | Data entries in `providers/presets.toml` or `[presets.<name>]` in user config |
| Credential backends | `CredentialBackend` protocol; new backends are registered in `credentials/registry.py` (no plugin loading via entry points, so arbitrary installed packages cannot inject a backend) |
| Auth mechanisms | `Authenticator` protocol (`XOAuth2Auth` next, with token storage through `credentials/`) |
| Attachment extractors | `content/extractors` registry keyed by MIME type; each one runs under the same byte, char and time limits |
| Notifications | `SessionFactory` + `IdleWatcher` (§2.2) |
| Write/SMTP | §2.5 |
| Client registration | `registration/clients/<client>.py` implementing `discover()`, `render()`, `write()` |

## 5. Platform support matrix

| | Linux | WSL2 | Windows native | macOS |
|---|---|---|---|---|
| Config dir | XDG config | XDG config (Linux side) | `%APPDATA%\mailferret` | `~/Library/Application Support/mailferret` |
| Default credential backend | Secret Service via `keyring` | `command` (`pass` recipe); Secret Service if `doctor` finds a working one | Windows Credential Locker | Keychain |
| `register claude-code` | yes | yes | yes | yes |
| `register claude-desktop` | not targeted | writes the Windows-side config: launch via `wsl.exe -d <distro> -- <abs uvx> …` | regular and MSIX config paths | yes |
| Plugin | yes | yes | yes (needs `uvx` on the client PATH) | yes |
| Plugin in Cowork | unverified (§10 item 14) | unverified | unverified | unverified |
| CI unit tests | yes | covered by Linux, plus WSL detection unit tests with a faked `/proc` | yes | yes |
| CI GreenMail integration | yes | — | — (Linux runners only, by decision) | — (Linux runners only, by decision) |

## 6. Read-only enforcement in the server

Client hints and plugin hooks are advisory. The guarantee lives in `imap/`:

- **Command allowlist.** Every command leaving the process passes a guard. Allowed: `CAPABILITY`, `NOOP`, `LOGOUT`, `STARTTLS`, `LOGIN`, `AUTHENTICATE`, `ID`, `NAMESPACE`, `LIST`, `LSUB`, `STATUS`, `EXAMINE`, `CLOSE`/`UNSELECT` (both safe after EXAMINE), and `SEARCH`, `FETCH`, `SORT`, `THREAD` as plain or `UID` commands. `IDLE`/`DONE` are added when IDLE ships. Everything else (`SELECT`, `STORE`, `COPY`, `MOVE`, `EXPUNGE`, `APPEND`, `CREATE`, `DELETE`, `RENAME`, `SUBSCRIBE`, `SETACL`, `ENABLE` …) raises `ReadOnlyViolation` before any byte is sent.
- **FETCH item allowlist.** Only `UID`, `FLAGS`, `INTERNALDATE`, `RFC822.SIZE`, `ENVELOPE`, `BODYSTRUCTURE`, `RFC822.HEADER`, and `BODY.PEEK[...]` with an optional partial. `BODY[`, `RFC822`, `RFC822.TEXT` are denied (they set `\Seen`).
- **Type boundary.** `ReadOnlySession` exposes only the read methods. The raw client is a private attribute and is never returned.
- **Proof.** A recording fake IMAP server test drives every tool with every option and asserts that no denied verb or FETCH item appears on the wire. A GreenMail test asserts flags are unchanged after every tool.

The guard's hook point inside imapclient/imaplib is a Phase 2 verification item (§10).

## 7. Config schema

Location per R§6, override with `MAILFERRET_CONFIG` or `--config`. Account ids match `^[a-z0-9][a-z0-9_-]{0,31}$`.

```toml
schema_version = 1
default_account = "work"            # optional

[limits]                            # optional; may only lower the built-in ceilings (SECURITY.md §5)
max_body_chars = 50000
max_results = 100

[accounts.work]
preset = "generic"
host = "imap.example.com"
port = 993
tls = "implicit"                    # implicit | starttls
login = "user@example.com"
credential_backend = "keyring"      # keyring | command
# ca_file = "/path/to/ca.pem"       # extra trust anchor; verification stays on

[accounts.work.aliases]
domains = ["example.com"]
plus_separator = "+"
header_priority = ["Delivered-To", "X-Original-To", "To", "Cc"]

[accounts.shop]
preset = "hetzner"                  # supplies host, port and TLS mode
login = "shop@example.com"
credential_backend = "command"

[accounts.shop.credential_command]
get = ["/usr/bin/pass", "show", "mailferret/shop"]
set = ["/usr/bin/pass", "insert", "--multiline", "--force", "mailferret/shop"]

# Reserved, rejected when enabled in this version:
# [accounts.work.write]  enabled = false
# [smtp]
```

## 8. Dependencies

Snapshot of PyPI at design time (release date of the listed version). Policy and vetting: `docs/research/library-survey.md`, R§10.

| Package | Role | Version | Released | License |
|---|---|---|---|---|
| mcp | MCP SDK v2 (`from mcp.server import MCPServer`), pinned `>=2.3,<3` | 2.3.0 | 2026-10-02 | MIT |
| imapclient | IMAP | 4.3.0 | 2026-11-17 | BSD-3 |
| inscriptis (+ lxml) | HTML → text | 2.7.7 (lxml 6.1.3) | 2026-11-19 (2026-09-02) | Apache-2.0 (BSD-3) |
| pypdf | PDF text, no extras | 7.2.0 | 2026-11-26 | BSD-3 |
| keyring | platform credential stores | 25.7.0 | 2025-11-16 | MIT |
| platformdirs | config paths | 4.14.8 | 2026-11-20 | MIT |
| click | CLI | 8.5.1 | 2026-11-06 | BSD-3 |
| pydantic | config and output models (already via mcp) | 2.14.4 | 2026-11-19 | MIT |
| tomlkit | TOML write (read: stdlib `tomllib`) | 0.15.3 | 2026-11-24 | MIT |
| ruff (dev) | lint/format | 0.17.6 | 2026-11-19 | MIT |
| mypy (dev) | `--strict` | 2.4.1 | 2026-10-28 | MIT |
| pytest (dev) | tests | 9.2.0 | 2026-10-27 | MIT |
| GreenMail (test, Docker) | IMAP server | 2.1.15 | not recorded | Apache-2.0 |
| uv (launcher) | `uvx --from` | 0.13.10 | 2026-11-24 | MIT / Apache-2.0 |

Python floor `>=3.11`. Rejected: fastmcp, aioimaplib, html2text, pymupdf, tomli-w, keyrings.alt (survey). Not added: charset detection libraries (the stdlib fallback chain is enough, R§11), justhtml (optional fallback only if inscriptis fails vetting later).

## 9. Claude Code plugin

### 9.1 Repo layout

```
pyproject.toml  uv.lock  src/mailferret/  tests/          # PyPI package
plugin-evals/                                            # `claude plugin eval` cases + mocked-IMAP fixture config
.claude-plugin/marketplace.json                          # repo is its own marketplace
plugin/                                                  # plugin root (marketplace source "./plugin")
  .claude-plugin/plugin.json
  .mcp.json
  constraints.txt                                        # generated, §9.4
  skills/doctor/SKILL.md
  agents/mail-reader.md
docs/  .github/workflows/
```

The plugin lives in `plugin/` rather than the repo root. With `source: "./"` the whole repo (sources, tests, the malicious-mail fixture corpus) would be copied into every user's plugin cache. A subdirectory keeps the cache down to what the plugin needs at runtime, and leaves no top-level `bin/`. Evals sit outside `plugin/` for the same reason; if `claude plugin eval` only accepts an in-plugin `evals/`, they move there only after checking what the cache copies (§10 item 20). Bomb fixtures are generated at test time, never committed.

### 9.2 Launch

`plugin/.mcp.json`:

```json
{"mcpServers": {"mailferret": {"command": "uvx", "args": ["--constraints", "${CLAUDE_PLUGIN_ROOT}/constraints.txt", "--from", "mailferret==X.Y.Z", "mailferret", "serve"]}}}
```

- The exact pin is required, so a cached older version is never served silently. `--from pkg==ver cmd` is the documented uvx form (survey); the shorter `uvx pkg==ver` is not relied on.
- `--constraints`: uvx ignores `uv.lock`, so without it plugin users would resolve unlocked transitive dependencies (the large `mcp` tree included) at install time. The constraints file is generated with `uv export` from the lock of the pinned release, so users run the exact set CI tested and the audit scanned. Chosen over `--exclude-newer`: a date cutoff still resolves versions CI never saw and cannot be audited as a list. Cost: transitive fixes reach users only through a mailferret release, so the scheduled audit runs against the shipped constraints file (T-13).
- No `env`, no `userConfig`: the server reads its own config file. Cowork ignores servers whose options have no default, and an unset `${…}` stays literal. Evals inject their fixture config through `MAILFERRET_CONFIG` in the inherited environment; only if MCP servers do not inherit it does `.mcp.json` gain `"env": {"MAILFERRET_CONFIG": "${MAILFERRET_CONFIG:-}"}`, which needs `${VAR:-default}` support (§10 item 15). The server treats an empty value as unset.
- Tool names: `mcp__plugin_mailferret_mailferret__<tool>`. The agent and skill use these names, enumerated.
- **The absolute-path gap (R§11).** `.mcp.json` cannot carry an absolute `uvx` path, so a missing launcher on the client PATH is a silent start failure. No mailferret process can observe the client's PATH from outside it. The coverage is the `doctor` skill (§9.7), whose ground truth is whether the mailferret tools are present in the session. The README covers putting `uvx` on the PATH the client inherits, per platform.

### 9.3 Credentials

Keyring (or the `command` backend) stays the single source of truth. Plugin `userConfig` carries no secrets, and in fact no options at all in this version. Reasons: one write path (`mailferret auth set`, R§7) for every client; a `sensitive` userConfig value would reach the server through `env`, readable by same-user processes and inherited by children; Cowork never prompts; and a second store would diverge silently from the first.

There is no setup skill. A secret must never pass through the model, so the guard sits in the CLI and the server (SECURITY T-20):

- `auth set` and `setup` refuse when stdin is not a TTY, unless `--stdin` is given. `getpass` itself silently falls back to reading stdin without a TTY, so the TTY check happens before it is called.
- `--stdin` is refused when `CLAUDECODE=1` is set, i.e. when an agent's Bash tool pipes the secret in. This is a speed bump against accidents, not a boundary: an agent can unset the variable.
- Every tool returns `not_configured` when no account exists or an account has no stored secret. Its text names the terminal command to run (`mailferret setup` / `mailferret auth set <account>`) and says never to paste a password into the chat.

### 9.4 Versioning and release

- `pyproject.toml` leads. The plugin version set is: `plugin.json` `version`, the `.mcp.json` pin, the pins in the `doctor` skill (command and `allowed-tools`), and `plugin/constraints.txt`. All of them always refer to one released PyPI version, so the plugin lags `pyproject.toml` by one PR after each release.
- CI on every PR: every pin under `plugin/` equals `plugin.json` `version`, which is `≤` the `pyproject.toml` version; `plugin/constraints.txt` equals `uv export` (no dev, no project) of the lock at tag `v<plugin version>`. The release job (and a scheduled job) also checks that the pinned version exists on PyPI.
- Order (per the spec): a tag `vX.Y.Z` on main → trusted publishing to PyPI with attestations → a smoke job runs the exact plugin launch command with `--version` → a follow-up PR bumps all plugin pins, regenerates `constraints.txt` and bumps `plugin.json` `version` together → merge. Plugin users update only on that bump, so unreleased code on main never reaches them.
- Before the first PyPI release the plugin cannot launch, so the marketplace entry is added in the PR that follows the first release.
- `register`-written entries use the same mechanism: the wheel ships its own `constraints.txt` as package data, `register` copies it to the data dir as `constraints-X.Y.Z.txt` and references it by absolute path.

### 9.5 Duplicate registration policy

A manual `register claude-code` entry named `mailferret` outranks the plugin server, and it changes the tool names from `mcp__plugin_mailferret_mailferret__*` to `mcp__mailferret__*`. That silently breaks the plugin agent's `tools` allowlist and the skill's pre-approval. Policy:

- The plugin is the recommended Claude Code path. `register claude-code` detects an installed mailferret plugin and refuses unless `--force`. Both the refusal and the `--force` path print what breaks and the exact command to disable or uninstall the plugin (`claude plugin disable mailferret@<marketplace>` / `claude plugin uninstall …`, forms verified in §10 item 20).
- Plugin detection only sees the scopes visible from the current directory (user scope, and project/local scope of the current project), so a plugin enabled in another project is not seen. The message says so.
- Reverse order (the plugin installed after a manual entry): `mailferret doctor` lists every registration it can see, and the `doctor` skill detects shadowing from inside the session (`mcp__mailferret__*` present, `mcp__plugin_mailferret_mailferret__*` absent) and gives the `claude mcp remove` command for the manual entry.

`register claude-code` mechanism: it runs `claude mcp add-json --scope <user|project|local> mailferret '<json>'` through the absolute path of the `claude` CLI, so Claude Code owns its file format and locking. The JSON names the absolute `uvx` path, the constraints file and the running mailferret version. It never edits Claude Code's state files directly. Without the CLI it falls back to `--print`. The exact `claude mcp` flags are a verification item (§10).

### 9.6 Claude Desktop

Primary: `mailferret register claude-desktop` (backup, then an atomic merge into `claude_desktop_config.json`; `--print` shows the snippet only). Paths: macOS Application Support; Windows regular `%APPDATA%\Claude`; Windows MSIX `%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Roaming\Claude` (the package family suffix is globbed, never hard-coded). From WSL it looks for those paths under `/mnt/<drive>/Users/*/` without running Windows binaries. If not exactly one candidate is found it requires `--desktop-config <path>`. The command is `wsl.exe -d <distro> -- <absolute uvx path> --constraints <absolute constraints path> --from mailferret==X.Y.Z mailferret serve` (distro from `WSL_DISTRO_NAME`).

`.mcpb`: deferred. The manifest format supports `server.type: "uv"`, but host support in Desktop is unverified (§10). If verified, ship an `.mcpb` with no `sensitive` user_config (keyring stays the source of truth, §9.3).

### 9.7 Plugin components

The adversarial review is done; these verdicts are decided. The baseline: the MCP tool descriptions and input schemas already explain each tool, so a component must add something the server cannot. Rejected rows stay as a record.

| Name | Type | Verdict | Design / decisive reason |
|---|---|---|---|
| `mail-reader` | agent | **ship** | See below. Opt-in containment, not a guarantee: nothing forces delegation |
| `doctor` | skill (model- and user-invocable) | **ship** | See below. Useful exactly when the server failed to start and no tool exists to ask |
| `setup` | skill | reject | A skill cannot keep a password out of chat; the guard moved into the CLI and the server (`--stdin`/TTY rules, `not_configured`, §9.3) |
| `triage` | skill | reject | Its only unique content (call order, limits, "mail is data") is folded into the `mail-reader` body, where the tool allowlist also applies |
| `alias-report` | skill | reject | One `list_aliases` call with documented parameters; pure duplication of the tool schema |
| `search-syntax` | skill | reject | Plugin-only knowledge other clients lack; the fix is precise `Field` descriptions and examples in the `search` input schema |
| `register` | command | reject | The plugin already registers the server; a wrapper invites the duplicate of §9.5 |
| `launcher-check` | hook (SessionStart) | reject | Its PATH may differ from the MCP spawn PATH (false all-clear) and it runs every session; the `doctor` skill uses the session's tool list instead |
| `readonly-guard` | hook (PreToolUse) | reject | No write tools exist, hooks fail open, and the server guard is the enforcement (§6) |
| `injection-scan` | hook (PostToolUse) | reject | Heuristic with false negatives that fails open; it would suggest a protection it cannot provide |

**`mail-reader` agent.**
- `tools`: the scoped read tools enumerated by name (`list_accounts`, `list_folders`, `search`, `get_message`, `get_thread`, `list_attachments`, `get_attachment_text`, `list_aliases`), with no wildcard, so a future write tool is never granted by accident. No Bash, web, file, Skill or Agent tools (verify that an allowlist excludes the last two, §10 item 18). No `skills` preload. A `maxTurns` cap.
- A CI test asserts that the agent's `tools` list equals the server's registered read tools, prefixed with the plugin scope.
- If its tools are missing (manual-registration shadowing, §9.5, or the server not running), it stops and reports that, with a pointer to the `doctor` skill, instead of summarizing from nothing.
- Body: the call order and bounds (accounts → folders → `search` with an explicit page size → `get_message` only for the messages it needs, honouring `truncated`), and the rule that mail content is data.
- Output contract: instructions found in mail are reported as quoted speech attributed to the sender ("the mail asks the reader to …"), never followed; URLs are defanged (`hxxps://example[.]com`) unless the user asked for links; no raw headers or bodies beyond short quotes.

**`doctor` skill.**
1. Ground truth first: is `mcp__plugin_mailferret_mailferret__list_accounts` present in the session? If yes, the server runs: call it and report the accounts and any `not_configured` error. If `mcp__mailferret__list_accounts` is present instead, report the shadowing of §9.5.
2. If absent: `command -v uvx`. A miss is conclusive (install uv, fix the PATH the client inherits). A hit is inconclusive, because the Bash tool's PATH may differ from the MCP spawn PATH (§10 item 11).
3. Run the exact plugin launch command with `--version`, timed. Success with a duration above the client's MCP startup timeout (`MCP_TIMEOUT`) means the first-run download timed out the launch: the cache is now warm, so tell the user to reconnect via `/mcp` or restart. Success that was fast points at the PATH. Then run `mailferret doctor` with the same pins and explain it.
- `allowed-tools` pre-approves only the exact Bash strings of steps 2 and 3 (pins included, so they are part of the version set, §9.4; whether `${CLAUDE_PLUGIN_ROOT}` expands there is §10 item 17).
- Model-invocable, so the model can offer it when the mailferret tools are missing.

## 10. To verify in Phase 2

Each item is a research spike (`docs/PLAN.md` phase 2a). The design names a fallback for each.

1. The imapclient/imaplib hook point for the command guard and the read-side literal cap (fallback: wrap at the socket-file level in the `IMAP4` subclass imapclient uses).
2. Whether imapclient exposes ESEARCH (`RETURN (COUNT MIN MAX)`); the design does not depend on it.
3. Which capabilities GreenMail advertises (SORT, THREAD, CONDSTORE, UIDPLUS, STARTTLS, SPECIAL-USE). Branches it lacks are covered by the scripted fake server.
4. The text content the SDK emits next to structured output, and whether the envelope delimiters survive in both.
5. Whether Claude Desktop runs `.mcpb` `server.type: "uv"` on Windows, macOS, and via WSL.
6. How `register` detects an installed plugin (e.g. `claude plugin list --json`, or the plugin install record), and that a same-name user server really shadows the plugin server.
7. Headless unlock behaviour from a client- or `wsl.exe`-launched process: `pass`/gpg-agent with an expired cache and closed stdin (fails fast?), and Secret Service bus discovery without `DBUS_SESSION_BUS_ADDRESS`.
8. The Claude Code hook shell on Windows (only relevant if a hook is ever included).
9. The claude.ai/Cowork installability of a plugin whose root is a subdirectory.
10. Exact `pypdf` knobs for the stream-length and decompression caps in 7.x.
11. Whether Claude Code's Bash tool and its MCP server launches inherit the same PATH (the `doctor` skill relies on it).
12. Whether the Bash tool on Windows (Git Bash) provides `command -v` for the `doctor` skill, or it needs a `where` branch.
13. The `claude mcp add-json` flags and scopes used by `register claude-code`.
14. Whether a Cowork plugin's stdio server runs on the host or in the sandbox VM (config, keyring and IMAP egress all depend on it). Until then Cowork is "unverified" in §5.
15. Whether plugin `.mcp.json` supports `${VAR:-default}`, and whether MCP servers inherit Claude Code's environment (how evals inject `MAILFERRET_CONFIG`, §9.2).
16. That `uvx --constraints <file> --from pkg==ver` applies the constraints to the tool environment, and that `${CLAUDE_PLUGIN_ROOT}` expands inside `args`.
17. Whether skill `allowed-tools` Bash patterns may contain `${CLAUDE_PLUGIN_ROOT}`; if not, the `doctor` skill pre-approves only step 2 and step 3 prompts.
18. That an agent `tools` allowlist excludes the Skill and Agent tools.
19. That Claude Code sets `CLAUDECODE=1` in its Bash tool environment (the `--stdin` refusal, §9.3).
20. Whether `claude plugin eval` accepts an evals directory outside the plugin root, what the plugin cache copies, and the exact `claude plugin disable` / `uninstall` forms.

## 11. Open decisions (Checkpoint 1)

| Decision | Recommendation | Why |
|---|---|---|
| License | MIT | Matches every runtime dependency's permissive license; simplest for reuse |
| WSL credential backend | Default: the `command` backend with a documented `pass` recipe (GPG-encrypted at rest, no D-Bus, works under `wsl.exe` launch). Fallback: `keyring` Secret Service when `doctor` finds a working, unlocked one (e.g. gnome-keyring or KeePassXC under WSLg) | See below |
| Desktop distribution | `register claude-desktop` now; `.mcpb` only after item 5 of §10 is verified | Format support is documented, host support is not |
| Plugin root | `plugin/` subdirectory | Keeps tests and fixtures out of plugin caches (§9.1) |
| Plugin `userConfig` | None | Single source of truth (§9.3) |
| Plugin components | `mail-reader` agent and `doctor` skill only | Adversarial review verdicts (§9.7) |
| Plugin dependency locking | `uvx --constraints` with a generated file | Exact, audited transitive set; `--exclude-newer` is not a list (§9.2) |
| LICENSE copyright holder | The GitHub handle (`<owner>`), not a legal name | Minimises personal data in the repo; the handle already identifies the publisher |
| `open_world_hint` | `True` | Content comes from arbitrary senders; clients should treat the output as external |
| GreenMail integration scope | Linux CI only; Windows/macOS run unit tests and the fake server | Container support on hosted Windows/macOS runners is not something to depend on; the fake server covers the platform-independent protocol paths |

WSL options, scored against the constraints (headless stdio child, a locked store must fail fast, `auth set` is the write path, no new unvetted dependency, no secret in client `env`):

| Option | Headless fit | Locked → fails fast | `auth set` works | New dep | Verdict |
|---|---|---|---|---|---|
| Secret Service via gnome-keyring under WSLg | needs a session bus, a running daemon and an unlocked collection; none is guaranteed under `wsl.exe` launch | the unlock prompt may hang or pop up a window | yes | none (`keyring` → `secretstorage`/`jeepney`) | fallback, when detected working |
| `pass`/GPG via the `command` backend | gpg-agent starts on demand, no bus | yes, with stdin closed and a timeout (verify item 7) | yes, via `set` argv | none in Python; `pass` + `gnupg` are distro packages | **default** |
| Windows Credential Manager via interop | breaks when interop is disabled or PATH ordering changes; `cmdkey` cannot read secrets, so it needs a PowerShell P/Invoke script | the PowerShell startup cost is paid on every call | needs a second script | none, but a fragile Windows-side script | reject as built-in; a user may wire it through `command` at their own risk |
| Encrypted file + passphrase | the passphrase must still reach a headless process, so the problem only moves | — | yes | crypto code to own | reject |
| Env var / command fallback | env ends up in client `env` (R§8) and `/proc/<pid>/environ` | — | no | none | env: reject; command: this is the default above |

`doctor` reports: backend type and class; `secure: yes/no`; WSL detected; for `command`, the resolved absolute path and a timed lookup result (`found`, `not_found`, `locked`, `timeout`); for `keyring` on WSL, bus reachability and collection lock state.
