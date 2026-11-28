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
| `config/` | pydantic models, `tomllib` load, `tomlkit` write (comment-preserving), `platformdirs` paths, `MAILFERRET_CONFIG` env and `--config` override (R§6) | An override naming a missing file means no accounts (`not_configured`), never the default path (§7). The schema rejects any key named like a secret (`password`, `token`, `secret`) and rejects `write.enabled = true` / `smtp.enabled = true` with "not supported in this version" |
| `providers/` | Presets as data: `generic`, `hetzner` (host, port, TLS mode, login is the full address, header quirks such as the alias header priority). User presets go under `[presets.<name>]` | A preset only supplies defaults; explicit account keys win |
| `credentials/` | `CredentialBackend` protocol: `get`, `set`, `delete`, `describe()`. Backends: `keyring` (platform backend, used only through a bounded probe subprocess, §2.1) and `command` (user argv). Backend detection, WSL detection, typed errors | The secret is a `Secret` wrapper whose `repr`/`str` is redacted. Entry key = service `mailferret/<account_id>`, username `<login>@<host>` (account-specific per R§11). Both backends bind the secret to `<login>@<host>` (T-11): `keyring` through the entry key, `command` through a binding record written by `auth set` to the data dir and checked before `get` runs |
| `auth/` | `Authenticator` protocol: `authenticate(session, account, backend)`. `PasswordAuth` now, choosing from the capabilities re-read after TLS: `LOGIN` unless `LOGINDISABLED`; else `AUTHENTICATE PLAIN` if `AUTH=PLAIN` is advertised; else `auth_failed` before `credentials/` is touched. `LOGIN` gets `str` only, after an `isascii()` check on login and secret (imaplib's ASCII encoding error would carry the secret, T-02): non-ASCII goes to `AUTHENTICATE PLAIN` (UTF-8) when advertised, else a typed credential error with fixed text, raised outside any `except` (for a non-ASCII login: default, pending D3). `XOAuth2Auth` later, via `imapclient.oauth2_login` | A failed login is never retried, across processes too: an explicit server rejection of LOGIN/AUTHENTICATE (a tagged `NO`/`BAD`; not a timeout, TLS or network error) writes an auth-failed marker for `<login>@<host>` to the data dir, and every later login attempt from any server process returns `auth_failed` (naming the command) until `auth set`, `setup` or `auth retry <account>` clears it (R§11, T-16) |
| `imap/` | `connect()`: TLS (implicit or STARTTLS), `SocketTimeout(connect, read)`, CAPABILITY logged and parsed into a `Capabilities` value; `ReadOnlySession`; the command guard (§6); per-command read caps (§2.2); per-account connection cache with an idle timeout | The only module holding an `IMAPClient`. It is never returned to callers (see §6). The guard and caps hook imaplib/imapclient private API, so imapclient is pinned exactly and the hooks check themselves before the first connection and on every session (§2.2) |
| `query/` | `list_folders` (LIST + STATUS), `search` (criteria builder, SORT when advertised, paging, caps, post-filters per §2.6), `fetch` (structure-first), `thread`, alias scans | Criteria are always passed to imapclient as a list (never a raw string), so user text cannot inject IMAP syntax |
| `content/` | `mime.py` (bounded walk), `charset.py` (decode with fallback chain then `errors="replace"`), `headers.py` (RFC 2047/2231, size caps), `html.py` (strip hidden content, then `inscriptis`), `pdf_worker.py` (subprocess, `pypdf`), `truncate.py` | No network, no file writes. Every limit (`L-nn`) is enforced here or in `imap/` |
| `aliases/` | Resolve the recipient alias from configured headers in configured priority; exact and wildcard match; aggregation for `list_aliases` (R§5) | Off when an account has neither alias domains nor a plus separator |
| `server/` | `MCPServer` app, tool functions, pydantic output models, the untrusted-content envelope, `instructions=` text (passed by keyword) | Registers read tools only. There is no code path that registers a write tool in this version |
| `cli/` | `click` app: `setup`, `auth set`, `accounts list`, `doctor`, `register claude-code / claude-desktop [--print]`, `serve` | Secrets are read with `getpass` (TTY) or from stdin with `--stdin`, never from argv |
| `registration/` | Client config discovery, backup, atomic JSON write, duplicate detection, the WSL Desktop launcher script (§9.6) | Never writes a secret, writes absolute launcher paths only |
| `limits.py` | The `L-nn` ceilings as one frozen model, merged with `[limits]` (lower only) | Imports nothing from mailferret, so `content/` and `imap/` can enforce limits without depending on `server/` |
| `logging.py` | stderr-only logging (stdout belongs to the MCP protocol), redaction filter | Every secret seen by `credentials/` is added to a process-wide redaction set in three forms: raw, IMAP-quoted, and the base64 `AUTHENTICATE PLAIN` blob; continuation lines are redacted while an AUTHENTICATE is in progress. No record contains a mail-derived string; detail is limited to IDs, sizes and codes (T-21). imapclient's own logging is pinned off (§2.2) |

### 2.1 Credentials and the WSL strategy

Resolution per account: `credential_backend = "keyring" | "command"` (default `keyring`).

- `keyring`: the platform backend (macOS Keychain, Windows Credential Locker, Secret Service). `detect.py` rejects the fail, null, chainer-with-no-real-backend and any plaintext backend; the probe then reports `unavailable`, and `get` raises `CredentialBackendUnavailable` with a hint to run `doctor`. `keyring` itself is not bounded (`keyring.get_keyring()` hung on a mute session bus, V3 E6), so no mailferret process calls it in-process (T-17):
  - Backend selection and detection (`detect.py`, `get_keyring()`), the D-Bus error mapping and every lookup or write run in a probe subprocess under the process rules of `command` below, bounded by `L-27`; `serve`, `doctor` and `auth set` use the same probe and bound. The probe alone also gets `PYTHON_KEYRING_BACKEND` and `XDG_CONFIG_HOME` when set, so the user's keyring backend choice holds; `doctor` prints the backend the probe chose (§2.1, WSL strategy below). The parent runs only the bus-address pre-check. The probe is started as `sys.executable -I -m mailferret.credentials.keyring_probe`, as the PDF worker is, so its `cwd` (the data dir) is not on `sys.path`. Its stdout carries the secret, capped at `L-22` and accepted only under the fail-closed rule below; `auth set` passes the secret on its stdin (the write rule of the spawn below). The process rules have Linux and WSL evidence only (V3), and no probe has run yet (below); the probe through Keychain and Credential Locker, and the Windows job object, are §10 item 23.
  - Secret Service pre-check, in the parent before the probe starts: `DBUS_SESSION_BUS_ADDRESS` unset is `unavailable`; there is no fallback discovery (such as `$XDG_RUNTIME_DIR/bus`), so keyring users export the variable. The value is a `;`-separated list and every entry is parsed. Only transport exactly `unix` with exactly one of `path`/`abstract` (plus `guid`) is accepted, and only accepted entries reach the probe. Anything else is `unavailable`: `unixexec:` (runs a program), `autolaunch:` (spawns `dbus-launch`), `tcp:`, `nonce-tcp:`, `launchd:`, and the listen-only keys `tmpdir`/`dir`/`runtime`; the only network connection mailferret makes is IMAP. A `path` that does not exist is `unavailable`.
  - Inside the probe, raw `FileNotFoundError`, `ConnectionError` and `TimeoutError` from the Secret Service connection are reported as `unavailable` (`CredentialBackendUnavailable` in the parent).
  - The probe's bound counts as tested only once B4 has a retained mute-bus repro (V3 E6).
- `command`: `credential_command.get = [argv]` prints the secret on stdout. `credential_command.set = [argv]` receives it on stdin. `auth set` stays the write path (R§7) through `set`. Process rules (T-17):
  - No shell; an absolute executable path resolved at setup; `cwd` = the mailferret data dir; a minimal env (`PATH`, `HOME`, `USER`/`LOGNAME`, locale, `GNUPGHOME`, `PASSWORD_STORE_DIR`, `XDG_RUNTIME_DIR`, `DBUS_SESSION_BUS_ADDRESS`, and on Windows `SYSTEMROOT`/`USERPROFILE`/`APPDATA`/`LOCALAPPDATA`) plus the account's `credential_command.env`. That map accepts only allowlisted variable names (`PASSWORD_STORE_GPG_OPTS`, `PASSWORD_STORE_DIR`, `GNUPGHOME`), so it cannot carry a secret; any other name is a schema error. The secret-name rule of the `config/` row applies to keys, not to these allowlisted names.
  - Spawn: `Popen` with `shell=False`, `stdin=DEVNULL` (a write, `credential_command.set` or the probe's, uses `stdin=PIPE`: a daemon writer sends the secret once under the same deadline, then closes the pipe, so the writer never delays the bounded return; only a child that also does not exit ends in `timeout`), `close_fds=True`, the minimal env, and on POSIX `start_new_session=True` (which also drops the controlling TTY); on Windows an own `ctypes` job object with kill-on-close (unverified, §10 item 23). Not `subprocess.run(timeout=…)`: on timeout it returns no result and leaves a grandchild holding the pipes.
  - Bound (`L-14`): daemon reader threads on the raw pipe fds with a stop flag, `killpg(SIGKILL)` at the deadline, joins bounded, never `communicate()` after a kill. `killpg` frees readers blocked by same-session descendants, but a descendant that calls `setsid` (as an on-demand gpg-agent does) escapes it and may keep the pipes, so the return time never depends on the readers ending: at the bound the parent closes its pipe ends and returns.
  - Fail closed: the output is a secret only if the process exited 0, every reader reached EOF before the return, and stdout, once one trailing line ending (`\n` or `\r\n`) is stripped, is not empty and holds no CR, LF or NUL. A kill at the deadline or a reader not at EOF returns `timeout`; a non-zero exit that the `pass` classification below does not name `locked` or `not_found`, an empty result, or a CR, LF or NUL, returns `error` with fixed text, so a multi-line `pass` entry is refused, not cut. Every buffer is then discarded and nothing is sent: a bad secret would cost a failed login (T-16), and over AUTHENTICATE PLAIN it would send the whole entry. Readers enforce `L-22` on stdout while reading; on a breach they kill the group and return `limit_exceeded`. Stderr may contain the secret: its reader keeps the first `L-28` bytes for the classifier and drops the rest, and none of it leaves the classifier: not logged, not returned, not in exceptions. `auth set` and `setup` refuse, before any spawn and for both backends, a secret this rule or `L-22` would refuse on `get` (fixed-text `error`).
  - `pass` recipe: closing stdin does not stop a pinentry (gpg-agent spawns it outside this process tree), so `PASSWORD_STORE_GPG_OPTS` carries `--pinentry-mode=error`: a locked store fails at once and a warm cache still decrypts (V3). **Decided (B5):** the recipe applies when the basename of `argv[0]` is `pass`, on POSIX only. Its gpg status channel, separate from stderr, is a pipe passed with `pass_fds` and named in `--status-fd=<n>` (appended after the user's options, with `LC_ALL=C`); a daemon reader keeps the first `L-29` bytes under the `L-14` deadline and the pipe is closed at the bounded return like the others, since a descendant can hold it too. `--status-file` was not chosen (a private path, cleanup, and a child-controlled write size); on Windows no recipe is applied, so there is no `locked`. A direct `gpg` argv is not recognised. The user's `PASSWORD_STORE_GPG_OPTS` is an allowlist of exact tokens: `--pinentry-mode=error`, `--quiet`, `--no-tty`; any other token is refused before the spawn. Status lines carry key user IDs (`USERID_HINT`, `ENC_TO`), so, like stderr, they never leave the classifier.
  - Classification (`pass`): `locked` is a non-zero exit with `[GNUPG:] ERROR pkdecrypt_failed <n>` where `n` is gpg-agent source with `GPG_ERR_NO_PIN_ENTRY` (`67108949`); `NO_SECKEY` and `DECRYPTION_FAILED` are not lock signals. Any other code, or no status line, is `error`. `not_found` is exit 1 with `pass`'s own `is not in the password store`. Stderr text is matched only when the child ran under `LC_ALL=C`, and for `locked` only as confirmation.
  - Binding record (B5): `set` validates its argv and env, then removes the account's record, runs the command, and writes the record (0600, in the data dir) only on success, so a failed or ambiguous write leaves none. `get` checks it before any spawn: a missing or mismatched record is `not_found`. `delete` removes only the record, since the user owns the store. `describe()` reports `secure` only when the `pass` recipe applies.
- The `command` argv lives in the config, so write access to the config means code execution as the user. That is the same-user boundary SECURITY.md places out of scope; `doctor` prints the configured argv so a change is visible.
- No env-var backend (it would end up in client config `env`, R§8). Tests inject an in-memory backend through the same protocol.

On WSL, `setup` detects that no usable keyring exists and proposes `command` with a `pass` recipe (the decided default, §11; V3 verified it at the `pass`/gpg level, §10 item 7). `doctor` reports the backend in use, whether it is secure, and the result of a timed lookup (found / not found / locked / timeout / error) without printing the secret.

### 2.2 Connection layer

- TLS modes: `implicit` and `starttls`. There is no plaintext mode. The context comes from `ssl.create_default_context()`; `ca_file` is then added with `load_verify_locations()`, so it extends the system store instead of replacing it (passing `cafile=` to `create_default_context` would skip the system store). TLS 1.2 minimum, hostname checking on. No option disables verification (R§9).
- STARTTLS: refuse if not advertised, discard all pre-TLS capabilities after the upgrade, and treat bytes buffered before the handshake as a protocol error (T-07). imaplib's `starttls()` neither detects nor reliably discards such bytes (the behaviour differs between Python minors, V1), so a guarded `_command_complete` checks before the wrap, probing by feature, not version: the client read buffer (`_readbuf` if the attribute exists, else `file.peek(1)`; with neither, the upgrade fails), then the kernel buffer with `MSG_PEEK`, then the socket timeout is restored. Bytes arriving after the probe fail the handshake, so `LOGIN` is never sent.
- Capabilities are parsed once per connection into flags (`SORT`, `THREAD=REFERENCES`, `UIDPLUS`, `CONDSTORE`, `SPECIAL-USE`, `LOGINDISABLED`, `AUTH=PLAIN`, `IDLE`), and the query layer, `auth/` and the guard branch on them (R§11). imapclient is never shown `LITERAL+` (§6). ESEARCH is not used: imapclient does not expose it (§10 item 2).
- Read caps (T-08): every byte of a command's response counts against its response total, literals in `read` and lines in `readline`. Each line is also charged a fixed per-line overhead, at least what imaplib keeps for one minimal untagged line (dict key, string, list entry; D2 sets it from a `tracemalloc` measurement on every minor), so the total bounds what imaplib keeps, not only wire bytes. The overhead (`LINE_OVERHEAD_BYTES`) is a `limits.py` constant, not a `[limits]` key: lowering it would weaken the bound. The charge is split: `L-26` bounds the whole response (literals plus lines with their overhead), and `L-32` bounds the line bytes alone (each line plus `LINE_OVERHEAD_BYTES`; literals do not count), because lines are what imapclient parses and amplifies. Per command the caller sets the literal cap, the fetched item's limit (`L-05` header, `L-02` part, `L-08` attachment, `L-01` full fallback; default `L-05`), the total `n × (c + L-20) + L-20`, clamped to `L-26`, and the line total, clamped to `L-32`: for a command that fetches no message items it is `min(L-32, L-20 + L-21 × (overhead + LIST_LINE_ALLOWANCE_BYTES))`, for a FETCH `min(L-32, n × FETCH_LINE_ALLOWANCE_BYTES + L-20)` (`LIST_LINE_ALLOWANCE_BYTES` and `FETCH_LINE_ALLOWANCE_BYTES` are `limits.py` constants, not `[limits]` keys; the latter proposed, re-measured in D5; `merge` rejects an `L-32` below `L-20` plus `FETCH_LINE_ALLOWANCE_BYTES`, so one message always fits a batch). The total's terms: `n` messages fetched, `c` the literal cap of the fetched literal item (0 for items without one, such as `BODYSTRUCTURE` or `ENVELOPE`), and `L-20` as the line allowance (proposed, pending D2 and D5), one per message plus one for the tagged completion and unsolicited lines. A command that fetches no message items (SEARCH, LIST, STATUS, …) gets `L-26` as its total. Both reset in `_new_tag`, which also empties `untagged_responses`, so entries imapclient never consumes do not pile up across commands; what imapclient reads after a command (such as CAPABILITY after LOGIN) stays until the next command starts. `read(size)` aborts before reading a literal over the cap or past the total; `readline` aborts once the total or the line total is passed. Every multi-message FETCH is split so its unclamped total fits under `L-26` (§2.6), and a single message that cannot fit is not fetched (a `limit_exceeded` note naming L-26). So a response in which each message, with its lines' overhead, stays within `c + FETCH_LINE_ALLOWANCE_BYTES`, and whose batch stays within `n × FETCH_LINE_ALLOWANCE_BYTES + L-20` of line bytes, never breaches; a breach is hostile. Batch sizing (`max_messages`, D5) must keep both: it returns the `n` with `n × FETCH_LINE_ALLOWANCE_BYTES + L-20 ≤ L-32` and an unclamped total under `L-26`, and a message whose lines exceed its allowance is not served by a batch (D5 fetches it alone or reports `limit_exceeded`). Lines: `imaplib._MAXLINE` is set from `L-20` once at startup (process-global; `L-20` exceeds the stdlib default); an over-long line raises `imaplib.error` after a bounded overshoot, and the `readline` hook also checks every line it returns against `L-20`. A breach raises a typed mailferret error that maps to `limit_exceeded`, never imaplib's `abort`, which imaplib also raises for EOF; the `readline` hook translates the `_MAXLINE` `error` into it. `abort` discards the session, and only a drop is re-opened (Reconnect, below); a breach, guard or liveness failure and a timeout fail the call (SECURITY §5). After login, a tagged NO/BAD keeps the session and maps to `not_found` or `server_error` for that call or message, and so does a `ProtocolError` raised after the tagged completion was read; one raised before it discards the session, since the rest of the response would be taken for the next command's (T-08). A tagged NO/BAD to STARTTLS or LOGIN/AUTHENTICATE discards the session (T-07, T-16), and so does any other imaplib `error`.
- imapclient logging (T-03, T-21): `debug` is a property that reads 0 and ignores sets (imapclient sets it after construction), and the `imapclient` logger is set to `CRITICAL + 1` with `propagate = False` and a `NullHandler`; both are required, since a WARNING pin still reaches stderr through `logging.lastResort`. An imapclient `Address` is never stringified (addresses are formatted in `content/`). imaplib/imapclient exception messages and tracebacks carry server text, so they are never logged or formatted: `imap/` maps them to fixed error codes.
- Private API, failing closed (SECURITY §3 R5). The guard (§6), the read caps and the STARTTLS probe hook imaplib/imapclient internals. imapclient is pinned exactly; imaplib comes with whichever interpreter runs, so the hooks check themselves. The required hook set, defined here only:
  - Methods and globals, checked by `imap/` before the first connection in every process (`serve`, `setup`, `doctor`): imapclient's `IMAPClient._create_IMAP4` (installs the mixin) and `has_capability` (hides `LITERAL+`, §6), and `_create_socket` of `IMAP4WithTimeout` and `IMAP4_TLS` (the guarded classes override it to hand the new socket to the `L-13` deadline, so `expire` can shut a connect in progress down; a connect whose socket never reached the handle is refused); on imaplib's `IMAP4` `_new_tag`, `send`, `_command` (a clearer error only), `read` and `readline` (caps), `_command_complete` (the STARTTLS probe, the tripwire) and `_log` (overridden to keep nothing: imaplib's ring of the last ten command lines would hold a LOGIN, T-02; absent under `python -O`, where `_cmd_log` does not exist either), each a callable with the overridden signature; the module global `imaplib._MAXLINE`, an int. A miss or a changed shape refuses to connect.
  - Instance attributes, checked on each connection before STARTTLS or LOGIN: `untagged_responses`, a dict (reset in `_new_tag`, read caps above); `tagre`, a compiled pattern with `tag` and `type` groups (the tagged completion, read in `readline`; absent or reshaped, the session is discarded); for STARTTLS, the probe's read buffer, `_readbuf` or a callable `file.peek`, one requirement that either satisfies; with neither, the upgrade fails.
  - An override, not a lookup: `debug` is a property on the mixin; the per-connection check asserts it reads 0 after imapclient has set it.
  - Liveness, on every connection before LOGIN: the greeting passed the `readline` hook; the first CAPABILITY was vetted in `send` and completed through the hooked `_command_complete`; with STARTTLS, `connect()` requires the probe's flag before `login`. For the session's life: a line ending in `{n}` that `readline` returns must be followed by the hooked `read(n)`; `readline` checks `L-20` on every line it returns, so a minor that ignores `_MAXLINE` still fails; and a tagged completion in `_command_complete` for a tag whose command line the guard never vetted aborts the session (the tripwire). These checks detect a bypass after its bytes have left. The greeting, CAPABILITY, tripwire and STARTTLS checks guarantee that no LOGIN follows a session whose hooks did not run. The `read(n)` and `L-20` checks fire at the first literal or over-long line, after it has been read, so on a minor that bypasses them the literal caps, the `L-20` overshoot and the `L-26` total do not bound that first read; the every-minor tests (PLAN §3.3) are the guarantee there.
  - Every failure of these checks or of the probe raises a typed mailferret error that discards the session and is never reconnected.
  - The guard (wire survey, send gate), read-cap, logging-pin, STARTTLS-probe, self-check and liveness tests run on every supported Python minor (PLAN §3.3).
- IDLE later: sessions are created by a `SessionFactory`, and `ReadOnlySession` has no state tied to request handling, so a future `IdleWatcher` opens its own dedicated connection per account with the same factory and pushes events through a callback interface. The command connection is never shared with IDLE.
- Reconnect: only a dropped connection (imaplib's own `abort` for EOF or a socket error, never one raised by a hook) is re-opened, once per tool call. Never reconnected: a typed mailferret error (a breach, a guard, liveness or probe failure); an `L-11` or `L-12` timeout, which discards the session and fails the call with `timeout`; the `L-13` shutdown (Deadline, below). A failure during the login phase (from sending LOGIN/AUTHENTICATE to its tagged response) ends the call with `timeout` or `server_error`, does not reconnect and sets no marker (default, pending D3; T-16). An explicit rejection sets the persistent marker (§2 `auth/` row), so no process retries it. The deadline marks the session before the shutdown, and a marked session is never re-opened. Test: a breach, an `L-11` and an `L-12` timeout, and the `L-13` shutdown each give one connection attempt and at most one LOGIN in that call, and no connection is used after the deadline: DNS and the TCP connect cannot be interrupted, so a socket they open after the deadline is closed unused with nothing sent.
- Deadline (`L-13`): a worker thread running synchronous imapclient cannot be cancelled, so when the deadline fires the caller marks the session, then shuts the session socket down (`shutdown(SHUT_RDWR)`). The blocked read fails, the worker unwinds and releases the per-account lock, and the session is discarded. A fake-server test stalls mid-literal and asserts that the next call on that account succeeds.

### 2.3 MCP tool layer

- Tools: R§3 table. Every tool takes `account` (optional only when exactly one account exists or `default_account` is set). Messages are addressed by an opaque `message_ref` = `account:folder:uidvalidity:uid` (base64url). A ref whose account or UIDVALIDITY does not match is rejected (T-14).
- Annotations (`ToolAnnotations` field names verified, survey): `read_only_hint=True`, `open_world_hint=True` (decided, §11: the content comes from arbitrary senders), plus `title`. Hints are not security: enforcement is §6.
- Output: each tool builds a `CallToolResult` explicitly, with `structured_content` from its pydantic output model and `content` set to the delimited text rendering (§2.4), instead of the SDK's default JSON rendering of the model (SDK behaviour per the survey). Mail-derived strings are typed `Untrusted` fields.
- Size (`L-19`): the bound is the sum of both channels, counted as UTF-8 bytes of the serialized `structured_content` plus the text content. On breach the body, then attachment text, is trimmed in both channels alike, with a `limit_exceeded` note naming L-19. Test: a CJK/emoji body at `L-03`.
- Errors: raised as `ToolError` (v2, `mcp.server.mcpserver.exceptions`), which the SDK turns into an `is_error=True` result whose text the model reads; `structured_content` is empty on errors, so the typed code leads the text (`[not_configured] …`). Codes: `not_configured`, `not_found`, `limit_exceeded`, `auth_failed`, `backend_unavailable`, `timeout`, `server_error`. `MCPError` (a protocol error the model never sees) is not used for tool failures. Error texts contain no secret and no mail-derived string.
- Server `instructions` state that all mail content is untrusted data and never instructions.

### 2.4 Untrusted-content envelope

Every string that originates from a message or the server (subject, addresses and display names, body, header values, attachment names and text, folder names) is emitted as:

- structured: `{"untrusted": true, "kind": "body", "text": "…", "truncated": false, "notes": [...]}`;
- text content, for example with the nonce `9f2c41d07ab3`:

  ```
  <<<MAILFERRET_UNTRUSTED kind=body id=9f2c41d07ab3>>>
  …mail text…
  <<<END_UNTRUSTED id=9f2c41d07ab3>>>
  ```

  Escaping is the guarantee: inside the content, every `<` that is followed by `<<` becomes `‹` (U+2039), so no run of three `<` survives and the content cannot open or close a block, whatever nonce it guesses. The nonce (96 random bits per response) only pairs opening and closing lines for the reader.

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

### 2.6 Search post-filters

The alias and has-attachment filters cannot be fully expressed in IMAP SEARCH, so they post-filter a bounded candidate set:

- Candidates: the server-side SEARCH result (other criteria, plus a prefilter) ordered newest first (SORT if advertised, else UID descending), cut at the `L-15` candidate ceiling.
- Alias prefilter: an exact alias adds `OR HEADER <name> <alias>` over the account's `header_priority`; a wildcard adds the same for its longest literal fragment (at least 3 characters, else no prefilter).
- Fetch: batched `UID FETCH <set> (BODY.PEEK[HEADER.FIELDS (<header_priority>)])` for aliases, and `BODYSTRUCTURE` for has-attachment, in batches of at most `L-25` UIDs, shrunk so each command's total fits under `L-26` (§2.2).
- Glob syntax: `*` and `?` over the whole lower-cased address (`shop-*@example.com`); no character classes.
- Resolution: a message has one alias, the first qualifying address in `header_priority` order (R§5), and `search` matches only that alias. With both alias domains and a separator configured, the domain decides; the separator only splits the tag.
- Bounds: the scan stops at the candidate ceiling or when `L-13` is near; either sets `truncated: true`, so "no match" is never reported for an incomplete scan. Input bounds: pattern length and search-text length `L-23`, criteria count `L-24`.
- Response lines (every `search`, not only post-filters): without ESEARCH a `UID SEARCH` or `UID SORT` response is one line holding every match, so searches run over windowed UID ranges, newest first, each small enough to stay under `L-20`. Results are ordered within a window, and windows follow each other by UID range, newest first, so a SORT key other than arrival orders each window, not the whole result. The paging cursor carries the current window's UID range and the position in it. `L-20` is never raised to fit a response; a line that still overflows is hostile (§2.2, SECURITY §5).

## 3. Data flow: `get_message`

1. **MCP** `get_message(account, message_ref, max_chars?)` arrives over stdio. pydantic validates the input. `max_chars` is clamped to `≤ L-03`.
2. **server** decodes the `message_ref` and checks that its account equals the `account` argument. It takes the per-account lock and runs the rest in a worker thread, under a whole-call deadline (`L-13`).
3. **imap** reuses or opens the session: TCP connect (`L-11`) → TLS verify → CAPABILITY → hook liveness checks (§2.2) → `auth/` (auth-failed marker check → mechanism choice from the post-TLS capabilities, §2 `auth/` row → `credentials/` get → `isascii()` check → LOGIN or AUTHENTICATE PLAIN; secret added to the redaction set, local reference dropped) → CAPABILITY again.
4. **query** `EXAMINE folder` (never SELECT) → compare UIDVALIDITY with the ref → `UID FETCH uid (RFC822.SIZE FLAGS INTERNALDATE BODYSTRUCTURE BODY.PEEK[HEADER])`. The command's literal cap is `L-05`, enforced on read (§2.2).
5. **content** parses BODYSTRUCTURE into a bounded tree (`L-06` depth, `L-07` parts) and picks the text part (prefer `text/plain`, else `text/html`).
6. **query** `UID FETCH uid (BODY.PEEK[<section>]<0.L-02>)`. The command's literal cap is `L-02`, enforced on read regardless of what the server returns (T-08). If BODYSTRUCTURE is unusable, it falls back to `BODY.PEEK[]` (literal cap `L-01`) only when `RFC822.SIZE ≤ L-01`, otherwise it returns headers plus a `limit_exceeded` note.
7. **content** decodes the transfer encoding → charset chain → for HTML, strips hidden content and converts to text → removes `Cf` controls → truncates at `max_chars` on a codepoint boundary (an incomplete tail from a partial fetch is dropped by an incremental decoder).
8. **aliases** resolves the recipient alias if enabled.
9. **server** builds `MessageResult` (headers, `body: Untrusted`, attachments metadata, `alias`, `truncated`, `notes`), wraps it in the envelope and returns a `CallToolResult` with both channels, bounded by `L-19`.

`\Seen` is never set (EXAMINE + PEEK only, R§11). This is asserted against GreenMail.

## 4. Extension points

| Point | Mechanism |
|---|---|
| Provider presets | Data entries in `providers/presets.toml` or `[presets.<name>]` in user config |
| Credential backends | `CredentialBackend` protocol; new backends are registered in `credentials/registry.py` (no plugin loading via entry points, so arbitrary installed packages cannot inject a backend) |
| Auth mechanisms | `Authenticator` protocol (`XOAuth2Auth` next, with token storage through `credentials/`) |
| Attachment extractors | `content/extractors` registry keyed by MIME type; each one runs under the same byte, char and time limits (the attachment fetch's literal cap is `L-08`, §2.2) |
| Notifications | `SessionFactory` + `IdleWatcher` (§2.2) |
| Write/SMTP | §2.5 |
| Client registration | `registration/clients/<client>.py` implementing `discover()`, `render()`, `write()` |

## 5. Platform support matrix

| | Linux | WSL2 | Windows native | macOS |
|---|---|---|---|---|
| Config dir | XDG config | XDG config (Linux side) | `%APPDATA%\mailferret` | `~/Library/Application Support/mailferret` |
| Default credential backend | Secret Service via `keyring` | decided: `command` (`pass` recipe); Secret Service if `doctor` finds a working one | Windows Credential Locker | Keychain |
| `register claude-code` | yes | yes | yes | yes |
| `register claude-desktop` | not targeted | writes the Windows-side config: launch via absolute `wsl.exe … --exec <abs launcher script>` (§9.6) | regular config path (documented); MSIX requires `--desktop-config` (§10 item 21) | yes (documented path) |
| Plugin | yes | yes | yes (needs `uvx` on the client PATH) | yes |
| Plugin in Cowork | unverified (§10 item 14) | unverified | unverified | unverified |
| CI unit tests | yes | covered by Linux, plus WSL detection unit tests with a faked `/proc` | yes | yes |
| CI GreenMail integration | yes | — | — (Linux runners only; decided, §11) | — (Linux runners only; decided, §11) |

## 6. Read-only enforcement in the server

Client hints and plugin hooks are advisory. The guarantee lives in `imap/`:

- **Hook point.** One guard mixin for imaplib's `IMAP4WithTimeout` and `IMAP4_TLS` (implicit TLS does not use the former), installed by an `IMAPClient._create_IMAP4` override. `_command` is not a choke point: imapclient sends SEARCH, SORT, THREAD and APPEND through `_new_tag` + `send`. So `_new_tag` arms the guard and every `send` passes it; `_command` is overridden only for a clearer error.
- **Command allowlist.** The first `send` after `_new_tag` must parse as `tag [UID] VERB` and is vetted before any byte is written. Allowed: `CAPABILITY`, `NOOP`, `LOGOUT`, `STARTTLS`, `LOGIN`, `AUTHENTICATE`, `ID`, `NAMESPACE`, `LIST`, `LSUB`, `STATUS`, `EXAMINE`, `CLOSE`/`UNSELECT` (both safe after EXAMINE), and `SEARCH`, `FETCH`, `SORT`, `THREAD` as plain or `UID` commands. `IDLE`/`DONE` are added when IDLE ships. Everything else (`SELECT`, `STORE`, `COPY`, `MOVE`, `EXPUNGE`, `APPEND`, `CREATE`, `DELETE`, `RENAME`, `SUBSCRIBE`, `SETACL`, `ENABLE` …) raises `ReadOnlyViolation` before any byte is sent, with a fixed reason and never the line's bytes (the line may be a LOGIN).
- **FETCH item allowlist.** Only `UID`, `FLAGS`, `INTERNALDATE`, `RFC822.SIZE`, `ENVELOPE`, `BODYSTRUCTURE`, `RFC822.HEADER`, and `BODY.PEEK[...]` with an optional partial. `BODY[`, `RFC822`, `RFC822.TEXT` are denied (they set `\Seen`). An allowlist, not the spike's denylist.
- **Send gate (fail closed).** The armed line may contain no CR or LF before its closing CRLF (imaplib itself refuses them only on 3.13+) and must end in CRLF, except SEARCH, SORT and THREAD: imapclient sends their line unterminated and the CRLF separately, so only they may leave the line open or announce a literal. A line ending in `{n}` or `{n+}` is an announcement whatever precedes it (`({n}` included); an unterminated or literal-bearing FETCH is refused, and so is every `{n+}` (below). `_new_tag` refuses to re-arm while a command is open, awaiting a continuation, in a literal, in AUTHENTICATE or in IDLE. After the armed line only these `send`s are allowed: literal bytes of the announced length (only after this tag's `+`), a space, a fragment without line breaks (SEARCH/SORT/THREAD), the closing CRLF, AUTHENTICATE replies (matched with `fullmatch`), and `DONE` in an active IDLE. A tagged completion closes the gate. A failed vet leaves the gate armed, so a later `send` is parsed as a command line; the gate is reset on abort and reconnect.
- **`{n+}` refused.** LITERAL+ bytes leave before the server has accepted the announcing line and cannot be vetted, so a server that rejects the line would run them as a command (a SEARCH ending `{n+}` whose literal carries `UID STORE … \Seen`). The gate raises on any `{n+}`, advertised or not; that is the guarantee. `ReadOnlySession` also reports no `LITERAL+` through imapclient's `has_capability`, which only steers imapclient to send every literal synchronously, gated on this tag's `+`.
- **Type boundary.** `ReadOnlySession` exposes only the read methods. The raw client is a private attribute and is never returned.
- **Proof.** A recording fake IMAP server test drives every tool with every option and compares the wire with the allowlist, not with the guard's own log: no denied verb or FETCH item appears. Send-gate tests per SECURITY §3. A GreenMail test asserts flags are unchanged after every tool.

## 7. Config schema

Location per R§6, override with `MAILFERRET_CONFIG` or `--config`. An override naming a missing file means no accounts (`not_configured`), never a fallback to the default location. Account ids match `^[a-z0-9][a-z0-9_-]{0,31}$`.

```toml
schema_version = 1
default_account = "work"            # optional

[limits]                            # optional; keys and ceilings in SECURITY.md §5; values may only lower them
max_body_chars = 50000              # L-03
max_page_size = 100                 # L-15

[accounts.work]
preset = "generic"
host = "imap.example.com"
port = 993
tls = "implicit"                    # implicit | starttls
login = "user@example.com"
credential_backend = "keyring"      # keyring | command
# ca_file = "/path/to/ca.pem"       # added to the system trust store; verification stays on

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
env = { PASSWORD_STORE_GPG_OPTS = "--pinentry-mode=error" }   # allowlisted names only (§2.1)

# Reserved, rejected when enabled in this version:
# [accounts.work.write]  enabled = false
# [smtp]
```

## 8. Dependencies

Choices, versions, release dates and vetting live in `docs/research/library-survey.md` (one dated snapshot, the only copy). Runtime: `mcp` (v2, `>=2.3,<3`), `imapclient` (pinned exactly, §2.2), `inscriptis` (+ `lxml`), `pypdf` (no extras), `keyring` (+ its vetted platform transitives), `platformdirs`, `click`, `pydantic`, `tomlkit`. Dev: `ruff`, `mypy`, `pytest`, `hypothesis` (dev-only, MPL-2.0, survey); GreenMail in Docker; `uv` as the launcher. No dependency outside the survey's vetted table (R§10, SECURITY §6).

Python floor `>=3.13`. Rejected: fastmcp, aioimaplib, html2text, pymupdf, tomli-w, keyrings.alt (survey). Not added: charset detection libraries (the stdlib fallback chain is enough, R§11), justhtml (optional fallback only if inscriptis fails vetting later).

## 9. Claude Code plugin

### 9.1 Repo layout

```
pyproject.toml  uv.lock  src/mailferret/  tests/          # PyPI package
.claude-plugin/marketplace.json                          # repo is its own marketplace
plugin/                                                  # plugin root (marketplace source "./plugin")
  .claude-plugin/plugin.json
  .mcp.json
  constraints.txt                                        # generated, §9.4
  skills/doctor/SKILL.md
  agents/mail-reader.md
  evals/                                                 # `claude plugin eval` cases and mocks (§9.8)
docs/  .github/workflows/
```

The plugin lives in `plugin/` rather than the repo root. With `source: "./"` the whole repo (sources, tests, the malicious-mail fixture corpus) would be copied into every user's plugin cache. A subdirectory keeps the cache down to what the plugin needs at runtime, and leaves no top-level `bin/` (claude.ai and Cowork refuse a plugin with one). Evals must sit inside the plugin (§10 item 20), so they ship in every plugin cache and hold synthetic `example.com` data only; the injection mail is generated at eval time and never ships (§9.8). Bomb fixtures are generated at test time, never committed.

### 9.2 Launch

`plugin/.mcp.json`:

```json
{"mcpServers": {"mailferret": {"command": "uvx", "args": ["--constraints", "${CLAUDE_PLUGIN_ROOT}/constraints.txt", "--from", "mailferret==X.Y.Z", "mailferret", "serve"]}}}
```

- The exact pin is required: it keeps the server, the constraints file and the plugin version in lockstep, and it rules out uvx serving a cached older version (that uvx behaviour is the plugin spec's *inference*, not verified). `--from pkg==ver cmd` is the documented uvx form (survey); the shorter `uvx pkg==ver` is not relied on.
- `--constraints`: uvx ignores `uv.lock`, so without it plugin users would resolve unlocked transitive dependencies (the large `mcp` tree included) at install time. The constraints file is generated with `uv export` from the lock of the pinned release, so users run the exact set CI tested and the audit scanned. Both facts behind this are verified (§10 item 16): `--constraints` applies to the `--from` tool environment, and `${CLAUDE_PLUGIN_ROOT}` expands inside `args`. Chosen over `--exclude-newer`: a date cutoff still resolves versions CI never saw and cannot be audited as a list. V4 proposes `--exclude-newer <release timestamp>` as an additional pin; whether to add it, which would put the timestamp into the version set (§9.4), is P1's decision. Cost: transitive fixes reach users only through a mailferret release, so the scheduled audit runs against the shipped constraints file (T-13).
- No `env`, no `userConfig`: the server reads its own config file. Cowork ignores servers whose options have no default, and an unset `${…}` stays literal (§10 item 15). Evals never inject a config (§9.8).
- Tool names: `mcp__plugin_mailferret_mailferret__<tool>` (the server key is `plugin:mailferret:mailferret`). The agent and skill use these names, enumerated. A manual registration's tools are `mcp__mailferret__<tool>` (§9.5).
- **The absolute-path gap (R§11).** `.mcp.json` cannot carry an absolute `uvx` path, so a missing launcher on the client PATH is a silent start failure. No mailferret process can observe the client's PATH from outside it. The coverage is the `doctor` skill (§9.7), whose ground truth is whether the mailferret tools are present in the session. The README covers putting `uvx` on the PATH the client inherits, per platform.

### 9.3 Credentials

Keyring (or the `command` backend) stays the single source of truth. Plugin `userConfig` carries no secrets, and in fact no options at all in this version. Reasons: one write path (`mailferret auth set`, R§7) for every client; a `sensitive` userConfig value would reach the server through `env`, readable by same-user processes and inherited by children; Cowork never prompts; and a second store would diverge silently from the first.

There is no setup skill. A secret must never pass through the model, so the guard sits in the CLI and the server (SECURITY T-20):

- `auth set` and `setup` refuse when stdin is not a TTY, unless `--stdin` is given. `getpass` itself silently falls back to reading stdin without a TTY, so the TTY check happens before it is called.
- `--stdin` is refused when `CLAUDECODE=1` or `CLAUDE_CODE_CHILD_SESSION` is set, i.e. when an agent's Bash tool pipes the secret in (§10 item 19). Claude Code also sets `CLAUDECODE=1` in IDE terminals and hooks, so a human piping a secret there is refused too: an accepted false positive (use the TTY prompt). This is a speed bump against accidents, not a boundary: an agent can unset the variables.
- Every tool returns `not_configured` when no account exists or an account has no stored secret. Its text names the terminal command to run (`mailferret setup` / `mailferret auth set <account>`) and says never to paste a password into the chat.

### 9.4 Versioning and release

- `pyproject.toml` leads. The plugin version set is: `plugin.json` `version`, the `.mcp.json` pin, the pins in the `doctor` skill (command and `allowed-tools`), and `plugin/constraints.txt`. All of them always refer to one released PyPI version, so the plugin lags `pyproject.toml` by one PR after each release.
- CI on every PR: every pin under `plugin/` equals `plugin.json` `version`, which is `≤` the `pyproject.toml` version; `plugin/constraints.txt` equals `uv export` (no dev, no project) of the lock at tag `v<plugin version>`. The release job (and a scheduled job) also checks that the pinned version exists on PyPI.
- Order (per the spec): a tag `vX.Y.Z` on main → trusted publishing to PyPI with attestations → a smoke job runs the exact plugin launch command with `--version` → a follow-up PR bumps all plugin pins, regenerates `constraints.txt` and bumps `plugin.json` `version` together → merge. Plugin users update only on that bump, so unreleased code on main never reaches them.
- Before the first PyPI release the plugin cannot launch, so the marketplace entry is added in the PR that follows the first release.
- `register`-written entries use the same mechanism: the wheel ships its own `constraints.txt` as package data, `register` copies it to the data dir as `constraints-X.Y.Z.txt` and references it by absolute path.

### 9.5 Duplicate registration policy

Plugin servers register as `plugin:mailferret:mailferret`, so a manual entry named `mailferret` does not shadow them by name (§10 item 6). If its command or args differ, which they always do for `register` output (absolute paths), both servers start: two processes, and two mailferret tool sets in the session (`mcp__mailferret__*` beside `mcp__plugin_mailferret_mailferret__*`). Only a manual entry with exactly the plugin's command and args (env ignored) suppresses the plugin server; the tools are then `mcp__mailferret__*` only, which breaks the plugin agent's `tools` allowlist and the skill's pre-approval. Policy:

- The plugin is the recommended Claude Code path. `register claude-code` detects an installed mailferret plugin and refuses unless `--force` (default, pending F2). Both the refusal and the `--force` path print the duplicate it creates and the exact command to disable or uninstall the plugin (`claude plugin disable mailferret@<marketplace>` / `claude plugin uninstall mailferret@<marketplace> [-s <scope>]`, §10 item 20).
- Detection: `claude plugin list --json` (an absent `claude` is tolerated), else the install record `~/.claude/plugins/installed_plugins.json`; ids with the prefix `mailferret@` match, `@builtin` ids are ignored. Project-scope installs are listed from any directory, with `projectPath`, but `enabled` reflects the current directory's merged settings only. The message reports each install's scope and `projectPath` and says that `enabled` is per directory.
- Reverse order (the plugin installed after a manual entry): `mailferret doctor` lists every registration it can see, and the `doctor` skill reports from inside the session a duplicate (both prefixes present) or a suppressed plugin server (`mcp__mailferret__*` only), with the `claude mcp remove` command for the manual entry.

`register claude-code` mechanism: it runs `claude mcp add-json --scope <user|project|local> mailferret '<json>'` through the absolute path of the `claude` CLI, so Claude Code owns its file format and locking. Before invoking it, `register` backs up the file that scope writes (`~/.claude.json` for user scope, top level, and for local scope, under the project; `<cwd>/.mcp.json` for project scope, §10 item 13) with the same timestamped, 0600 rule as direct writes (R§8, T-12). It never edits Claude Code's state files itself. Without the CLI it falls back to `--print`.

Launcher selection (all `register` targets):
1. `uvx` found and the running version is a release on PyPI (checked with a timeout) → `<abs uvx> --constraints <abs constraints> --from mailferret==<version> mailferret serve`.
2. Otherwise, if the running `mailferret` executable lives in a persistent environment (a `pipx`/`uv tool` install or a venv, not the uv cache) → `<abs mailferret> serve`. This covers `pipx` without uv and editable/dev installs.
3. Otherwise refuse; only `--print` is allowed.

`mailferret doctor` checks every visible registration (plugin, Claude Code scopes, Desktop): that its absolute launcher and constraints paths exist and are executable or readable, including the Linux-side launcher script of a `wsl.exe` Desktop entry and the `uvx` it runs, and that the script is owned by its `-u` user and neither it nor its parent directory is group- or other-writable (§9.6, T-11). It cannot see the client's PATH itself (§9.2).

### 9.6 Claude Desktop

Primary: `mailferret register claude-desktop` (backup, then an atomic merge into `claude_desktop_config.json`; `--print` shows the snippet only). Paths (documented, not checked on real installs, §10 item 21): macOS `~/Library/Application Support/Claude/`; Windows regular `%APPDATA%\Claude\`. An MSIX install (`%LOCALAPPDATA%\Packages\Claude_*\…`, the package family suffix globbed, never hard-coded) is detected, but its config path is not relied on: it requires `--desktop-config <path>`. From WSL it looks for those paths under `/mnt/<drive>/Users/*/` without running Windows binaries. If not exactly one candidate is found it requires `--desktop-config <path>`.

From WSL the entry runs a generated Linux-side launcher script, because how `wsl.exe` passes arguments with spaces or JSON is undocumented (§10 item 22): `command` = the absolute Windows path of `wsl.exe` (found under the drive mount, converted with `wslpath -w`), `args` = `-d <distro> -u <user> --exec <absolute launcher path>`, one JSON array element per argument. The script sits at a space-free absolute path and is `#!/bin/sh` plus one line, `exec <absolute uvx> --constraints <absolute constraints path> --from mailferret==X.Y.Z mailferret serve`, with every argument passed through `shlex.quote`, so those paths may hold spaces or shell metacharacters; it holds no env and no secret. `--exec` runs it without the distro's default shell; distro from `WSL_DISTRO_NAME`. `registration/` writes it like a client config (T-12: backup, atomic write), owned by the `-u` user, with neither it nor its parent directory group- or other-writable; `doctor` checks the same (§9.5, T-11). Where the script goes, and what happens when no space-free absolute path exists, is F2's decision (`docs/STATUS.md`).

`.mcpb`: deferred. The manifest format supports `server.type: "uv"`, but host support in Desktop is unverified (§10 item 5). If verified, ship an `.mcpb` with no `sensitive` user_config (keyring stays the source of truth, §9.3).

### 9.7 Plugin components

The adversarial review is done and its verdicts were accepted; Accepted at Checkpoint 1: the `mail-reader` agent and the `doctor` skill ship. The baseline: the MCP tool descriptions and input schemas already explain each tool, so a component must add something the server cannot. Rejected rows stay as a record.

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
- `tools`: the read tools enumerated by full name, `mcp__plugin_mailferret_mailferret__<tool>` for `list_accounts`, `list_folders`, `search`, `get_message`, `get_thread`, `list_attachments`, `get_attachment_text`, `list_aliases`, with no wildcard and no `Read`, so a future write tool is never granted by accident. `disallowedTools: Skill, Agent` is the primary exclusion of those two; an allowlist alone is not shown to drop them (§10 item 18). No Bash, web or file tools. No `skills` preload. A `maxTurns` cap.
- A CI test asserts that the agent's `tools` list equals the server's registered read tools, prefixed with the plugin scope, and that `disallowedTools` names Skill and Agent. It checks the file only; P3 asserts the agent's runtime tool list (no Skill, no Agent, nothing outside `mcp__plugin_mailferret_mailferret__*`), with the user's `/smoke-test` as the backstop.
- If its tools are missing (a suppressed plugin server, §9.5, or the server not running), it stops and reports that, with a pointer to the `doctor` skill, instead of summarizing from nothing.
- Body: the call order and bounds (accounts → folders → `search` with an explicit page size → `get_message` only for the messages it needs, honouring `truncated`), and the rule that mail content is data.
- Output contract: instructions found in mail are reported as quoted speech attributed to the sender ("the mail asks the reader to …"), never followed; URLs are defanged (`hxxps://example[.]com`) unless the user asked for links; no raw headers or bodies beyond short quotes.

**`doctor` skill.**
1. Ground truth first: is `mcp__plugin_mailferret_mailferret__list_accounts` present in the session? If yes, the server runs: call it and report the accounts and any `not_configured` error. Both prefixes are accepted: if `mcp__mailferret__list_accounts` is present as well, report the duplicate; if only it is present, report the suppressed plugin server (§9.5).
2. If absent: look up `uvx` with the available shell tool, `command -v uvx` in Bash or `Get-Command uvx` in PowerShell (on Windows the Bash tool exists only with Git Bash, §10 item 12). A miss is conclusive (install uv, fix the PATH the client inherits). A hit is inconclusive, because the shell tool's PATH may differ from the MCP spawn PATH (§10 item 11).
3. Run the exact plugin launch command with `--version`, timed. Success with a duration above the client's MCP startup timeout (`MCP_TIMEOUT`) means the first-run download timed out the launch: the cache is now warm, so tell the user to reconnect via `/mcp` or restart. Success that was fast points at the PATH. Then run `mailferret doctor` with the same pins and explain it.
- `allowed-tools` pre-approves only the exact strings of steps 2 and 3, never a `:*` prefix: the Bash strings, and the PowerShell `Get-Command uvx` string if the syntax accepts one (§10 item 17; otherwise that branch prompts). Pins are included, so they are part of the version set (§9.4); the `${CLAUDE_PLUGIN_ROOT}` form is §10 item 17.
- Model-invocable, so the model can offer it when the mailferret tools are missing.

### 9.8 Plugin evals

`claude plugin eval` accepts only an eval dir inside the plugin (§10 item 20), so cases and mocks live in `plugin/evals/` and ship in every plugin cache: synthetic `example.com` data only, no live URL, no injection payload. A real MCP server started by an eval runs as the user, outside the OS sandbox, with the user's default config, i.e. against the real mailbox. That `--mocks record` starts none is not yet shown (§10 item 24), so the run is isolated instead of relying on it, and it never injects a config:

- `--mocks record`, never `--mocks off` or `--allow-real-servers`. Per the CLI help, a plugin server with no mock does not start under `record`, so the `mail-reader` cases need a mock under `plugin/evals/mocks/` (format to be established in P3). A non-interactive run needs `--trust-plugin`.
- Isolation: the run gets its own `HOME` and `XDG_CONFIG_HOME` and a `MAILFERRET_CONFIG` that names a file that does not exist, which means no accounts, never the default path (§7), so a server that does start has no account to connect to. Evals run on POSIX only: on Windows the default config sits under `%APPDATA%`, which `HOME` does not move. Claude Code must still authenticate under the isolated `HOME` without a credential file copied into it; P3 documents how. If it cannot, the fallback keeps `HOME` and isolates through `XDG_CONFIG_HOME` and `MAILFERRET_CONFIG` alone. P3 asserts that no mailferret server process or IMAP socket starts (§10 item 24).
- `--no-publish` (reports publish to claude.ai by default). `--output-dir`, `--report` and `--json` point outside `plugin/` (`--output-dir` moves only the aggregate result); `plugin/evals/results/` is gitignored and kept out of the shipped plugin.
- Never `--scaffold`. `--allow-tools` names only the enumerated `mcp__plugin_mailferret_mailferret__<tool>` tools, never Bash, WebFetch, Write or Edit.
- The T-18 injection mail is generated at eval time into a gitignored path under `plugin/evals/`, so it never ships. It is synthetic `example.com` with no live URL, and its payload asks only for a harmless canary output, never a tool call, command or URL.

## 10. Phase 2 verification items

Each item belongs to a spike in `docs/PLAN.md` phase 2a (V1–V4; evidence in `docs/research/v*-*.md`). **Resolved**: verified, and the design follows. **Decided**: not verified, but the design no longer depends on it. **Open**: the named check and its owner; the design uses the stated fallback meanwhile.

1. Guard hook point, read-side literal and line caps, pre-STARTTLS bytes. **Resolved (V1):** a guard mixin armed in `_new_tag` and enforced on every `send` (§6); per-command literal cap and response total in `read` (lines join the total in `readline`, §2.2), `imaplib._MAXLINE` from `L-20`, and the STARTTLS probe by feature in `_command_complete` (§2.2). V1 covers the Python minors it ran; for any other supported minor, D1's and D2's every-minor tests are the check, and the hooks' self-check, liveness checks and tripwire fail closed (§2.2).
2. ESEARCH. **Resolved (V1):** imapclient does not expose it; not used. Plain `UID SEARCH` over windowed UID ranges (§2.6).
3. GreenMail capabilities. **Resolved (V2):** no STARTTLS, ESEARCH, CONDSTORE, THREAD or SPECIAL-USE, and `AUTHENTICATE PLAIN` does not authenticate. Those paths, and the PLAIN leg of `test_login_redaction`, run on the D0 fake server only (PLAN §3.2).
4. A `CallToolResult` from an `MCPServer` tool with an output model keeps our text content. **Resolved (V4):** yes, in memory and over stdio; the low-level fallback is dropped.
5. `.mcpb` `server.type: "uv"` in Claude Desktop. **Open (manual, a user on Windows and macOS):** host support is undocumented. WSL is not an `.mcpb` case: Desktop runs on the Windows host. Fallback in force: `register claude-desktop` only.
6. Plugin detection and same-name shadowing. **Resolved (V4):** `claude plugin list --json`, then the install record; a same-name manual server does not shadow the plugin server unless its command and args equal the plugin's (§9.5).
7. Headless credentials. **Resolved (V3) at the `pass`/gpg level:** `--pinentry-mode=error` fails fast on a cold or expired agent cache and a warm cache still decrypts; `locked` comes from gpg status codes; `killpg` frees same-session descendants, a `setsid` descendant escapes it, so the return is bounded without the readers; no bus discovery without `DBUS_SESSION_BUS_ADDRESS` (§2.1). **Resolved (B5), in local runs (Linux CI installs `pass`):** the plain, `gpg2`-on-PATH and `GPG_AGENT_INFO` branches of `pass`, each cold, warm and expired, in a throwaway `GNUPGHOME`, through the real spawn path; the `--use-agent` branch is shown by a `gpg` wrapper log; a locked store with the status fd above 9. **Open (manual, a user):** the same from a client- or `wsl.exe`-launched process. Fallback: `doctor` reports `locked`; a long gpg-agent cache TTL stays documentation only.
8. Dropped: no hook ships (§9.7).
9. Subdirectory plugin root on claude.ai/Cowork. **Open (manual, a user):** docs say a zip upload accepts the manifest in one top-level directory and refuses a top-level `bin/` (this layout has none). Fallback: Cowork stays unsupported; the README gives zip-upload instructions for claude.ai.
10. PDF worker caps. **Resolved (V1, C4):** the pypdf caps are `Configuration` fields (T-06). Linux: the worker applies `RLIMIT_AS` to itself before importing pypdf (asserted through the real entry point). Windows: the host's `ctypes` job object with a process memory limit is enforced on the windows CI runners. macOS refuses `setrlimit(RLIMIT_AS)` and an over-cap allocation succeeds, so there (and on Windows if the job object cannot be made) the bound is wall time plus the page, char and per-stream caps, and the result carries a `memory_cap_unavailable` note. The 100,000-page tree and the deflate bomb end `limit_exceeded`; a cyclic page tree ends `malformed` (pypdf's own check), all within the deadline.
11. Bash tool PATH vs MCP launch PATH. **Resolved for the MCP half (V4):** the stdio child gets the launcher's PATH. The Bash half is documented only, so `doctor` keeps treating a `uvx` hit as inconclusive.
12. `command -v` on Windows. **Decided (V4):** the Bash tool exists on Windows only with Git Bash, else PowerShell; the `doctor` skill branches on the available shell tool (§9.7).
13. `claude mcp add-json` flags and scope files. **Resolved (V4):** `-s local|user|project`, default `local`; `user` and `local` write `~/.claude.json`, `project` writes `<cwd>/.mcp.json` (§9.5).
14. Cowork stdio server on the host or in the sandbox VM. **Open (manual, a user):** docs say the host. Cowork stays "unverified" in §5.
15. `${VAR:-default}` in plugin `.mcp.json`; env inheritance. **Resolved (V4):** both work (set-but-empty yields the empty string). The eval isolation relies on env inheritance; no config is injected through `${…}` (§9.8).
16. `uvx --constraints <file> --from pkg==ver`; `${CLAUDE_PLUGIN_ROOT}` in `args`. **Resolved (V4):** the constraints apply to the tool environment (a conflicting constraint fails resolution), and the variable expands (§9.2).
17. `${CLAUDE_PLUGIN_ROOT}` in skill `allowed-tools`. Non-strict `plugin validate` accepts the exact pinned `--version` string. **Open (P2, P3):** P2 confirms it under `--strict`, validates the `mailferret doctor` string, and checks whether `allowed-tools` accepts the exact PowerShell string of the `doctor` skill's step 2; prompt-free execution needs a model run (P3). Fallback: the `doctor` skill's step 3 prompts, and so does its PowerShell branch if that string is refused.
18. An agent `tools` allowlist excludes Skill and Agent. **Decided (V4):** `disallowedTools: Skill, Agent` is primary (§9.7); non-strict `plugin validate` accepts it. **Open:** P2 confirms it under `--strict`; P3 asserts the agent's runtime tool list. Until P3 asserts it, the agent-allowlist mitigation of T-04 and T-18 is unverified.
19. `CLAUDECODE=1` in the Bash tool. **Resolved (V4):** set in the Bash tool and in stdio MCP children (per docs also in IDE terminals and hooks); `--stdin` is refused on `CLAUDECODE=1` or `CLAUDE_CODE_CHILD_SESSION` (§9.3). **Open (manual):** whether `CLAUDE_CODE_CHILD_SESSION` is set in a top-level session; it may add nothing.
20. Evals outside the plugin root; cache copy; disable/uninstall. **Resolved (V4):** `--eval-dir` must be a relative path inside the plugin, so evals live in `plugin/evals/` (§9.8); install copies only the plugin dir (a local-directory marketplace runs in place); `claude plugin disable <id>` and `claude plugin uninstall <id> [-s <scope>]`.
21. Claude Desktop config paths. **Decided (V4):** the documented macOS and regular Windows paths (§9.6). **Open (manual, a user):** real installs. MSIX is undocumented, so `--desktop-config <path>` is mandatory there.
22. `wsl.exe --exec` argument passing. **Decided (V4):** quoting of space paths and JSON args is undocumented, so the former fallback is the design: a generated Linux-side launcher script at a space-free absolute path, run via `--exec` (§9.6). **Open (manual, a user):** `-d`, `-u` and `--exec` on a real install.
23. Credential subprocesses off Linux. **Open (B4, B5; windows and macos CI runners):** V3 ran Linux and WSL only. The `ctypes` job object with kill-on-close (B4 for the probe, B5 for `command`), with Windows equivalents of the grandchild and `setsid` tests: a grandchild holding stdout past the deadline, and one that tries to leave the job with `CREATE_BREAKAWAY_FROM_JOB`. The keyring probe through Keychain and Credential Locker within `L-27` (B4). Meanwhile T-17 claims the process-tree bound on Linux only, and the probe's bound nowhere until B4's mute-bus repro.
24. Eval runs start no MCP server. **Open (P3):** that `--mocks record` starts no plugin server without a mock comes from the CLI help only; V4 ran `plugin eval` on a case-less plugin. P3 asserts that no mailferret server process or IMAP socket starts during an eval run, and that Claude Code still authenticates under the isolated `HOME`, documenting how without copying a credential file into it. Fallback in force: the isolated run (§9.8); if Claude Code cannot authenticate under a fresh `HOME`, the run keeps `HOME` and isolates through `XDG_CONFIG_HOME` and the missing-file `MAILFERRET_CONFIG` (§7).

## 11. Decisions (Checkpoint 1)

| Decision | Outcome | Why |
|---|---|---|
| License | MIT (decided; `LICENSE` added) | Matches every runtime dependency's permissive license; simplest for reuse |
| Dependency licenses | Runtime: permissive only (MIT/BSD/Apache/PSF-compatible). Dev/test-only: weak copyleft (MPL-2.0, LGPL) allowed if it passes the same health checks | Weak copyleft in a tool that is never shipped or imported at runtime does not touch the distributed code; `hypothesis` adopted dev-only (survey) |
| Plugin components | `mail-reader` agent and `doctor` skill ship (§9.7) | Accepted as designed |
| WSL credential backend | Decided: the `command` backend with a documented `pass` recipe (GPG-encrypted at rest, no D-Bus, works under `wsl.exe` launch). Fallback: `keyring` Secret Service when `doctor` finds a working, unlocked one (e.g. gnome-keyring or KeePassXC under WSLg) | See below |
| Desktop distribution | Decided: `register claude-desktop` now; `.mcpb` only after item 5 of §10 is verified | Format support is documented, host support is not |
| Plugin root | `plugin/` subdirectory | Keeps tests and fixtures out of plugin caches (§9.1) |
| Plugin `userConfig` | None | Single source of truth (§9.3) |
| Plugin dependency locking | `uvx --constraints` with a generated file | Exact, audited transitive set (§10 item 16 verified); a date cutoff alone is not a list (§9.2) |
| LICENSE copyright holder | Decided: the GitHub handle `DocGerd`, not a legal name | Minimises personal data in the repo; the handle already identifies the publisher |
| `open_world_hint` | `True` | Content comes from arbitrary senders; clients should treat the output as external |
| GreenMail integration scope | Linux CI only; Windows/macOS run unit tests and the fake server | Container support on hosted Windows/macOS runners is not something to depend on; the fake server covers the platform-independent protocol paths |

WSL options, scored against the constraints (headless stdio child, a locked store must fail fast, `auth set` is the write path, no new unvetted dependency, no secret in client `env`):

| Option | Headless fit | Locked → fails fast | `auth set` works | New dep | Verdict |
|---|---|---|---|---|---|
| Secret Service via gnome-keyring under WSLg | needs a session bus, a running daemon and an unlocked collection; none is guaranteed under `wsl.exe` launch | the unlock prompt may hang or pop up a window, and `keyring` hung on a mute bus (V3), hence the bounded probe (§2.1) | yes | none (`keyring` → `secretstorage`/`jeepney`) | fallback, when detected working |
| `pass`/GPG via the `command` backend | gpg-agent starts on demand, no bus | yes: `--pinentry-mode=error` fails at once on a cold or expired cache (V3, §10 item 7), plus the process-tree timeout | yes, via `set` argv | none in Python; `pass` + `gnupg` are distro packages | **decided default** |
| Windows Credential Manager via interop | breaks when interop is disabled or PATH ordering changes; `cmdkey` cannot read secrets, so it needs a PowerShell P/Invoke script | the PowerShell startup cost is paid on every call | needs a second script | none, but a fragile Windows-side script | reject as built-in; a user may wire it through `command` at their own risk |
| Encrypted file + passphrase | the passphrase must still reach a headless process, so the problem only moves | — | yes | crypto code to own | reject |
| Env var / command fallback | env ends up in client `env` (R§8) and `/proc/<pid>/environ` | — | no | none | env: reject; command: this is the decided default above |

`doctor` reports: backend type and class; `secure: yes/no`; WSL detected; for `command`, the resolved absolute path and a timed lookup result (`found`, `not_found`, `locked`, `timeout`, `error`); for `keyring` on WSL, the bus-address pre-check result (§2.1) and collection lock state.
