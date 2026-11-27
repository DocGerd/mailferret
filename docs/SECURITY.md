# mailferret security design

Implements R§9 and R§11 (`R§n` = a section of `docs/REQUIREMENTS.md`, `A§n` = `docs/ARCHITECTURE.md`, bare `§n` = this file). Threat IDs (`T-nn`) and limit IDs (`L-nn`) are stable: PLAN tasks and the review gate cite them.

## 1. Assets

| Asset | Property to protect |
|---|---|
| IMAP credentials | confidentiality |
| Mail content and metadata | confidentiality; faithful (not silently altered) presentation |
| Mailbox state (flags, folders, messages) | integrity: nothing changes in this version, not even `\Seen` |
| Client config files (Claude Code, Claude Desktop) | integrity and availability |
| The user's machine | availability (no OOM, no hang) |

## 2. Trust boundaries

| ID | Boundary | Trust |
|---|---|---|
| B1 | MCP client / model → server tool inputs | untrusted: the model may itself be steered by injected content |
| B2 | Server ↔ IMAP server | network: TLS-authenticated, but the server's responses are still validated and bounded |
| B3 | Mail content (any sender) | hostile |
| B4 | Server ↔ credential backend (keyring, user command) | trusted store, untrusted availability (may be locked or hang) |
| B5 | Local files (mailferret config, client configs) | same-user, may be tampered with by other local tooling |
| B6 | Supply chain (PyPI, uvx cache, plugin marketplace) | pinned and verified |
| B7 | Plugin components inside Claude Code | defense in depth only, never the enforcement point |

Out of scope: malware running as the same user with full access (it can read the keyring directly), and a compromised OS or Python runtime.

## 3. Read-only guarantee

Enforced in the server process (`imap/`, A§6), independent of any client, hint or hook:

- R1: a command-verb allowlist; any other verb raises before a byte is sent.
- R2: a FETCH-item allowlist (`BODY.PEEK[...]`, never `BODY[`/`RFC822`/`RFC822.TEXT`).
- R3: folders are opened with `EXAMINE` only.
- R4: write/SMTP exist only as interfaces (A§2.5), with no implementation; the config schema rejects enabling them; the registered tool set is asserted exactly (A§2.5).

Verification: a recording fake IMAP server drives every tool and option and fails on any denied verb or item (`test_guard_wire`). A GreenMail test snapshots `FLAGS` and message counts for every folder before and after the full tool suite and asserts equality (`test_no_mutation`). Unit tests assert that `ReadOnlyViolation` is raised for every denied verb (`test_guard_denies`).

## 4. Threats

### Credentials

**T-01 Credentials at rest.** Mitigation: only in the platform keyring or behind the user's `command` backend; config keys named like secrets are rejected by the schema; registration never writes `env` secrets; on WSL the recommended default (pending Checkpoint 1 and spike V3) is GPG-encrypted `pass`; plaintext keyring backends are refused. Verification: a schema test rejects `password`/`token`/`secret` keys; a backend-detection test refuses fail, null and plaintext backends; a registration test asserts that written JSON contains no value taken from the test secret.

**T-02 Credentials in memory.** Mitigation: the secret is fetched only at login, held in a `Secret` wrapper (redacted `repr`/`str`), passed to `login`, then the reference is dropped. Python cannot zero strings, so this is best effort: no caching of the secret across reconnects beyond the backend itself, and no secret in exception arguments. Residual risk: the logging redaction set (T-03) keeps the secret and its encoded forms for the process lifetime, so a memory dump of a running server reveals it. Verification: `repr`/`str`/f-string/`logging` of `Secret` yield `***`; a test asserts no exception raised from `auth/` carries the secret in `args` or `__cause__` text.

**T-03 Credentials in logs, errors and tool output.** Mitigation: logging goes to stderr only, and imaplib's debug output is never enabled. A redaction filter replaces every value in the process-wide redaction set before formatting. The set holds three forms per secret: raw, IMAP-quoted (`"` and `\` backslash-escaped, as LOGIN sends it) and the base64 of the `AUTHENTICATE PLAIN` blob (`\0login\0secret`); any `LOGIN`/`AUTHENTICATE` line, and every continuation line while an AUTHENTICATE is in progress, is redacted whole. Typed credential errors carry no secret (R§11). Tool errors map to fixed codes. Verification: `test_login_redaction` logs at DEBUG during GreenMail logins (LOGIN and AUTHENTICATE PLAIN) with a known secret containing `"` and `\`, and asserts that none of the three forms appears in captured stderr or in any tool result; a seeded random loop feeds generated secrets through every error path.

**T-16 Lockout by repeated login.** Restarts, new client sessions and a second client each start their own server process, so "no retry" must hold across processes. Mitigation: a failed login writes an auth-failed marker for `<login>@<host>` to the data dir; while it exists, every process returns `auth_failed` naming `mailferret auth set <account>` (or `auth retry <account>` for a secret changed outside mailferret) without connecting; only those commands and `setup` clear it. Mechanism choice uses the post-TLS capabilities (A§2 `auth/` row): `LOGIN` unless `LOGINDISABLED`; else `AUTHENTICATE PLAIN` if `AUTH=PLAIN`; else `auth_failed` before `credentials/` is touched. Verification: against GreenMail with a real user (auth enabled) and a wrong password, exactly one login command appears on the wire across repeated tool calls in two separate server processes; fake-server cases for each mechanism branch (LOGIN; `LOGINDISABLED` + `AUTH=PLAIN` uses AUTHENTICATE; `LOGINDISABLED` without `AUTH=PLAIN` never calls the backend `get`).

**T-17 Credential command abuse or hang.** Mitigation (A§2.1): argv only (no shell), an absolute executable path resolved at setup, a fixed `cwd` and minimal env, the whole process tree bounded by `L-14` (new session + `killpg` on POSIX, a `ctypes` job object on Windows), pipes read under the same deadline, stdout capped at `L-22`, a trailing newline stripped, stderr summarized (not logged verbatim). A pinentry is spawned by gpg-agent outside the tree, so the `pass` recipe sets `--pinentry-mode=error` (to be verified, A§10 item 7). Verification: tests with a fake command that sleeps, prompts, prints megabytes, writes the secret to stderr, or leaves a grandchild holding stdout past the deadline; each returns within `L-14` plus a small margin and leaves no process behind.

### Mail content

**T-04 Prompt injection via mail content** (subject, body, headers, display names, attachment names and text, hidden HTML text). The server cannot stop a client from obeying injected text; it makes content unmistakably data and removes hidden channels. Mitigation: every mail- or server-derived string is an `Untrusted` field and is wrapped in delimiters, with the escaping rule of A§2.4; hidden HTML content (`display:none`, `visibility:hidden`, `hidden`, zero font size, comments, `<head>`, `<script>`, `<style>`) and `Cf` controls (bidi overrides, zero-width) are removed and noted; the server `instructions` state that content is never instructions; the plugin `mail-reader` agent removes exfiltration tools from the reading context. Residual risk: a client that obeys content can still act on it (T-18), and the `mail-reader` agent's summary is itself a channel into the parent context; its output contract (instructions reported as quoted speech, URLs defanged) reduces but does not close it. Verification: corpus fixtures with injection text in each field; tests assert wrapping, that a mail containing the closing delimiter cannot terminate the block, that hidden spans are removed and noted, and that controls are stripped.

**T-18 Exfiltration through the client.** Private data, untrusted content and outbound tools in one context. Mitigation (outside the server's control): document the risk in the README; the plugin agent's enumerated tool allowlist removes outbound tools from the reading context; no tool ever fetches URLs or remote images from mail (`inscriptis` makes no network calls; images are never resolved). Residual path: the agent's summary returns to a parent that has Bash and WebFetch, so injected text that survives summarization can still steer an outbound call there; the output contract (defanged URLs, quoted instructions) is the only mitigation on that path. Verification: a test asserts no socket other than the IMAP connection is opened while processing the corpus (socket monkeypatch); a plugin eval feeds an injection mail through `mail-reader` and asserts the summary quotes rather than follows it and contains no live URL.

**T-05 Oversized or malicious MIME** (multipart bombs, deep nesting, huge headers, many attachments). Mitigation: `RFC822.SIZE` is checked before any body fetch (R§11); BODYSTRUCTURE is bounded by depth `L-06` and part count `L-07`; headers are bounded by `L-05` and `L-04`; only selected parts are fetched, each partial-fetched to `L-02`; attachments listed up to `L-18`; each part is parsed in its own try block (per-attachment fault isolation, R§11). Verification: generated fixtures (at test time, not committed): 10,000-part multipart, 1,000-deep nesting, a 10 MiB header, a part declaring a 2 GiB size, a malformed boundary; tests assert bounded memory (`tracemalloc` peak under a budget) and a `limit_exceeded` note.

**T-06 PDF and attachment-parser DoS** (decompression bombs, recursive object graphs, page-count bombs). Mitigation: only attachments `≤ L-08` are fetched; `pypdf` runs in a subprocess (`python -I -m mailferret.content.pdf_worker`) with a wall time (`L-10`) and, per OS, a memory limit: `RLIMIT_AS` on Linux; on Windows an own `ctypes` job object (no pywin32); on macOS, which does not enforce `RLIMIT_AS`, no memory limit, so the bound there is the wall time plus the page and decompressed-bytes caps (A§10 item 10). Page cap `L-09`, a lowered declared-stream-length and decompression cap, extracted chars capped at `L-03`; no `pypdf` extras. Verification: generated PDF bombs (a deflate bomb stream, 100,000 pages, cyclic page tree) end with `limit_exceeded` within the timeout on every OS; the worker memory cap is asserted on Linux and Windows only.

**T-19 Charset and encoding attacks** (mislabelled charsets, invalid UTF-8, overlong sequences, encoded-word abuse). Mitigation: the decode chain falls back to `errors="replace"` (R§11); truncation never splits a codepoint, and an incomplete tail from a partial fetch is dropped; header decoding is bounded. Verification: corpus fixtures (PLAN §3.1) plus a seeded stdlib `random` fuzz loop over random bytes (Hypothesis failed vetting, survey) that asserts no exception, valid `str` output and length within the limit.

### Network and server

**T-07 TLS / STARTTLS downgrade and certificate failures.** Mitigation: implicit TLS or STARTTLS only, no plaintext mode; STARTTLS that is not advertised or fails is a hard error, never a fallback; all pre-TLS capabilities are discarded and CAPABILITY is re-issued after the upgrade; any data the server sent before the TLS handshake completed is treated as a protocol error; verification always on with a TLS 1.2 minimum; `ca_file` is added with `load_verify_locations()` on top of the system store (A§2.2). Detecting pre-handshake bytes needs the hook of A§10 item 1, because imaplib's `starttls()` drops them silently. Verification: a fake server that omits STARTTLS, strips it, injects a pipelined response before the handshake, or presents a self-signed or wrong-host certificate; each must fail without sending `LOGIN`. A GreenMail test with its self-signed certificate fails without `ca_file` and passes with it.

**T-08 Malicious or compromised server responses** (lying `RFC822.SIZE`, ignoring partial ranges, huge literals, endless lines, malformed FETCH, changed UIDVALIDITY, hostile folder names). Mitigation: limits are enforced on read, not only requested: a literal or line larger than the active cap raises before it is buffered (`L-02`, `L-05`, `L-20`); response parse errors become `server_error` for that message only; UIDs are validated as positive ints; UIDVALIDITY is checked against every `message_ref`; folder names are `Untrusted`. Verification: fake-server scenarios for each case, with a memory budget asserted.

**T-09 IMAP injection via tool inputs** (search terms, folder names, alias patterns). Mitigation: criteria always go to imapclient as a list, never a raw string; folder names are validated against the LIST result before EXAMINE; wildcards are matched client-side only. Verification: inputs containing `"`, `)`, CRLF and `{n}` literals produce exactly one well-formed command on the recording fake server.

**T-10 Accidental mutation.** See §3.

### Local files and supply chain

**T-11 Config file tampering.** Mitigation: on POSIX, `doctor` warns if the config or its directory is writable by group/others; the schema rejects unknown keys and secrets; credentials are bound to `<login>@<host>` (A§2): for `keyring` through the entry key, for `command` through the binding record written by `auth set` and checked before `get` runs. A tampered host or login therefore finds no secret instead of sending it elsewhere, until the user re-runs `auth set`. `doctor` reports `ca_file` and the configured credential argv. Residual risk: whoever can write the config can set `credential_command` to any program, which is code execution as the user (same-user, out of scope per §2); an attacker who rewrites both the config and the binding record defeats the binding. Verification: for each backend, a test changes `host`, then `login`, and asserts that `get` is never called and no `LOGIN` is sent.

**T-12 Registration-file tampering or clobbering.** Mitigation: a timestamped backup next to the target (mode 0600 on POSIX), then an atomic write (temp file + `os.replace`), with unknown keys preserved and the file re-parsed after writing; invalid existing JSON aborts without writing; only the `mailferret` entry is touched; absolute launcher paths only. For `register claude-code`, which writes through `claude mcp add-json`, the same backup is taken of the file that scope writes before the CLI runs (A§9.5). Verification: tests with a malformed file, a file with other servers, a read-only file, and a concurrent modification (mtime check before replace); for the CLI path, a fake `claude` executable asserts the backup exists before it is invoked.

**T-13 Supply chain.** Policy: R§10 and the survey. Mitigation: `uv.lock` committed and checked in CI (`uv lock --check`); a dependency audit (OSV-based) on the lock in CI and on a schedule; Dependabot; `mcp>=2.3,<3`; no optional extras (`inscriptis[web-service]`, `pypdf[full]`); the heavy `mcp` transitive tree (HTTP server stack, JWT, crypto) is accepted but tracked: the audit covers it and stdio never starts the HTTP transport; releases use PyPI trusted publishing with attestations; the plugin pins an exact version. uvx ignores `uv.lock`, so plugin and `register` launches pass `--constraints` with a file generated by `uv export` from the release's lock (A§9.2, A§9.4): users get the exact audited transitive set, provided `--constraints` applies to the uvx tool environment (unverified, A§10 item 16). Fallback and residual: `--exclude-newer <release timestamp>` bounds the set by date but does not pin it, so users may then run transitive versions the audit has not scanned. That freezes transitive fixes until the next mailferret release, so a scheduled audit runs on the shipped constraints file and a hit triggers a patch release. Verification: CI jobs; a check that `plugin/constraints.txt` equals the export of the pinned tag's lock; a test asserts the server starts with only the stdio transport.

**T-15 Plugin hooks fail open; plugin components bypassed.** Mitigation: no security property depends on a plugin hook or skill (hooks fail open on timeout or crash, and `allowed-tools` only pre-approves). The only plugin-side containment is the agent's enumerated `tools` allowlist, and it is defense in depth: nothing forces delegation to the agent. Verification: the read-only and redaction tests run against the bare server, with no plugin present; a CI test asserts the agent's `tools` equals the server's registered read tools (so a future write tool is never granted).

**T-20 Secret entry through the model.** A user pastes a password into chat, or an agent pipes one into `auth set` via its Bash tool. Mitigation: there is no setup skill; `auth set` and `setup` refuse a non-TTY stdin unless `--stdin` is given (checked before `getpass`, which otherwise silently falls back to stdin); `--stdin` is refused when `CLAUDECODE=1` is set (a speed bump: an agent can unset it); `not_configured` tool errors give the terminal command and say never to paste a password into the chat. Verification: CLI tests with a pipe for stdin (refused), `--stdin` with and without `CLAUDECODE=1`, and a tool-error text test.

**T-21 Mail content in logs.** MCP clients persist server stderr (per-server log files), so whatever mailferret logs lands on disk outside the mailbox's protection. Mitigation: no log record contains a mail-derived string (subject, address, display name, folder name, body, attachment name) at any level; records carry account ids, UIDs, sizes, durations and error codes only; `ToolError` texts (logged by the SDK at INFO) follow the same rule. Verification: a test runs the whole corpus through every tool at DEBUG and asserts that no corpus subject, address or folder name appears in captured stderr.

**T-14 Multi-account confusion.** Mitigation: `account` is required whenever more than one account exists and no `default_account` is set; `message_ref` embeds the account and UIDVALIDITY and is rejected for any other account; per-account connections, locks and credentials; every result names its account. Verification: tests with two accounts on GreenMail (distinct users) that cross-use refs, omit `account`, and confirm one account's failure leaves the other unaffected.

## 5. Limits (requirements)

The ceiling is a hard bound: user config (`[limits]`, key below) may lower it but never raise it. Where a row also has a default, a tool argument may choose any value up to the ceiling and the default applies when it is omitted. Rows without a separate default use the ceiling.

| ID | Limit | Default | Ceiling | Config key |
|---|---|---|---|---|
| L-01 | Message size for a full `BODY.PEEK[]` fetch (fallback only) | — | 25 MiB | `max_message_bytes` |
| L-02 | Bytes per fetched text part (partial fetch, enforced on read) | — | 2 MiB | `max_part_bytes` |
| L-03 | Chars returned for a body or an attachment's text | 100,000 | 100,000 | `max_body_chars` |
| L-04 | Chars per returned header value | — | 8,192 | `max_header_value_chars` |
| L-05 | Header block bytes | — | 256 KiB | `max_header_bytes` |
| L-06 | MIME nesting depth | — | 16 | `max_mime_depth` |
| L-07 | MIME parts walked per message | — | 256 | `max_mime_parts` |
| L-08 | Attachment bytes fetched for text extraction | — | 10 MiB | `max_attachment_bytes` |
| L-09 | PDF pages extracted | — | 50 | `max_pdf_pages` |
| L-10 | PDF worker: wall time / memory / decompressed bytes per stream | — | 20 s / 512 MiB / 32 MiB | `pdf_worker_seconds` / `pdf_worker_memory_bytes` / `pdf_stream_bytes` |
| L-11 | IMAP connect timeout | — | 15 s | `imap_connect_seconds` |
| L-12 | IMAP per-command read timeout | — | 30 s | `imap_read_seconds` |
| L-13 | Whole tool-call deadline | — | 90 s | `tool_deadline_seconds` |
| L-14 | Credential command timeout (whole process tree) | — | 10 s | `credential_command_seconds` |
| L-15 | Search: page size / candidate UIDs considered | 25 / — | 200 / 10,000 | `max_page_size` / `max_candidates` |
| L-16 | Messages per `get_thread` | — | 100 | `max_thread_messages` |
| L-17 | `list_aliases`: period / messages scanned | 30 days / — | 365 days / 5,000 | `max_alias_period_days` / `max_alias_scan` |
| L-18 | Attachments listed per message | — | 100 | `max_attachments_listed` |
| L-19 | Tool response: UTF-8 bytes of serialized `structured_content` plus text content (A§2.3; on breach the body, then attachment text, is trimmed) | — | 1 MiB | `max_response_bytes` |
| L-20 | Non-literal response line from the server | — | 1 MiB | `max_line_bytes` |
| L-21 | Folders returned by `list_folders` | — | 1,000 | `max_folders` |
| L-22 | Credential command stdout | — | 4 KiB | `credential_command_output_bytes` |
| L-23 | Chars per search text argument or alias pattern | — | 256 | `max_query_chars` |
| L-24 | Criteria per `search` call | — | 16 | `max_criteria` |
| L-25 | UIDs per post-filter `UID FETCH` batch (A§2.6) | — | 200 | `fetch_batch_size` |

Every cap that triggers sets `truncated: true` or adds a `limit_exceeded` note naming the limit ID; for L-22 and L-23/L-24 the call fails with `limit_exceeded` instead. Each limit has a test that crosses it.

## 6. Review checklist (per-module gate)

The reviewer confirms, for the threats the task cites: the mitigation exists in code, the listed verification exists as a test and fails when the mitigation is removed, no limit is hard-coded outside `limits.py`, no dependency is added outside the vetted table in `docs/research/library-survey.md` (R§10), and no personal data or secret appears in code, fixtures or docs.
