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
- R4: no write/SMTP code ships; the config schema rejects enabling it; the registered tool set is asserted exactly (A§2.5).

Verification: a recording fake IMAP server drives every tool and option and fails on any denied verb or item (`test_guard_wire`). A GreenMail test snapshots `FLAGS` and message counts for every folder before and after the full tool suite and asserts equality (`test_no_mutation`). Unit tests assert that `ReadOnlyViolation` is raised for every denied verb (`test_guard_denies`).

## 4. Threats

### Credentials

**T-01 Credentials at rest.** Mitigation: only in the platform keyring or behind the user's `command` backend; config keys named like secrets are rejected by the schema; registration never writes `env` secrets; on WSL the default is GPG-encrypted `pass`, and plaintext keyring backends are refused. Verification: a schema test rejects `password`/`token`/`secret` keys; a backend-detection test refuses fail, null and plaintext backends; a registration test asserts that written JSON contains no value taken from the test secret.

**T-02 Credentials in memory.** Mitigation: the secret is fetched only at login, held in a `Secret` wrapper (redacted `repr`/`str`), passed to `login`, then the reference is dropped. Python cannot zero strings, so this is best effort: no caching of the secret across reconnects beyond the backend itself, and no secret in exception arguments. Verification: `repr`/`str`/f-string/`logging` of `Secret` yield `***`; a test asserts no exception raised from `auth/` carries the secret in `args` or `__cause__` text.

**T-03 Credentials in logs, errors and tool output.** Mitigation: logging goes to stderr only, and imaplib's debug output is never enabled. A redaction filter replaces every value in the process-wide redaction set, plus any `LOGIN`/`AUTHENTICATE` line, before formatting. Typed credential errors carry no secret (R§11). Tool errors map to fixed codes. Verification: `test_login_redaction` logs at DEBUG during a GreenMail login with a known secret and asserts the secret and its base64 form are absent from captured stderr and from every tool result; a property test feeds random secrets through every error path.

**T-16 Lockout by repeated login.** Mitigation: no retry after an authentication failure; the account is marked failed until the config or secret changes; `LOGINDISABLED` is checked before the secret is loaded. Verification: against GreenMail with a real user (auth enabled) and a wrong password, exactly one `LOGIN` appears on the wire across repeated tool calls; with `LOGINDISABLED` advertised (fake server) the backend `get` is never called.

**T-17 Credential command abuse or hang.** Mitigation: argv only (no shell), an absolute executable path resolved at setup, stdin closed for `get`, a timeout (`L-14`), output capped at 4 KiB, a trailing newline stripped, stderr summarized (not logged verbatim). Verification: tests with a fake command that sleeps, prompts, prints megabytes, or writes the secret to stderr.

### Mail content

**T-04 Prompt injection via mail content** (subject, body, headers, display names, attachment names and text, hidden HTML text). The server cannot stop a client from obeying injected text; it makes content unmistakably data and removes hidden channels. Mitigation: every mail- or server-derived string is an `Untrusted` field and is wrapped in nonce delimiters with the prefix escaped (A§2.4); hidden HTML content (`display:none`, `visibility:hidden`, `hidden`, zero font size, comments, `<head>`, `<script>`, `<style>`) and `Cf` controls (bidi overrides, zero-width) are removed and noted; the server `instructions` state that content is never instructions; the plugin `mail-reader` agent removes exfiltration tools from the reading context. Residual risk: a client that obeys content can still act on it (T-18). Verification: corpus fixtures with injection text in each field; tests assert wrapping, that a mail containing the closing delimiter cannot terminate the block, that hidden spans are removed and noted, and that controls are stripped.

**T-18 Exfiltration through the client.** Private data, untrusted content and outbound tools in one context. Mitigation (outside the server's control): document the risk in the README; the plugin agent's tool allowlist; no tool ever fetches URLs or remote images from mail (`inscriptis` makes no network calls; images are never resolved). Verification: a test asserts no socket other than the IMAP connection is opened while processing the corpus (socket monkeypatch).

**T-05 Oversized or malicious MIME** (multipart bombs, deep nesting, huge headers, many attachments). Mitigation: `RFC822.SIZE` is checked before any body fetch (R§11); BODYSTRUCTURE is bounded by depth `L-06` and part count `L-07`; headers are bounded by `L-05` and `L-04`; only selected parts are fetched, each partial-fetched to `L-02`; attachments listed up to `L-18`; each part is parsed in its own try block (per-attachment fault isolation, R§11). Verification: generated fixtures (at test time, not committed): 10,000-part multipart, 1,000-deep nesting, a 10 MiB header, a part declaring a 2 GiB size, a malformed boundary; tests assert bounded memory (`tracemalloc` peak under a budget) and a `limit_exceeded` note.

**T-06 PDF and attachment-parser DoS** (decompression bombs, recursive object graphs, page-count bombs). Mitigation: only attachments `≤ L-08` are fetched; `pypdf` runs in a subprocess (`python -I -m mailferret.content.pdf_worker`) with a wall time and memory limit (`L-10`, `RLIMIT_AS` on POSIX; on Windows a job object or, failing that, the timeout alone), page cap `L-09`, a lowered declared-stream-length and decompression cap, extracted chars capped at `L-03`; no `pypdf` extras. Verification: generated PDF bombs (a deflate bomb stream, 100,000 pages, cyclic page tree) end with `limit_exceeded` within the timeout and the parent process stays under its memory budget.

**T-19 Charset and encoding attacks** (mislabelled charsets, invalid UTF-8, overlong sequences, encoded-word abuse). Mitigation: the decode chain falls back to `errors="replace"` (R§11); truncation never splits a codepoint, and an incomplete tail from a partial fetch is dropped; header decoding is bounded. Verification: corpus fixtures (PLAN §3.1) plus a Hypothesis-style fuzz over random bytes that asserts no exception, valid `str` output and length within the limit.

### Network and server

**T-07 TLS / STARTTLS downgrade and certificate failures.** Mitigation: implicit TLS or STARTTLS only, no plaintext mode; STARTTLS that is not advertised or fails is a hard error, never a fallback; all pre-TLS capabilities are discarded and CAPABILITY is re-issued after the upgrade; any data the server sent before the TLS handshake completed is treated as a protocol error; verification always on with a TLS 1.2 minimum; `ca_file` only adds trust anchors. Verification: a fake server that omits STARTTLS, strips it, injects a pipelined response before the handshake, or presents a self-signed or wrong-host certificate; each must fail without sending `LOGIN`. A GreenMail test with its self-signed certificate fails without `ca_file` and passes with it.

**T-08 Malicious or compromised server responses** (lying `RFC822.SIZE`, ignoring partial ranges, huge literals, endless lines, malformed FETCH, changed UIDVALIDITY, hostile folder names). Mitigation: limits are enforced on read, not only requested: a literal or line larger than the active cap raises before it is buffered (`L-02`, `L-05`, `L-20`); response parse errors become `server_error` for that message only; UIDs are validated as positive ints; UIDVALIDITY is checked against every `message_ref`; folder names are `Untrusted`. Verification: fake-server scenarios for each case, with a memory budget asserted.

**T-09 IMAP injection via tool inputs** (search terms, folder names, alias patterns). Mitigation: criteria always go to imapclient as a list, never a raw string; folder names are validated against the LIST result before EXAMINE; wildcards are matched client-side only. Verification: inputs containing `"`, `)`, CRLF and `{n}` literals produce exactly one well-formed command on the recording fake server.

**T-10 Accidental mutation.** See §3.

### Local files and supply chain

**T-11 Config file tampering.** Mitigation: on POSIX, `doctor` warns if the config or its directory is writable by group/others; the schema rejects unknown keys and secrets; credentials are bound to `<login>@<host>` (A§2): for `keyring` through the entry key, for `command` through the binding record written by `auth set` and checked before `get` runs. A tampered host or login therefore finds no secret instead of sending it elsewhere, until the user re-runs `auth set`. `doctor` reports `ca_file` and the configured credential argv. Residual risk: whoever can write the config can set `credential_command` to any program, which is code execution as the user (same-user, out of scope per §2); an attacker who rewrites both the config and the binding record defeats the binding. Verification: for each backend, a test changes `host`, then `login`, and asserts that `get` is never called and no `LOGIN` is sent.

**T-12 Registration-file tampering or clobbering.** Mitigation: a timestamped backup next to the target (mode 0600 on POSIX), then an atomic write (temp file + `os.replace`), with unknown keys preserved and the file re-parsed after writing; invalid existing JSON aborts without writing; only the `mailferret` entry is touched; absolute launcher paths only. Verification: tests with a malformed file, a file with other servers, a read-only file, and a concurrent modification (mtime check before replace).

**T-13 Supply chain.** Policy: R§10 and the survey. Mitigation: `uv.lock` committed and checked in CI (`uv lock --check`); a dependency audit (OSV-based) on the lock in CI and on a schedule; Dependabot; `mcp>=2.3,<3`; no optional extras (`inscriptis[web-service]`, `pypdf[full]`); the heavy `mcp` transitive tree (HTTP server stack, JWT, crypto) is accepted but tracked: the audit covers it and stdio never starts the HTTP transport; releases use PyPI trusted publishing with attestations; the plugin pins an exact version. Verification: CI jobs; a test asserts the server starts with only the stdio transport.

**T-15 Plugin hooks fail open; plugin components bypassed.** Mitigation: no security property depends on a plugin hook or skill (hooks fail open on timeout or crash, and `allowed-tools` only pre-approves). The only plugin-side containment is the agent's `tools` allowlist, and it is defense in depth. Verification: the read-only and redaction tests run against the bare server, with no plugin present.

**T-14 Multi-account confusion.** Mitigation: `account` is required whenever more than one account exists and no `default_account` is set; `message_ref` embeds the account and UIDVALIDITY and is rejected for any other account; per-account connections, locks and credentials; every result names its account. Verification: tests with two accounts on GreenMail (distinct users) that cross-use refs, omit `account`, and confirm one account's failure leaves the other unaffected.

## 5. Default limits (requirements)

Built-in ceilings. User config may lower but never raise them. Tool arguments may lower them per call.

| ID | Limit | Default |
|---|---|---|
| L-01 | Max message size for a full `BODY.PEEK[]` fetch (fallback only) | 25 MiB |
| L-02 | Max bytes per fetched text part (partial fetch, enforced on read) | 2 MiB |
| L-03 | Max chars returned for a body or an attachment's text | 100,000 |
| L-04 | Max chars per returned header value | 8,192 |
| L-05 | Max header block bytes | 256 KiB |
| L-06 | Max MIME nesting depth | 16 |
| L-07 | Max MIME parts walked per message | 256 |
| L-08 | Max attachment bytes fetched for text extraction | 10 MiB |
| L-09 | Max PDF pages extracted | 50 |
| L-10 | PDF worker: wall time / memory / decompressed bytes per stream | 20 s / 512 MiB / 32 MiB |
| L-11 | IMAP connect timeout | 15 s |
| L-12 | IMAP per-command read timeout | 30 s |
| L-13 | Whole tool-call deadline | 90 s |
| L-14 | Credential command timeout | 10 s |
| L-15 | Search results: default page / max page / max candidate UIDs considered | 25 / 200 / 10,000 |
| L-16 | Max messages per `get_thread` | 100 |
| L-17 | `list_aliases`: default period / max messages scanned | 30 days / 5,000 |
| L-18 | Max attachments listed per message | 100 |
| L-19 | Max serialized tool response | 512 KiB |
| L-20 | Max non-literal response line from the server | 1 MiB |
| L-21 | Max folders returned by `list_folders` | 1,000 |

Every cap that triggers sets `truncated: true` or adds a `limit_exceeded` note naming the limit ID. Each limit has a test that crosses it.

## 6. Review checklist (per-module gate)

The reviewer confirms, for the threats the task cites: the mitigation exists in code, the listed verification exists as a test and fails when the mitigation is removed, no limit is hard-coded outside `limits.py`, and no personal data or secret appears in code, fixtures or docs.
