# mailferret implementation plan

Implements `docs/ARCHITECTURE.md` (cited as A§n) and `docs/SECURITY.md` (`T-nn`, `L-nn`). Each task is one PR with its own tests, merged only after the review gate (§4).

## 1. Model and effort

| Work | Model / effort |
|---|---|
| Discovery | haiku / low |
| Research (verification spikes) | sonnet / medium: `mf-researcher` writes the note, `mf-implementer` runs the executable parts |
| Architecture / security | opus / high |
| Module implementation + tests | sonnet / medium; **sonnet / high for MIME/charset** (C1–C4) |
| Independent review (gate, §4) | opus / high, two fresh agents per PR (`mf-reviewer`, `mf-security-reviewer`) |
| Docs | haiku or sonnet / low |
| Claude Code setup (plugin) | opus / medium |

Where a non-MIME task is security-heavy (guard, credentials, TLS), the extra scrutiny comes from the review gate, not a higher implementation tier.

## 2. Tasks

`Deps` lists tasks that must be merged first. `Threats` are the IDs whose verification the task must implement. The decisions and the ceiling confirmations (`L-20` allowance, `L-26`–`L-29`) left to a task are owned by `docs/STATUS.md` Open.

### Phase 2a: scaffold and spikes

| ID | Task | Deps | Threats | Model / effort |
|---|---|---|---|---|
| F0 | Scaffold: `pyproject.toml` (uv, `src/` layout, entry point), `uv.lock`, ruff + `mypy --strict` + pytest config, `.gitattributes` (LF normalization), LICENSE, CI matrix (Linux/Windows/macOS × Python floor and latest), `uv lock --check`, dependency audit job, a personal-data grep job | — | T-13 | sonnet / medium |
| V1 | Spike: the imapclient/imaplib hook point for the command guard, read-side caps and pre-STARTTLS buffered bytes; ESEARCH exposure; pypdf knobs and the PDF worker memory cap per OS (Linux `RLIMIT_AS`, Windows `ctypes` job object, macOS) (A§10 items 1, 2, 10). Output: a short note in `docs/research/` and a throwaway prototype test | — | T-08, T-10 | sonnet / medium |
| V2 | Spike: GreenMail capabilities, auth-enabled users via `GREENMAIL_OPTS`, the TLS keystore/CA for `ca_file` tests, and whether APPEND preserves plus-address recipients (A§10 item 3) | — | T-07 | sonnet / medium |
| V3 | Spike: headless credential behaviour on WSL (`pass` with an expired agent cache under `--pinentry-mode=error`; a grandchild holding stdout; Secret Service bus discovery) (A§10 item 7) | — | T-17 | sonnet / medium |
| V4 | Spike: SDK text content beside structured output; plugin detection and same-name shadowing; Desktop `.mcpb` `type: uv`; subdirectory plugin root on claude.ai/Cowork; Bash/MCP PATH inheritance; `command -v` on Windows; `claude mcp add-json`; Cowork host vs VM; `${VAR:-default}` and env inheritance; `uvx --constraints`; `${CLAUDE_PLUGIN_ROOT}` in `allowed-tools`; agent allowlist excluding Skill/Agent; `CLAUDECODE=1`; out-of-plugin evals and `claude plugin disable`; Desktop config paths; `wsl.exe --exec` argument passing (A§10 items 4–6, 9, 11–22) | — | T-04 | sonnet / medium |

V1–V4 run in parallel with each other and with F0. Each pairs `mf-researcher` (docs and source questions, the note) with `mf-implementer` (prototype tests, GreenMail in Docker, `pass`/gpg on WSL, `claude` CLI checks). A spike that contradicts the design returns to an opus / high architecture update before dependent tasks start.

### Phase 2b: foundation

| ID | Task | Deps | Threats | Model / effort |
|---|---|---|---|---|
| B1 | `config/`: schema, load/write, paths, env/flag override (an override naming a missing file gives no accounts, never the default path, with a test; A§7), `write`/`smtp` positions that validate only `enabled = false`, limits that can only lower | F0 | T-01, T-11 | sonnet / medium |
| B7 | `write/api.py`, `smtp/api.py` protocols (A§2.5) + the AST and import-graph tests that keep them implementation-free and unimported | F0 | T-10 | sonnet / medium |
| B2 | `providers/`: preset data (generic, hetzner), user presets, merge rules | B1 | — | sonnet / medium |
| B3 | `logging.py`: stderr-only, redaction set (raw, IMAP-quoted, PLAIN blob), LOGIN/AUTHENTICATE and continuation-line redaction, no mail-derived strings in records | F0 | T-03, T-21 | sonnet / medium |
| B4 | `credentials/` protocol, `Secret`, typed errors, the secret-acceptance rule (exit 0, readers at EOF, not empty, no CR/LF/NUL; T-02), `keyring` backend used only through a bounded probe subprocess started as `sys.executable -I -m` (test: a `keyring.py` planted in the data dir is never imported) after the bus-address pre-check, with backend selection and detection (fail/null/plaintext; raw D-Bus errors as unavailable) inside the probe and the same probe for `doctor` and `auth set` (`L-27`, `L-22`, `L-28` with the stderr flood test, A§2.1), `PYTHON_KEYRING_BACKEND` and `XDG_CONFIG_HOME` passed to the probe only, writes on a stdin pipe fed by a daemon writer under the deadline, WSL detection, `<login>@<host>` entry key; the job object and the probe on windows and macos runners (A§10 item 23). The probe bound counts as tested only with a retained mute-bus repro (V3 E6) | F0, B3, B6, V3 | T-01, T-02, T-03, T-11, T-17 | sonnet / medium |
| B5 | `credentials/` `command` backend: process-tree timeout (`L-14`) with daemon readers and a fail-closed return, output cap while reading (`L-22`), stderr and status channel kept to `L-28`/`L-29` (megabyte flood tests), minimal env, binding-record check, `set` on a stdin pipe fed by a daemon writer under `L-14`; `pass` recipe with `--pinentry-mode=error`, a gpg status channel (decides `pass_fds` or a 0600 `--status-file`, and how a gpg recipe is recognised to add it, A§2.1) and `locked` from status codes (A§2.1); tests include a `setsid` descendant holding stdout, a `set` child that neither reads stdin nor exits, a locked store through the real spawn path, and the `gpg2`/`GPG_AGENT_INFO` branch warm and expired in a throwaway `GNUPGHOME` (A§10 item 7); the job object for `command` on a windows runner (A§10 item 23) | B4, B6, V3 | T-02, T-03, T-11, T-17 | sonnet / medium |
| B6 | `limits.py` (top level, imported by every layer): the L-table as one frozen model, config merge | B1 | all `L-nn` | sonnet / medium |

### Phase 2c: content (pure, fixture-driven)

| ID | Task | Deps | Threats | Model / effort |
|---|---|---|---|---|
| C0 | Fixture corpus, generators and Hypothesis strategies for MIME/charset/alias fuzzing (§3.1) | F0 | T-04, T-05, T-06, T-19 | sonnet / medium |
| C1 | `content/charset.py`, `headers.py`, `truncate.py`: fallback chain, RFC 2047/2231, codepoint-safe truncation, incremental tail handling, address formatting from imapclient `Address` fields (never `str(Address)`, A§2.2) | C0, B6 | T-19, T-05, T-21 | **sonnet / high** |
| C2 | `content/mime.py`: bounded BODYSTRUCTURE and MIME walk, part selection, per-part fault isolation | C1 | T-05 | **sonnet / high** |
| C3 | `content/html.py` + `Cf` stripping: hidden-content removal, then own text extraction on `lxml` (no `inscriptis`, see the survey), notes | C1 | T-04, T-18 | **sonnet / high** |
| C4 | `content/pdf_worker.py` + extractor registry (PDF, text, HTML) with subprocess limits; pypdf `Configuration` fields from `L-10`/`L-09`, found at runtime, with the test that no integer field exceeds `pdf_stream_bytes`, every program field (`jbig2dec_binary`) set to `None` with the fake-`jbig2dec` test, and the `PdfReader` constructor limits at pypdf's defaults (T-06); the Windows job-object and macOS `RLIMIT_AS` memory caps researched and run on windows and macos CI runners; cyclic page-tree and 100,000-page bombs (A§10 item 10) | C2, V1 | T-06 | **sonnet / high** |
| C5 | `aliases/` resolver: header priority, plus separator, domains, exact and wildcard match, aggregation | C1 | T-09 | sonnet / medium |

### Phase 2d: IMAP and query

| ID | Task | Deps | Threats | Model / effort |
|---|---|---|---|---|
| D0 | Recording fake IMAP server for tests (scripted capabilities and responses, wire log) | F0 | T-07, T-08, T-10 | sonnet / medium |
| D1 | `imap/` connect, adding `imapclient` pinned exactly (`==`, A§2.2): TLS modes, STARTTLS rules with the buffered-bytes probe by feature (A§2.2), timeouts, capability parsing; the STARTTLS injection test on every supported Python minor | B6, D0, V1 | T-07 | sonnet / medium |
| D2 | `imap/` guard mixin on `_new_tag` + `send` with the fail-closed send gate, `{n+}` refused and `LITERAL+` hidden from imapclient, `ReadOnlyViolation` with a fixed reason, reset on abort and reconnect (A§6) + the hook-set self-check before the first connection, the per-session liveness checks and the unvetted-tag tripwire, one bypass test per hook (A§2.2, SECURITY §3 R5) + the `LITERAL+` hide test + typed breach errors that are never reconnected, no reconnect on an `L-11` or `L-12` timeout or the `L-13` shutdown (the deadline marks the session first), one connection attempt and at most one LOGIN per call on a breach or any of these, no socket opened after the deadline (A§2.2) + `ReadOnlySession` + per-command literal caps and response total over `read` and `readline` (`L-26`), the per-line overhead constant from a `tracemalloc` measurement, `untagged_responses` reset in `_new_tag`, the distinct-type flood test, the dense-token FETCH parse test (SECURITY T-08) + `imaplib._MAXLINE` from `L-20` + imapclient logging pin and fixed error codes for library exceptions + `login` taking `str` only + deadline cancellation by socket shutdown (`L-13`); wire-survey, send-gate, read-cap, logging-pin, self-check and liveness tests on every supported minor (SECURITY §3) | D1 | T-02, T-03, T-08, T-10, T-21 | sonnet / medium |
| D3 | `auth/` protocol + `PasswordAuth`: mechanism choice from post-TLS capabilities, the `isascii()` branch with the T-02 test on the `imap/` login path, persistent auth-failed marker, no reconnect after a failure during the login phase (A§2.2); decides whether a non-ASCII login takes `AUTHENTICATE PLAIN` and whether an indeterminate outcome sets a time-boxed marker (T-16 residual risk) | B4, D2, D4 | T-02, T-03, T-16 | sonnet / medium |
| D4 | GreenMail harness: compose file `tests/integration/docker-compose.yml`, auth-enabled users, CA, APPEND-based seeding from C0, two-account setup, per the V2 note's decisions and D4 requirements (image pinned by digest, the `ca_file` check through mailferret's TLS context, a `\Seen` control test, the plaintext port as a no-STARTTLS case). Capabilities GreenMail lacks are covered on D0 | V2, C0 | T-07, T-14 | sonnet / medium |
| D5 | `query/` folders + search: criteria list builder, SORT branch, windowed UID ranges so no response line exceeds `L-20`, ordered per window with the window in the paging cursor (A§2.6), FETCH batches shrunk to fit `L-26` (A§2.2), caps, has-attachment and alias post-filters (A§2.6, `L-23`–`L-25`) | D3, C5, D4 | T-08, T-09, T-14 | sonnet / medium |
| D6 | `query/` fetch + `get_message` assembly (A§3) | D5, C2, C3, D4 | T-05, T-08 | sonnet / medium |
| D7 | `query/` thread (THREAD=REFERENCES branch and header fallback) and attachments | D6, C4 | T-05 | sonnet / medium |

### Phase 2e: server and CLI

| ID | Task | Deps | Threats | Model / effort |
|---|---|---|---|---|
| E1 | `server/` envelope (A§2.4 escaping) + output models + `CallToolResult` builder with the `L-19` count and trim | B6, C3 | T-04 | sonnet / medium |
| E2 | `server/` app and tools, annotations, instructions, errors incl. `not_configured`, exact tool-set test, `message_ref`, `search` `Field` descriptions with examples (replaces the rejected search-syntax skill) | E1, D5, D6, D7, D4 | T-04, T-10, T-14, T-21 | sonnet / medium |
| E3 | `cli/`: `serve`, `accounts list`, `auth set` (TTY check before `getpass`, `--stdin`, refused under `CLAUDECODE=1` or `CLAUDE_CODE_CHILD_SESSION`; refuses before any spawn a secret `get` would refuse; writes the binding record, clears the auth-failed marker), `auth retry`; the R5 self-check refusal test from `serve` | E2, B5 | T-01, T-02, T-03, T-10, T-11, T-16, T-20 | sonnet / medium |
| E4 | `cli/setup`: interactive (same TTY rules and secret refusal as `auth set`), preset or manual, read-only connection test; the R5 self-check refusal test from `setup` | E3, B2 | T-01, T-02, T-10, T-20 | sonnet / medium |
| E5 | `cli/doctor`: config, permissions, backend (incl. the keyring bus-address pre-check, the bounded probe and the backend it chose), connectivity, TLS, every visible registration (incl. a manual entry duplicating or suppressing a later plugin install) with its absolute launcher and constraints paths checked for existence and permissions, including the Linux-side launcher script of a `wsl.exe` Desktop entry, its owner and mode and its parent directory (A§9.5, A§9.6); the R5 self-check refusal test from `doctor` | E3, F2 | T-10, T-11, T-12, T-17 | sonnet / medium |

### Phase 2f: registration and plugin

| ID | Task | Deps | Threats | Model / effort |
|---|---|---|---|---|
| F1 | `registration/` core: discovery, backup, atomic write, duplicate detection | B1, V4 | T-12 | sonnet / medium |
| F2 | `register claude-code` (via `claude mcp add-json`) + `register claude-desktop` (regular; MSIX only with `--desktop-config`; WSL→Windows through a generated `#!/bin/sh` launcher script with one `shlex.quote`d `exec` line, T-12; decides its location and the case with no space-free path), `--print`, `--force` policy printing the plugin disable/uninstall command (decides whether the refusal stays), plugin detection reporting scope and `projectPath`, backup of the scope's file before `claude mcp add-json`, launcher selection, constraints file copied to the data dir (A§9.4, A§9.5, A§9.6) | F1, E3 | T-11, T-12 | sonnet / medium |
| P1 | Plugin skeleton: `plugin/` manifests, `.mcp.json` with pin and `--constraints`, constraints generation, marketplace, `claude plugin validate --strict` in CI, version-set check (A§9.4); decides whether `--exclude-newer` joins the pins (A§9.2) | E2 | T-13 | opus / medium |
| P2 | `mail-reader` agent and `doctor` skill per A§9.7 (enumerated tools plus `disallowedTools: Skill, Agent`, stop-if-missing, output contract, `maxTurns`; ground-truth branch accepting both tool prefixes, shell-tool branch for the `uvx` lookup, exact pre-approvals, MCP_TIMEOUT detection) + the CI test that the agent's tools equal the server's read tools; confirms A§10 items 17 and 18 under `--strict`, incl. whether `allowed-tools` accepts the exact PowerShell string | P1, E5 | T-04, T-15, T-18 | opus / medium |
| P3 | Plugin evals in `plugin/evals/` (`claude plugin eval`) with MCP mocks and the isolated invocation of A§9.8 (POSIX only; documents how Claude Code authenticates under the isolated `HOME`), incl. a synthetic injection mail through `mail-reader`, generated at eval time, never shipped and asking only for a harmless canary output; asserts that no mailferret server process or IMAP socket starts (A§10 item 24) and the agent's runtime tool list (no Skill, no Agent, nothing outside the plugin's mailferret tools; A§10 item 18), confirms that the `doctor` skill's pre-approved strings run without a prompt in a model run (A§10 item 17), with the user's `/smoke-test` as the backstop; decides whether it still needs D0 | P2, D0 | T-04, T-15, T-18 | opus / medium |

### Phase 2g: docs and release

| ID | Task | Deps | Threats | Model / effort |
|---|---|---|---|---|
| G1 | README: install, setup, credentials per platform (incl. the WSL recipe and exporting `DBUS_SESSION_BUS_ADDRESS` for keyring), config reference, registration, generic MCP client setup, presets, zip-upload instructions for claude.ai (A§10 item 9), the T-18 residual risk | E5, F2, P2 | — | sonnet / low |
| G2 | Release workflow: tag → trusted publishing → uvx smoke → plugin pin bump PR that regenerates `constraints.txt` (A§9.4); the first release claims the PyPI name and is followed by the PR that adds the marketplace entry | P1 | T-13 | sonnet / medium |

## 3. Test strategy

### 3.1 Fixture corpus (C0)

Committed `.eml` files (small, synthetic, `example.com` only) plus generators for anything large or hostile:

- Charsets: UTF-8 umlauts and CJK; ISO-8859-1 and -15 labelled correctly and mislabelled; `windows-1252` labelled as `iso-8859-1`; Shift_JIS; an unknown charset label; invalid UTF-8; a part with no charset.
- Headers: RFC 2047 Q and B encoded words, adjacent encoded words, a broken encoded word, folded headers, RFC 2231 filenames with a continuation, duplicate headers, header-injection attempts.
- Structure: nested `multipart/mixed` > `alternative` > `related`; `message/rfc822` attachments; a missing end boundary; base64 and quoted-printable with errors.
- Content: HTML with hidden spans of each kind, bidi and zero-width characters, injection text in every field, a closing-delimiter forgery, remote images and links.
- Aliases: `Delivered-To`/`X-Original-To`/`To`/`Cc` combinations, plus-addresses, multiple alias domains, wildcard cases.
- Property-based (Hypothesis, dev-only): arbitrary bytes, charset labels, encoded words and alias header combinations through the `content/` and `aliases/` pure functions; no exception, valid `str`, length within limits (T-19).
- Generated at test time: MIME bombs (part count, depth), a huge header, PDF bombs (stream deflate bomb, page bomb, cyclic tree), a large plain PDF, a mail exceeding `L-01`.

### 3.2 Layers

| Layer | Runs on | What |
|---|---|---|
| Unit (pure modules) | Linux, Windows, macOS | `content/`, `aliases/`, `config/`, `credentials/` (in-memory and fake-command backends), `registration/` (temp dirs, fake platform roots) |
| Fake IMAP server (D0) | Linux, Windows, macOS | Guard wire and send-gate tests, capability branches GreenMail lacks (STARTTLS, CONDSTORE, THREAD, SPECIAL-USE), TLS/STARTTLS failure modes, hostile responses, the AUTHENTICATE PLAIN leg of `test_login_redaction` (T-03, T-07, T-08, T-09, T-10) |
| GreenMail integration | Linux CI and local Docker | All tools end to end, `\Seen` and flags unchanged, two accounts, login failure without retry, `ca_file`, the plaintext port as a no-STARTTLS case, the LOGIN leg of `test_login_redaction` |
| Plugin | Linux CI | `claude plugin validate --strict`, version-coupling check, evals with MCP mocks (P3, A§9.8) |

No test touches a real mailbox. Integration tests are marked and skipped when Docker is unavailable, with a visible skip reason.

### 3.3 CI

- Matrix: `ubuntu`, `windows`, `macos` × Python floor and latest: lint, `mypy --strict`, unit and fake-server tests, including the PDF worker memory-cap tests (C4).
- Every supported Python minor, not only floor and latest: the `imap/` private-API tests (guard wire survey and send gate, read caps, logging pin, STARTTLS probe, the hooks' self-check, liveness checks and tripwire; A§2.2).
- Linux only: GreenMail integration, plugin validation, the dependency audit, `uv lock --check`, the personal-data grep.

## 4. Review gate (per PR)

1. CI green on every matrix job the task touches.
2. Two fresh opus / high agents review in parallel (`/review-module`): `mf-reviewer` (correctness, tests, design fit) and `mf-security-reviewer` (SECURITY threats, limits, §6). Each gets the diff, the cited `T-nn`/`L-nn` and SECURITY §6, not the implementer's reasoning, and posts one review thread per finding. Each finding is fixed or explicitly answered.
3. For every cited threat, the reviewers check that its test fails when the mitigation is removed (mutation spot check).
4. Merge only with no open findings and both verdicts approve on the latest commit.

## 5. Parallelism (worktrees)

The `Deps` column in §2 is the only schedule: any task whose dependencies are merged may start, each in its own git worktree, touching only its module, its tests and its fixtures. F0 and V1–V4 start together.

## 6. Checkpoint 2

Reached when all of:

- Every task through E5 and F2 is merged with its gate passed.
- The full unit and fake-server suite is green on Linux, Windows and macOS.
- The GreenMail integration suite is green against Docker GreenMail, including `test_no_mutation`, the LOGIN leg of `test_login_redaction` (its AUTHENTICATE PLAIN leg is in the fake-server suite), the two-account tests and the TLS `ca_file` tests.
- Every `T-nn` in SECURITY §4 has its verification test, and every `L-nn` has a test that crosses it. Exempt until P2/P3: the plugin-side parts of T-04 (the agent's runtime tool list), T-15 (agent tools parity test) and T-18 (injection eval).
- `claude plugin validate --strict` passes on P1.

Plugin components (P2, P3), the README (G1) and the release (G2) follow Checkpoint 2.
