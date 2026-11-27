# mailferret implementation plan

Implements `docs/ARCHITECTURE.md` (cited as A§n) and `docs/SECURITY.md` (`T-nn`, `L-nn`). Each task is one PR with its own tests, merged only after the review gate (§4).

## 1. Model and effort

| Work | Model / effort |
|---|---|
| Discovery | haiku / low |
| Research (verification spikes) | sonnet / medium |
| Architecture / security | opus / high |
| Module implementation + tests | sonnet / medium; **sonnet / high for MIME/charset** (C1–C4) |
| Independent review (gate, §4) | opus / high, a fresh agent per PR |
| Docs | haiku or sonnet / low |
| Claude Code setup (plugin) | opus / medium |

Where a non-MIME task is security-heavy (guard, credentials, TLS), the extra scrutiny comes from the review gate, not a higher implementation tier.

## 2. Tasks

`Deps` lists tasks that must be merged first. `Threats` are the IDs whose verification the task must implement.

### Phase 2a: scaffold and spikes

| ID | Task | Deps | Threats | Model / effort |
|---|---|---|---|---|
| F0 | Scaffold: `pyproject.toml` (uv, `src/` layout, entry point), `uv.lock`, ruff + `mypy --strict` + pytest config, `.gitattributes` (LF normalization), LICENSE, CI matrix (Linux/Windows/macOS × Python floor and latest), `uv lock --check`, dependency audit job, a personal-data grep job | — | T-13 | sonnet / medium |
| V1 | Spike: the imapclient/imaplib hook point for the command guard, read-side caps and pre-STARTTLS buffered bytes; ESEARCH exposure; pypdf knobs and the PDF worker memory cap per OS (Linux `RLIMIT_AS`, Windows `ctypes` job object, macOS) (A§10 items 1, 2, 10). Output: a short note in `docs/research/` and a throwaway prototype test | — | T-08, T-10 | sonnet / medium |
| V2 | Spike: GreenMail capabilities, auth-enabled users via `GREENMAIL_OPTS`, the TLS keystore/CA for `ca_file` tests, and whether APPEND preserves plus-address recipients (A§10 item 3) | — | T-07 | sonnet / medium |
| V3 | Spike: headless credential behaviour on WSL (`pass` with an expired agent cache under `--pinentry-mode=error`; a grandchild holding stdout; Secret Service bus discovery) (A§10 item 7) | — | T-17 | sonnet / medium |
| V4 | Spike: SDK text content beside structured output; plugin detection and same-name shadowing; Desktop `.mcpb` `type: uv`; subdirectory plugin root on claude.ai/Cowork; Bash/MCP PATH inheritance; `command -v` on Windows; `claude mcp add-json`; Cowork host vs VM; `${VAR:-default}` and env inheritance; `uvx --constraints`; `${CLAUDE_PLUGIN_ROOT}` in `allowed-tools`; agent allowlist excluding Skill/Agent; `CLAUDECODE=1`; out-of-plugin evals and `claude plugin disable`; Desktop config paths; `wsl.exe --exec` argument passing (A§10 items 4–6, 9, 11–22) | — | T-04 | sonnet / medium |

V1–V4 run in parallel with each other and with F0. A spike that contradicts the design returns to an opus / high architecture update before dependent tasks start.

### Phase 2b: foundation

| ID | Task | Deps | Threats | Model / effort |
|---|---|---|---|---|
| B1 | `config/`: schema, load/write, paths, env/flag override, `write`/`smtp` positions that validate only `enabled = false`, limits that can only lower | F0 | T-01, T-11 | sonnet / medium |
| B7 | `write/api.py`, `smtp/api.py` protocols (A§2.5) + the AST and import-graph tests that keep them implementation-free and unimported | F0 | T-10 | sonnet / medium |
| B2 | `providers/`: preset data (generic, hetzner), user presets, merge rules | B1 | — | sonnet / medium |
| B3 | `logging.py`: stderr-only, redaction set (raw, IMAP-quoted, PLAIN blob), LOGIN/AUTHENTICATE and continuation-line redaction, no mail-derived strings in records | F0 | T-03, T-21 | sonnet / medium |
| B4 | `credentials/` protocol, `Secret`, typed errors, `keyring` backend, backend detection (fail/null/plaintext, WSL), `<login>@<host>` entry key | F0, B3 | T-01, T-02, T-03, T-11 | sonnet / medium |
| B5 | `credentials/` `command` backend: process-tree timeout (`L-14`), pipe deadline, output cap (`L-22`), minimal env, binding-record check | B4, V3 | T-11, T-17 | sonnet / medium |
| B6 | `limits.py` (top level, imported by every layer): the L-table as one frozen model, config merge | B1 | all `L-nn` | sonnet / medium |

### Phase 2c: content (pure, fixture-driven)

| ID | Task | Deps | Threats | Model / effort |
|---|---|---|---|---|
| C0 | Fixture corpus, generators and Hypothesis strategies for MIME/charset/alias fuzzing (§3.1) | F0 | T-04, T-05, T-06, T-19 | sonnet / medium |
| C1 | `content/charset.py`, `headers.py`, `truncate.py`: fallback chain, RFC 2047/2231, codepoint-safe truncation, incremental tail handling | C0, B6 | T-19, T-05 | **sonnet / high** |
| C2 | `content/mime.py`: bounded BODYSTRUCTURE and MIME walk, part selection, per-part fault isolation | C1 | T-05 | **sonnet / high** |
| C3 | `content/html.py` + `Cf` stripping: hidden-content removal, then `inscriptis`, notes | C1 | T-04, T-18 | **sonnet / high** |
| C4 | `content/pdf_worker.py` + extractor registry (PDF, text, HTML) with subprocess limits | C2, V1 | T-06 | **sonnet / high** |
| C5 | `aliases/` resolver: header priority, plus separator, domains, exact and wildcard match, aggregation | C1 | T-09 | sonnet / medium |

### Phase 2d: IMAP and query

| ID | Task | Deps | Threats | Model / effort |
|---|---|---|---|---|
| D0 | Recording fake IMAP server for tests (scripted capabilities and responses, wire log) | F0 | T-07, T-08, T-10 | sonnet / medium |
| D1 | `imap/` connect: TLS modes, STARTTLS rules, timeouts, capability parsing | B6, D0, V1 | T-07 | sonnet / medium |
| D2 | `imap/` guard + `ReadOnlySession` + read-side caps + deadline cancellation by socket shutdown (`L-13`) | D1 | T-08, T-10 | sonnet / medium |
| D3 | `auth/` protocol + `PasswordAuth`: mechanism choice from post-TLS capabilities, persistent auth-failed marker | B4, D2, D4 | T-03, T-16 | sonnet / medium |
| D4 | GreenMail harness: compose file, auth-enabled users, CA, APPEND-based seeding from C0, two-account setup | V2, C0 | T-14 | sonnet / medium |
| D5 | `query/` folders + search: criteria list builder, SORT branch, paging cursor, caps, has-attachment and alias post-filters (A§2.6, `L-23`–`L-25`) | D3, C5, D4 | T-09, T-14 | sonnet / medium |
| D6 | `query/` fetch + `get_message` assembly (A§3) | D5, C2, C3, D4 | T-05, T-08 | sonnet / medium |
| D7 | `query/` thread (THREAD=REFERENCES branch and header fallback) and attachments | D6, C4 | T-05 | sonnet / medium |

### Phase 2e: server and CLI

| ID | Task | Deps | Threats | Model / effort |
|---|---|---|---|---|
| E1 | `server/` envelope (A§2.4 escaping) + output models + `CallToolResult` builder with the `L-19` count and trim | B6, C3 | T-04 | sonnet / medium |
| E2 | `server/` app and tools, annotations, instructions, errors incl. `not_configured`, exact tool-set test, `message_ref`, `search` `Field` descriptions with examples (replaces the rejected search-syntax skill) | E1, D5, D6, D7, D4 | T-04, T-10, T-14, T-21 | sonnet / medium |
| E3 | `cli/`: `serve`, `accounts list`, `auth set` (TTY check before `getpass`, `--stdin`, refused under `CLAUDECODE=1`; writes the binding record, clears the auth-failed marker), `auth retry` | E2, B5 | T-01, T-03, T-11, T-16, T-20 | sonnet / medium |
| E4 | `cli/setup`: interactive (same TTY rules as `auth set`), preset or manual, read-only connection test | E3, B2 | T-01, T-20 | sonnet / medium |
| E5 | `cli/doctor`: config, permissions, backend, connectivity, TLS, every visible registration (incl. a manual entry shadowing a later plugin install) with its absolute launcher and constraints paths checked for existence and permissions, including the Linux-side `uvx` of a `wsl.exe` Desktop entry (A§9.5) | E3, F2 | T-11, T-17 | sonnet / medium |

### Phase 2f: registration and plugin

| ID | Task | Deps | Threats | Model / effort |
|---|---|---|---|---|
| F1 | `registration/` core: discovery, backup, atomic write, duplicate detection | B1, V4 | T-12 | sonnet / medium |
| F2 | `register claude-code` (via `claude mcp add-json`) + `register claude-desktop` (regular, MSIX, WSL→Windows), `--print`, `--force` policy printing the plugin disable/uninstall command, scope-limited detection notice, backup of the scope's file before `claude mcp add-json`, launcher selection, constraints file copied to the data dir, absolute `wsl.exe --exec` entries (A§9.4, A§9.5, A§9.6) | F1, E3 | T-12 | sonnet / medium |
| P1 | Plugin skeleton: `plugin/` manifests, `.mcp.json` with pin and `--constraints`, constraints generation, marketplace, `claude plugin validate --strict` in CI, version-set check (A§9.4) | E2 | T-13 | opus / medium |
| P2 | `mail-reader` agent and `doctor` skill per A§9.7 (enumerated tools, stop-if-missing, output contract, `maxTurns`; ground-truth branch, exact pre-approvals, MCP_TIMEOUT detection) + the CI test that the agent's tools equal the server's read tools | P1, E5 | T-04, T-15, T-18 | opus / medium |
| P3 | Plugin evals in `plugin-evals/` with mocked IMAP via `MAILFERRET_CONFIG` (`claude plugin eval`), incl. an injection mail through `mail-reader`. The harness runs a test copy of the plugin whose `.mcp.json` launches the PR tree (`uvx --from <repo path> mailferret serve`), so evals need no PyPI release and test the PR's code | P2, D0 | T-04, T-18 | opus / medium |

### Phase 2g: docs and release

| ID | Task | Deps | Threats | Model / effort |
|---|---|---|---|---|
| G1 | README: install, setup, credentials per platform (incl. the WSL recipe), config reference, registration, generic MCP client setup, presets, the T-18 residual risk | E5, F2, P2 | — | sonnet / low |
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
| Fake IMAP server (D0) | Linux, Windows, macOS | Guard wire tests, capability branches GreenMail lacks, TLS/STARTTLS failure modes, hostile responses (T-07, T-08, T-09, T-10) |
| GreenMail integration | Linux CI and local Docker | All tools end to end, `\Seen` and flags unchanged, two accounts, login failure without retry, `ca_file` |
| Plugin | Linux CI | `claude plugin validate --strict`, version-coupling check, evals with mocked IMAP (P3) |

No test touches a real mailbox. Integration tests are marked and skipped when Docker is unavailable, with a visible skip reason.

### 3.3 CI

- Matrix: `ubuntu`, `windows`, `macos` × Python floor and latest: lint, `mypy --strict`, unit and fake-server tests.
- Linux only: GreenMail integration, plugin validation, the dependency audit, `uv lock --check`, the personal-data grep.

## 4. Review gate (per PR)

1. CI green on every matrix job the task touches.
2. A fresh opus / high reviewer (it gets the diff, the cited `T-nn`/`L-nn` and SECURITY §6, not the implementer's reasoning) returns findings. Each finding is fixed or explicitly answered.
3. For every cited threat, the reviewer checks that its test fails when the mitigation is removed (mutation spot check).
4. Merge only with no open findings.

## 5. Parallelism (worktrees)

The `Deps` column in §2 is the only schedule: any task whose dependencies are merged may start, each in its own git worktree, touching only its module, its tests and its fixtures. F0 and V1–V4 start together.

## 6. Checkpoint 2

Reached when all of:

- Every task through E5 and F2 is merged with its gate passed.
- The full unit and fake-server suite is green on Linux, Windows and macOS.
- The GreenMail integration suite is green against Docker GreenMail, including `test_no_mutation`, `test_login_redaction`, the two-account tests and the TLS `ca_file` tests.
- Every `T-nn` in SECURITY §4 has its verification test, and every `L-nn` has a test that crosses it. Exempt until P2/P3: the plugin-side parts of T-15 (agent tools parity test) and T-18 (injection eval).
- `claude plugin validate --strict` passes on P1.

Plugin components (P2, P3), the README (G1) and the release (G2) follow Checkpoint 2.
