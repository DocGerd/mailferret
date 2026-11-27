# mailferret requirements

The source of truth for the design. `docs/ARCHITECTURE.md`, `docs/SECURITY.md` and `docs/PLAN.md` implement this file.

## 1. Product principle: generic
- For any user on any machine. No usernames, home paths, mail addresses, domains or machine details in code, defaults, tests or docs. Examples use `example.com` / `user@example.com`.
- Everything user- or machine-specific comes from user config or is detected at runtime/setup.

## 2. Distribution
- A Python package `mailferret` (PyPI-ready, `uvx mailferret` / `pipx`). The CLI is `mailferret`, and the MCP server runs over stdio.
- **Also a full Claude Code plugin** from the same repo (the repo is its own marketplace). Skills, commands, hooks and agents are included **only if they are meaningful and pass an independent adversarial check**. The standalone server plus `register` stay first-class for other clients.
- Claude Desktop: a supported path (`register claude-desktop`, and possibly a `.mcpb` extension if it is verified to work).
- See `docs/research/claude-plugin-spec.md` and `docs/research/library-survey.md`.

## 3. Tools in scope now (read-only)
| Tool | Purpose |
|---|---|
| `list_accounts` / `list_folders` | Accounts, and folders with counts (unseen/total) |
| `search` | from / to / cc / subject / body text / date range / unseen / flagged / has-attachment, plus the alias filter (§5). Paging and a hard result limit |
| `get_message` | Headers, and the body as clean text (HTML→text), with MIME and charsets decoded. Size-capped, with a truncation notice |
| `get_thread` | The messages of one thread (References / In-Reply-To) |
| `list_attachments` / `get_attachment_text` | Metadata, and text extraction for PDF, plain text and HTML. Size limits |
| `list_aliases` | The aliases seen in a period, with counts (§5) |

## 4. Prepared for later (architecture only, disabled now)
- **Write ops** (move, flag, mark read, create folder): a separate module, off by default, enabled per account via config. Every call needs an explicit `confirm` parameter.
- **Send via SMTP**: a separate module, off by default, draft-first design.
- **IMAP IDLE / new-mail notifications**: the connection layer must allow this later without a rewrite.
- **OAuth2 / XOAUTH2**: a pluggable auth interface (for Gmail/M365 later). Password auth only for now.

## 5. Alias filter (generic)
- Per account: configurable alias domains and/or a plus-address separator. The feature is off when neither is set.
- Resolve the recipient alias from `Delivered-To`, `X-Original-To`, `To` and `Cc`. The header priority is configurable per account.
- `search` filters by alias (exact match and wildcard). `list_aliases` returns the aliases seen in a period with counts.

## 6. Accounts, config, providers
- Multiple accounts from day one. The config file lives in the platform-standard location (XDG on Linux/WSL, `%APPDATA%` on Windows, `~/Library/Application Support` on macOS), overridable by env var or CLI flag.
- Provider presets (host, ports, TLS mode, known header quirks), easy to extend. At least: generic IMAP, and Hetzner managed mail (`mail.your-server.de`, 993 implicit TLS, the login is the full address).
- CLI:
  - `mailferret setup`: interactive. Add an account from a preset or manually, and test the connection read-only.
  - `mailferret auth set <account>`
  - `mailferret accounts list`
  - `mailferret doctor`: checks config, credentials and which backend is in use, connectivity, TLS, and that uv/the launcher is on the client PATH.

## 7. Platforms and credentials
- Linux, WSL2, Windows native and macOS. CI runs tests on Linux, Windows and macOS.
- Credentials go through `keyring` with the platform backend. WSL usually has no working backend, so evaluate options and propose one; it is an open decision at Checkpoint 1. Rejected so far: `keyrings.alt`. Calling Windows binaries from WSL is acceptable *only* if the design shows it is robust, and it is never required.
- The **user** stores the password via `auth set`. Never ask anyone to paste a password into a chat.

## 8. Client registration
- `mailferret register claude-code` and `register claude-desktop`, plus `--print` to only show the snippet.
- Auto-detect config paths per platform, including Claude Desktop MSIX vs. a regular install on Windows, and WSL→Windows (launch via `wsl.exe -d <distro> -- …` with absolute paths, because Windows interop can put Windows binaries ahead of WSL ones on PATH).
- Always back up client config before writing. Never write credentials into it. Detect and warn about a duplicate registration (plugin + manual).
- Document generic MCP client setup.

## 9. Security (non-negotiable)
- Read-only by default. Write/send code paths are unreachable unless enabled in config.
- Credentials never appear in config files, the repo, logs or tool output.
- TLS certificate verification is always on.
- Mail content in tool output is marked as untrusted external data (clear delimiters).
- Limits for message size, attachment size and result count, and timeouts on every IMAP call.

## 10. Engineering
- Python with `uv`, `src/` layout, type hints, `ruff` + `mypy --strict`, `pytest`.
- **Dependency policy:** only well-adopted, regularly patched, actively maintained libraries with a permissive license and no open advisories. Vet every new dependency (see the survey).
- Tests:
  - Unit tests for MIME/charset/HTML/alias parsing with a fixture corpus: umlauts and other non-ASCII, broken charsets, nested multipart, encoded headers.
  - Integration tests against a local IMAP server in Docker (GreenMail).
  - No test touches a real mailbox automatically.
- Git: small commits per task, conventional commits, delivered via PRs, an open-source license (MIT proposed).
- README: install, setup, credentials per platform, config reference, client registration, provider presets.

## 11. Lessons from a predecessor project (requirements, not code)
- Read-only fetch uses `EXAMINE` plus `BODY.PEEK`, so `\Seen` is never set.
- Log CAPABILITY at connect and branch on it:
  - SORT: server-side ordering.
  - UIDPLUS: gates future move/expunge. Never run a session-wide EXPUNGE.
  - CONDSTORE.
- Credentials:
  - The keyring service/entry must be account-specific, because username collisions happened before.
  - Check `LOGINDISABLED` before loading the secret.
  - Never retry a failed login, to avoid lockout.
  - Redact LOGIN lines in all logs, with a test for it.
  - Typed credential errors that never echo the secret.
- Check `RFC822.SIZE` **before** fetching a body. Uncapped fetches caused OOM.
- Truncation must never split a UTF-8 codepoint.
- Charset mislabels fall back to `errors="replace"`.
- Per-attachment fault isolation.
- Large-archive search: cap results with a `truncated` flag, and use SORT when it is available.
- The launcher (`uv`/`uvx`) missing from the MCP client's PATH caused silent start failures. Registration writes absolute paths, and `doctor` checks this.
- Normalise line endings (`.gitattributes`) across WSL, Windows and macOS.
