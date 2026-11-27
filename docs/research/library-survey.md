# Library survey (input to the Phase 1 design)

Snapshot from PyPI JSON, endoflife.date and the official docs at design time. Re-check versions before pinning.

| Component | Choice | Version / date | License | Notes |
|---|---|---|---|---|
| Python | floor `>=3.11`, develop on 3.14 | 3.15.2 latest | PSF | 3.10 is EOL; 3.11 is supported until 2027-10. `platformdirs`/`inscriptis` need 3.11+ |
| uv | `uvx mailferret` | 0.13.10 (2026-11-24) | MIT/Apache | `uvx --from <pkg> <cmd>` is still the documented pattern |
| MCP SDK | official `mcp >=2.3,<3` | 2.3.0 (2026-10-02) | MIT | **v2 breaks v1**: `from mcp.server import MCPServer` (FastMCP renamed), types in `mcp-types`, `MCPError`, snake_case fields. Protocol `2026-07-28`; use `LATEST_HANDSHAKE_VERSION`. Tools: `@mcp.tool(annotations=ToolAnnotations(...))`, structured output from a pydantic return type, stdio is the default. The exact `read_only_hint` field name is unverified |
| (rejected) fastmcp | — | 4.2.6 | Apache | heavy dependency tree, releases every few days |
| IMAP | `imapclient` (sync) | 4.3.0 (2026-11-17) | BSD-3 | socket timeout, `idle()`/`idle_check()`, `sort`, UIDs by default, `oauth2_login` (XOAUTH2). ESEARCH unverified |
| (rejected) aioimaplib | — | 2.0.3 | GPL-3.0 | license |
| (fallback) imaplib | stdlib | — | PSF | `idle()` only from 3.14 |
| HTML→text | `inscriptis` | 2.7.7 (2026-11-19) | Apache-2.0 | lxml-based, no network fetch. Strip script/style and cap the size first. Fallback: `justhtml` 3.18.0 (MIT, pure Python) |
| (rejected) html2text | — | — | GPL-3.0 | license |
| PDF text | `pypdf` | 7.2.0 (2026-11-26) | BSD-3 | pure Python. **Not bomb-hardened by default**: cap input bytes, pages and extracted chars, use a timeout or subprocess, lower `maximum_declared_stream_length`, never use the `[image]`/`[full]` extras |
| (rejected) pymupdf | — | — | AGPL | license |
| Credentials | `keyring` | 25.7.0 (2025-11-16) | MIT | macOS Keychain, Windows Credential Locker, Secret Service. **WSL: no backend by default** (NoKeyringError); detect the fail/null backend |
| WSL options | — | — | — | `keyrings.alt` (last release 2024, weak), `keyring-pass` (stale, needs gpg), gnome-keyring under WSLg (fragile, needs dbus+unlock), a password-command hook. No maintained WSL→Windows Credential Manager bridge; don't shell out to Windows binaries |
| Paths | `platformdirs` | 4.14.8 | MIT | |
| CLI | `click` | 8.5.1 | BSD-3 | `typer` is fine but only a wrapper |
| Config | `pydantic` v2 | 2.14.4 | MIT | already a dependency of `mcp` |
| TOML | `tomllib` (read) + `tomlkit` (write) | 0.15.3 | MIT | tomli-w was dropped after vetting (see below) |
| Test IMAP server | GreenMail `greenmail/standalone` | 2.1.15 | Apache-2.0 | IMAP+IMAPS. Preload by APPEND in fixtures; env var names unverified |
| Lint | `ruff` | 0.17.6 | MIT | |
| Types | `mypy --strict` | 2.4.1 | MIT | `ty` is still 0.0.x beta |
| Tests | `pytest` | 9.2.0 | MIT | |

Sources: pypi.org/pypi/<pkg>/json, endoflife.date/api/python.json, py.sdk.modelcontextprotocol.io (migration, structured-output), docs.astral.sh/uv/guides/tools, docs.python.org/3.14/library/imaplib.html, pypdf.readthedocs.io/en/stable/user/security.html, hub.docker.com greenmail/standalone, github.com/mjs/imapclient.

## Dependency vetting (policy check)

Policy: significant downloads (≥1M/month for core runtime deps), regular patch releases or a mature project with recent commits, actively maintained (not archived), no open OSV advisories, MIT-compatible license.

| Package | Verdict | Decision |
|---|---|---|
| mcp, imapclient, inscriptis, pypdf, platformdirs, click, pydantic, tomlkit, lxml, ruff, mypy, pytest | PASS | adopt |
| keyring | BORDERLINE (no release in 12 months, commits are recent, 157M downloads/month) | adopt; re-check if there is still no release by 2027-03 |
| tomli-w | BORDERLINE (no release or commit for ~10 months) | **replace with tomlkit** (writes and preserves comments; read with tomllib) |
| justhtml | BORDERLINE (185k downloads/month, single maintainer) | not a hard dependency; optional fallback at most |
| keyrings.alt | FAIL (no release since 2024, weak file store) | **reject** |
| pyright | BORDERLINE (community wrapper, downloads Node at runtime) | not used; mypy --strict |
| typer | PASS | not used; click is enough (typer adds rich + shellingham) |
| beautifulsoup4 | not needed | — |

Transitive dependencies worth tracking:
- `mcp` pulls starlette, uvicorn, sse-starlette, httpx2, pyjwt[crypto] (cryptography), jsonschema and opentelemetry-api, even for stdio. That cost is accepted, so budget for CVE churn and pin `mcp>=2.3,<3`.
- `inscriptis` pulls `requests` (unused) and caps `lxml<6.2`. Never install its `web-service` extra.
