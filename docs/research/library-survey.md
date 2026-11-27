# Library survey (input to the Phase 1 design)

Snapshot taken **2026-11-27** from PyPI JSON, pypistats.org, api.osv.dev, endoflife.date and the official docs. Every version, date and download figure below is as of that day; re-check before pinning. This file is the only copy of these figures (ARCHITECTURE §8 references it).

| Component | Choice | Version / date | License | Notes |
|---|---|---|---|---|
| Python | floor `>=3.11`, develop on 3.14 | 3.15.2 latest | PSF | 3.10 is EOL; 3.11 is supported until 2027-10. `platformdirs`/`inscriptis` need 3.11+ |
| uv | `uvx mailferret` | 0.13.10 (2026-11-24) | MIT/Apache | `uvx --from <pkg> <cmd>` is still the documented pattern. The CI pin is the single `[tool.uv] required-version` in `pyproject.toml`, read by setup-uv; Dependabot does not bump it, so bump it by hand with the uv release |
| MCP SDK | official `mcp >=2.3,<3` | 2.3.0 (2026-10-02) | MIT | **v2 breaks v1**: `from mcp.server import MCPServer` (FastMCP renamed), types in `mcp-types`, `MCPError`, snake_case fields. Protocol `2026-07-28`; use `LATEST_HANDSHAKE_VERSION`. Tools: `@mcp.tool(annotations=ToolAnnotations(...))`, structured output from a pydantic return type, stdio is the default. Annotation fields are snake_case (`read_only_hint`, `destructive_hint`, `idempotent_hint`, `open_world_hint`; verified in the `mcp_types` API reference). Errors: raising `ToolError` (`mcp.server.mcpserver.exceptions`) returns `is_error=True` with the message in `content` and `structured_content` empty; `MCPError` is a JSON-RPC protocol error the model never sees; any other exception is a crash shown as `Error executing tool <name>`. A pydantic return fills both `content` (a text rendering) and `structured_content`; returning a `CallToolResult` directly sets both explicitly (validated against the output model). Sources: py.sdk.modelcontextprotocol.io servers/handling-errors, servers/structured-output, api/mcp_types |
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
| Paths | `platformdirs` | 4.14.8 (2026-11-20) | MIT | |
| CLI | `click` | 8.5.1 (2026-11-06) | BSD-3 | `typer` is fine but only a wrapper |
| Config | `pydantic` v2 | 2.14.4 (2026-11-19) | MIT | already a dependency of `mcp` |
| TOML | `tomllib` (read) + `tomlkit` (write) | 0.15.3 (2026-11-24) | MIT | tomli-w was dropped after vetting (see below) |
| Test IMAP server | GreenMail `greenmail/standalone` | 2.1.15 | Apache-2.0 | IMAP+IMAPS. Preload by APPEND in fixtures. Configured via `GREENMAIL_OPTS` / `GREENMAIL_ADDITIONAL_OPTS` / `JAVA_OPTS` (verified in the GreenMail docs); defaults are auth disabled and a self-signed certificate |
| Lint | `ruff` | 0.17.6 (2026-11-19) | MIT | |
| Types | `mypy --strict` | 2.4.1 (2026-10-28) | MIT | `ty` is still 0.0.x beta |
| Tests | `pytest` | 9.2.0 (2026-10-27) | MIT | |
| HTML parser (via inscriptis) | `lxml` | 6.1.3 (2026-09-02) | BSD-3 | |

Sources: pypi.org/pypi/<pkg>/json, endoflife.date/api/python.json, py.sdk.modelcontextprotocol.io (migration, structured-output), docs.astral.sh/uv/guides/tools, docs.python.org/3.14/library/imaplib.html, pypdf.readthedocs.io/en/stable/user/security.html, hub.docker.com greenmail/standalone, github.com/mjs/imapclient.

## Dependency vetting (policy check)

Policy: significant downloads (≥1M/month for core runtime deps), regular patch releases or a mature project with recent commits, actively maintained (not archived), no open OSV advisories. Runtime dependencies must be permissive (MIT/BSD/Apache/PSF-compatible). Dev/test-only tools may be weak copyleft (MPL-2.0, LGPL) if they pass the same health checks.

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
| hypothesis | PASS as dev-only (MPL-2.0 weak copyleft, allowed for dev/test tools; 6.170.18 released 2026-11-27, 5329 files in the last 12 months, ~75.2M downloads/month, no OSV advisories) | **adopt, dev-only**: property-based MIME/charset/alias fuzzing (T-19) |
| secretstorage, jeepney (keyring, Linux) | PASS (BSD-3 / MIT, ~150M downloads/month, no OSV advisories; low release cadence, mature) | adopt as keyring transitives |
| pywin32-ctypes (keyring, Windows) | BORDERLINE (BSD-3, ~8M downloads/month, no OSV advisories, last release 2024-08) | accept as a keyring transitive; re-check with keyring |
| jaraco.classes, jaraco.functools, importlib-metadata (<3.12) (keyring) | PASS (MIT / Apache-2.0, >150M downloads/month, no OSV advisories) | adopt as keyring transitives |
| jaraco.context (keyring) | PASS with a floor: two OSV entries (GHSA-58pv-8j8x-9vj2 / PYSEC-2026-1469, path traversal) affect 5.2.0 to <6.1.0; 6.1.2 is current | the lock must resolve `>=6.1.0`; the dependency audit enforces it |
| colorama (click, Windows; runtime) | PASS (BSD-3, ~299M downloads/month, no OSV advisories; mature, last release 0.4.6 in 2022-10) | adopt as a click transitive |
| uv_build (build backend, `[build-system]`) | PASS (MIT OR Apache-2.0 on PyPI; Astral, same release line as uv, 0.13.10 on 2026-11-24; first release 2025-02, ~20M downloads/month, no OSV advisories) | adopt as build backend. It sits in `[build-system].requires`, outside `uv.lock`, so `uv audit` does not cover it; it is bounded by the `<0.14` cap and the pinned uv in CI |
| ast-serialize (mypy, dev-only) | PASS (MIT on PyPI; mypyc project, 0.13.1 released 2026-10-17, first release 2026-01, 23 releases; ~114M downloads/month, no OSV advisories) | young but maintained by the mypy authors; adopt dev-only, never shipped |
| librt (mypy, dev-only) | PASS (MIT on PyPI; mypyc project, 0.17.0 released 2026-11-19, first release 2025-09, 34 releases; ~174M downloads/month, no OSV advisories) | young but maintained by the mypy authors; adopt dev-only, never shipped |
| pydantic-core (pydantic, runtime) | PASS (MIT on PyPI; pydantic project, source in the pydantic repo, 2.50.5 released 2026-11-19, 165 releases since 2022-04; ~1,188M downloads/month, no OSV advisories; compiled Rust wheels) | adopt as a pydantic transitive; the pin follows pydantic |
| annotated-types (pydantic, runtime) | PASS (MIT on PyPI; 0.8.0 released 2026-07-23, 9 releases since 2022-05, repo not archived and pushed 2026-10; ~1,052M downloads/month, no OSV advisories; small pure-Python package) | adopt as a pydantic transitive |
| typing-inspection (pydantic, runtime) | PASS (MIT on PyPI; pydantic project, 0.4.5 released 2026-11-04, 11 releases since 2025-02; ~1,054M downloads/month, no OSV advisories) | adopt as a pydantic transitive |
| typing-extensions (pydantic, pydantic-core, typing-inspection, runtime; mypy, dev) | PASS (PSF-2.0 on PyPI; CPython typing team, 4.16.0 released 2026-07-02, 52 releases since 2017; ~1,827M downloads/month, no OSV advisories) | adopt as a runtime transitive of pydantic; also pulled in by mypy |
| Dev-only indirect packages of vetted tools, listed only: mypy-extensions, pathspec (MPL-2.0), pluggy, iniconfig, packaging, pygments (mypy, pytest), sortedcontainers (hypothesis; Apache-2.0, mature, last release 2021-05, no OSV advisories) | accepted on the strength of `uv.lock` plus the `uv audit` CI job; licenses checked on PyPI (MIT, MPL-2.0, Apache-2.0 OR BSD-2-Clause, BSD-2-Clause, Apache-2.0) | dev-only, never shipped; any new indirect package needs vetting before it is accepted |
| Windows job objects (T-06, T-17) | no package: own stdlib `ctypes` code | pywin32 not adopted |

Transitive dependencies worth tracking:
- `mcp` pulls starlette, uvicorn, sse-starlette, httpx2, pyjwt[crypto] (cryptography), jsonschema and opentelemetry-api, even for stdio. That cost is accepted, so budget for CVE churn and pin `mcp>=2.3,<3`.
- `inscriptis` pulls `requests` (unused) and caps `lxml<6.2`. Never install its `web-service` extra.
