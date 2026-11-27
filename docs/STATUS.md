# Status

Phase: RESTART POINT A done (Claude Code project configuration). Restart required.

## Done

- Phase 1 design approved at Checkpoint 1 (`docs/ARCHITECTURE.md` §11).
- Claude Code project configuration: `.claude/agents/mf-*`, `.claude/skills/`, `.claude/settings.json` (permissions, ruff/test/PII hooks), `.mcp.json` (Context7, development only), `scripts/pii_check.py` + `.githooks/` + `.github/workflows/pii-check.yml` (self-tests in `tests/tooling/`), `.gitattributes`.

## Next

1. One-time contributor setup: `git config core.hooksPath .githooks` (PII scan and tests on every commit).
2. Start `claude` in the repo and say: Continue from docs/STATUS.md
3. Phase 2 per `docs/PLAN.md`: first the verification spikes V1–V4 (`mf-researcher` writes the notes, `mf-implementer` runs the executable parts), in parallel with the scaffold F0 (`mf-implementer`).

## Open

- Make `pii-check` a required check in a ruleset on `main`; until then it reports but cannot block a merge.

## Contributor notes

- Windows: the git hooks find Python as `python3`, `python` or `py -3`. Where `python3` is the Microsoft Store stub, run the scanner as `py -3 scripts/pii_check.py`.
- Context7 (`.mcp.json`) is for development only. The pin covers the top-level package only: its npm dependencies are unpinned and resolved by `npx` on a cold cache, with no lockfile. Approve the server per user; never set `enableAllProjectMcpServers`.
- Native Windows needs a `cmd /c` wrapper for `npx`. Add a local-scope override with the version from `.mcp.json`: `claude mcp add-json -s local context7 '{"command":"cmd","args":["/c","npx","-y","@upstash/context7-mcp@<version>"]}'`.
- The Read/Edit denies in `.claude/settings.json` cover the default config, data and credential locations only. A config moved with `XDG_CONFIG_HOME` or `MAILFERRET_CONFIG` is not covered.
- Tooling self-tests: `python3 -m unittest discover -s tests/tooling -t .` (from the repo root).
