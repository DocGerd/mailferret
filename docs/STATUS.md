# Status

Phase: 2a done (scaffold F0, spikes V1–V4) and the architecture update that folds the spike results into the design (issue #7). Phase 2b–2d tasks may start.

## Done

- Phase 1 design approved at Checkpoint 1 (`docs/ARCHITECTURE.md` §11).
- Claude Code project configuration: `.claude/agents/mf-*`, `.claude/skills/`, `.claude/settings.json` (permissions, ruff/test/PII hooks), `.mcp.json` (Context7, development only), `scripts/pii_check.py` + `.githooks/` + `.github/workflows/pii-check.yml` (self-tests in `tests/tooling/`), `.gitattributes`.
- Phase 2a: F0 scaffold; spikes V1–V4 (notes in `docs/research/v1-…` to `v4-…`); the architecture update (ARCHITECTURE §10 marks every item resolved, decided or open).

## Next

1. One-time contributor setup: `git config core.hooksPath .githooks` (PII scan and tests on every commit).
2. Start the tasks whose dependencies are merged (`docs/PLAN.md` §2, §5), each in its own worktree: B1, B3, B7, C0, D0.

## Open

- Decisions left to their owning task:
  - B5: the gpg status channel, `pass_fds` or a 0600 `--status-file`, and how the `command` backend recognises a gpg recipe to add it (A§2.1).
  - D3: whether a non-ASCII login, not only a non-ASCII secret, takes `AUTHENTICATE PLAIN` (V1 ran the secret only; A§2 `auth/` row, T-02, T-16); a time-boxed marker for an indeterminate auth outcome, so other processes do not log in again at once (T-16 residual risk until then). Every other site marks both as the default, pending D3.
  - F2: whether `register claude-code` still refuses unless `--force`, now that the reason is a duplicate server rather than shadowing (A§9.5); where the WSL launcher script goes, and what happens when no space-free absolute path exists (A§9.6).
  - P1: `--exclude-newer` as a second pin (A§9.2).
  - P3: whether P3 still needs D0 now that evals use MCP mocks (PLAN P3).
  - Confirm the proposed ceilings (SECURITY §5): `L-26` (D2), `L-27` (B4), `L-28` and `L-29` (B5). Confirm the `L-20` line allowance in the `L-26` total, which keeps default FETCH batches well below `L-25` (D2, D5; A§2.2). Set the `L-26` per-line overhead constant from a `tracemalloc` measurement on every minor (D2; A§2.2).
- Verification owned by agent tasks (ARCHITECTURE §10): item 7, the `gpg2`/`GPG_AGENT_INFO` branch warm and expired (B5); items 17 and 18 (P2 `--strict`; P3 runtime); item 23, the job object and the keyring probe on Windows and macOS (B4, B5); item 24, no server starts in an eval run (P3).
- C4: research and run the Windows job-object and macOS `RLIMIT_AS` PDF worker memory caps on windows and macos CI runners, plus the cyclic page-tree and 100,000-page bombs (A§10 item 10). Until then T-06 scopes the memory guarantee to Linux.
- Manual checks only a user can run: ARCHITECTURE §10 items 5, 7 (the client- or `wsl.exe`-launched part), 9, 14, 19, 21 and 22.
- Task-owner notes from the architecture-update review: issue #14 (D2, D5, B4, B5, C4, E3, P3).
- Parked: issue #10, commit-guard hardening. The guard stays best effort; `.githooks` and CI `scan` enforce.

## Contributor notes

- Windows: the git hooks find Python as `python3`, `python` or `py -3`. Where `python3` is the Microsoft Store stub, run the scanner as `py -3 scripts/pii_check.py`.
- Context7 (`.mcp.json`) is for development only. The pin covers the top-level package only: its npm dependencies are unpinned and resolved by `npx` on a cold cache, with no lockfile. Approve the server per user; never set `enableAllProjectMcpServers`.
- Native Windows needs a `cmd /c` wrapper for `npx`. Add a local-scope override with the version from `.mcp.json`: `claude mcp add-json -s local context7 '{"command":"cmd","args":["/c","npx","-y","@upstash/context7-mcp@<version>"]}'`.
- The Read/Edit denies in `.claude/settings.json` cover the default config, data and credential locations only. A config moved with `XDG_CONFIG_HOME` or `MAILFERRET_CONFIG` is not covered.
- Tooling self-tests: `python3 -m unittest discover -s tests/tooling -t .` (from the repo root).
