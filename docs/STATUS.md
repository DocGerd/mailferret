# Status

Phase: 2a done (scaffold F0, spikes V1–V4) and the architecture update that folds the spike results into the design (issue #7). Phase 2b–2d under way: B1, B2, B3, B4, B5, B6, B7, C0, C1, C2, C4, C5, D0, D1, D2, D4, F1 merged.

## Done

- Phase 1 design approved at Checkpoint 1 (`docs/ARCHITECTURE.md` §11).
- Claude Code project configuration: `.claude/agents/mf-*`, `.claude/skills/`, `.claude/settings.json` (permissions, ruff/test/PII hooks), `.mcp.json` (Context7, development only), `scripts/pii_check.py` + `.githooks/` + `.github/workflows/pii-check.yml` (self-tests in `tests/tooling/`), `.gitattributes`.
- Phase 2a: F0 scaffold; spikes V1–V4 (notes in `docs/research/v1-…` to `v4-…`); the architecture update (ARCHITECTURE §10 marks every item resolved, decided or open).
- Phase 2b–2d: B1 (#17), B3 (#15), B7 (#16), C0 (#18), D0 (#19), B2 (#22), B6 (#23), F1 (#24), D4 (#25), D1 (#29), C1 (#31), B4 (#33, replacing #32), B5 (#37), C2 (#36), C4 (#40), C5 (#35), D2 (#43, replacing #39); Windows backup-name fix (#28); Python 3.13 floor (#44).

## Next

1. One-time contributor setup: `git config core.hooksPath .githooks` (PII scan and tests on every commit).
2. Start the next unblocked PLAN tasks (see `docs/PLAN.md` §2), each in its own worktree (§5).

## Open

- Decisions left to their owning task:
  - D3: whether a non-ASCII login, not only a non-ASCII secret, takes `AUTHENTICATE PLAIN` (V1 ran the secret only; A§2 `auth/` row, T-02, T-16); a time-boxed marker for an indeterminate auth outcome, so other processes do not log in again at once (T-16 residual risk until then). Every other site marks both as the default, pending D3.
  - F2: whether `register claude-code` still refuses unless `--force`, now that the reason is a duplicate server rather than shadowing (A§9.5); where the WSL launcher script goes, and what happens when no space-free absolute path exists (A§9.6).
  - P1: `--exclude-newer` as a second pin (A§9.2).
  - P3: whether P3 still needs D0 now that evals use MCP mocks (PLAN P3).
  - Confirm the `L-20` line allowance in the `L-26` total, which keeps default FETCH batches well below `L-25` (D2, D5; A§2.2).
- Verification owned by agent tasks (ARCHITECTURE §10): item 7, the `gpg2`/`GPG_AGENT_INFO` branch warm and expired (B5); items 17 and 18 (P2 `--strict`; P3 runtime); item 23, the job object and the keyring probe on Windows and macOS (B4, B5); item 24, no server starts in an eval run (P3).
- C4 (done, PR #40): Windows job-object cap enforced and macOS `RLIMIT_AS` refused (wall time plus caps, noted per result), both observed on CI; bombs run on every OS. Open for D6/C3: the registry's HTML slot (`unsupported` until C3) and a shared `Cf` stripper in place of the registry's local one.
- Manual checks only a user can run: ARCHITECTURE §10 items 5, 7 (the client- or `wsl.exe`-launched part), 9, 14, 19, 21 and 22.
- Task-owner notes from the architecture-update review: issue #14 (D2, D5, B4, B5, C4, E3, P3).
- Task-owner notes from the B1, B3, B7, C0, D0, B2, B6, F1, D4, D1, C1 and B4 reviews: also issue #14.
- Parked: issue #10, commit-guard hardening. The guard stays best effort; `.githooks` and CI `scan` enforce.

## Contributor notes

- Windows: the git hooks find Python as `python3`, `python` or `py -3`. Where `python3` is the Microsoft Store stub, run the scanner as `py -3 scripts/pii_check.py`.
- Context7 (`.mcp.json`) is for development only. The pin covers the top-level package only: its npm dependencies are unpinned and resolved by `npx` on a cold cache, with no lockfile. Approve the server per user; never set `enableAllProjectMcpServers`.
- Native Windows needs a `cmd /c` wrapper for `npx`. Add a local-scope override with the version from `.mcp.json`: `claude mcp add-json -s local context7 '{"command":"cmd","args":["/c","npx","-y","@upstash/context7-mcp@<version>"]}'`.
- The Read/Edit denies in `.claude/settings.json` cover the default config, data and credential locations only. A config moved with `XDG_CONFIG_HOME` or `MAILFERRET_CONFIG` is not covered.
- Tooling self-tests: `python3 -m unittest discover -s tests/tooling -t .` (from the repo root).
