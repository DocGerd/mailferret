---
name: mf-status
description: "Report the mailferret project state: phase, next step and open items from docs/STATUS.md plus git state, in at most 10 lines. Use at session start or when asked where the project stands."
allowed-tools:
  - Read
  - Bash(git status *)
  - Bash(git log *)
  - Bash(git config --get core.hooksPath)
  - Bash(gh pr list *)
---

Report the project state in at most 10 lines. Do not change anything.

1. Read `docs/STATUS.md`.
2. Run `git status -sb`, `git log --oneline -5`, `git config --get core.hooksPath`, and `gh pr list --state open --limit 10` (skip if `gh` fails).
3. Output:
   - Phase: <from STATUS>
   - Next: <the exact next step from STATUS>
   - Open: <open items, open PRs, uncommitted or unpushed work>
   - Branch: <branch and tracking state from the first line of `git status -sb`>
   - Hooks: `WARNING: git hooks off, terminal commits unscanned` unless the hooksPath is `.githooks`

No other prose.
