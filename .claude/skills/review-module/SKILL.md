---
name: review-module
description: "Run the mailferret per-PR review gate (docs/PLAN.md §4) on a module PR: mf-reviewer and mf-security-reviewer in parallel as fresh agents, each posting its own PR review with one thread per finding."
argument-hint: "<module or task ID> [PR number]"
---

Review gate for: $ARGUMENTS

1. Resolve the PR (from the argument, else `gh pr list --head <branch>`), its branch, the PLAN task ID and the cited A§, T-nn and L-nn from `docs/PLAN.md` §2. Head SHA: `gh pr view <n> --json headRefOid --jq .headRefOid`; on a Projects-classic error use `gh api repos/{owner}/{repo}/pulls/<n> --jq .head.sha`. Confirm CI state with `gh pr checks <n>` (exit 0 pass, 8 pending).
2. In ONE message spawn both agents in the background, each with only: PR number, branch, head SHA, task ID and cited IDs. Never pass the implementer's reasoning.
   - `mf-reviewer`
   - `mf-security-reviewer`
3. Each agent posts its own review on that head SHA, one inline thread per finding, and returns the review URL, its findings and its verdict. Do not post for them.
4. Report a table: `severity | source | path:line | finding`, plus both verdicts and review URLs.

The gate passes only when every thread is fixed or explicitly answered and resolved, and both verdicts are approve on the latest commit. Fixes go to a fresh `mf-implementer`; re-run this skill after them.
