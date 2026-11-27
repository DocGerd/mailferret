---
name: review-module
description: "Run the mailferret per-PR review gate (docs/PLAN.md §4) on a module PR: mf-reviewer and mf-security-reviewer in parallel as fresh agents, findings posted as one PR review thread each."
argument-hint: "<module or task ID> [PR number]"
disable-model-invocation: true
---

Review gate for: $ARGUMENTS

1. Resolve the PR (from the argument, else `gh pr list --head <branch>`), its branch, the PLAN task ID and the cited A§, T-nn and L-nn from `docs/PLAN.md` §2. Confirm CI state with `gh pr checks <n>` (exit 0 pass, 8 pending).
2. In ONE message spawn both agents in the background, each with only: PR number, branch, task ID, cited IDs, and the instruction to use `git show origin/<branch>:<path>` or its own worktree. Never pass the implementer's reasoning.
   - `mf-reviewer`
   - `mf-security-reviewer`
3. Post each finding as its own inline review thread on a changed line (`gh api repos/{owner}/{repo}/pulls/<n>/comments` with `-F` fields: `body`, `commit_id`, `path`, `line`, `side=RIGHT`). A finding on an unchanged file is anchored on the nearest changed line and names its real location.
4. Report a table: `severity | source | path:line | finding`, plus both verdicts.

The gate passes only when every thread is fixed or explicitly answered and resolved, and both verdicts are approve on the latest commit. Fixes go to a fresh `mf-implementer`; re-run this skill after them.
