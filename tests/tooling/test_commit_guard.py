""".claude/hooks/commit_guard.py: one case per review finding. Run: python3 -m unittest discover -s tests/tooling"""

from __future__ import annotations

import json
from pathlib import Path

from support import EMAIL, ENV, GUARD, HOME, RepoCase, git, run

ENV_LINE = "IMAP_PASS" + "WORD=" + "s3cr3t" + "Value9"


class Guard(RepoCase):
    def guard(self, command: str, cwd: Path | None = None, raw: str | None = None) -> int:
        payload = raw if raw is not None else json.dumps(
            {"tool_input": {"command": command}, "cwd": str(cwd or self.repo)})
        res = run(["python3", str(GUARD), "pii"], self.repo, stdin=payload,
                  env={**ENV, "CLAUDE_PROJECT_DIR": str(self.repo)})
        self.assertNotIn(EMAIL, res.stderr)
        return res.returncode

    def stage_hit(self, root: Path) -> None:
        self.write("leak.txt", f"{EMAIL}\n", root=root)
        git(root, "add", "leak.txt")

    def worktree(self, path: Path) -> Path:
        git(self.repo, "worktree", "add", "-q", "-b", path.name, str(path))
        return path

    def test_clean_commit_passes(self) -> None:
        self.assertEqual(self.guard('git commit -m "fix: thing; more" 2>&1 | tail -1'), 0)
        self.assertEqual(self.guard("git status && git log --oneline -3"), 0)

    def test_cd_into_worktree_before_commit(self) -> None:
        wt = self.worktree(self.repo / ".claude" / "worktrees" / "wt")
        self.stage_hit(wt)
        self.assertEqual(self.guard("cd .claude/worktrees/wt && git commit -m x"), 2)

    def test_linked_worktree_outside_project(self) -> None:
        wt = self.worktree(self.tmp / "review-wt")
        self.stage_hit(wt)
        self.assertEqual(self.guard(f"git -C {wt} commit -m x"), 2)
        self.assertEqual(self.guard("git commit -m x", cwd=wt), 2)

    def test_foreign_repo_is_left_alone(self) -> None:
        other = self.tmp / "other"
        other.mkdir()
        git(other, "init", "-q")
        self.stage_hit(other)
        self.assertEqual(self.guard(f"cd {other} && git commit -m x"), 0)

    def test_force_added_ignored_file(self) -> None:
        self.write(".env", ENV_LINE + "\n")
        self.assertEqual(self.guard("git add -f .env && git commit -m wip"), 2)
        self.assertEqual(self.guard("git add . && git commit -m wip"), 0)  # .env stays ignored

    def test_commit_message_is_scanned(self) -> None:
        self.assertEqual(self.guard(f'git commit -m "contact {EMAIL}"'), 2)
        self.assertEqual(self.guard(f"git commit -am 'see {HOME}/x'"), 2)
        self.assertEqual(self.guard(f"git commit -F - <<'EOF'\nfix: x\n\n{EMAIL}\nEOF"), 2)
        self.assertEqual(self.guard(f"git commit -m \"$(cat <<'EOF'\nfix: x\n\n{EMAIL}\nEOF\n)\""), 2)
        msg = self.write("msg.txt", f"{EMAIL}\n", root=self.tmp)
        self.assertEqual(self.guard(f"git commit -F {msg}"), 2)
        self.assertEqual(self.guard('git commit -m "Co-Authored-By: X <noreply@anthropic.com>"'), 0)

    def test_expansion_and_aliases_are_ambiguous(self) -> None:
        self.stage_hit(self.repo)
        for command in ("c=commit; git $c -m x", "git $(echo commit) -m x", "G=git; $G commit -m x",
                        "git ci -m x", "bash -c 'git commit -m x'"):
            with self.subTest(command=command):
                self.assertEqual(self.guard(command), 2)
        self.assertEqual(self.guard("git status"), 0)

    def test_unresolvable_target_fails_closed(self) -> None:
        self.assertEqual(self.guard("cd /nonexistent-mf-dir && git commit -m x"), 2)
        plain = self.tmp / "plain"
        plain.mkdir()
        self.assertEqual(self.guard("git commit -m x", cwd=plain), 2)

    def test_crash_fails_closed_for_possible_commits(self) -> None:
        self.assertEqual(self.guard("", raw='{"tool_input": "git commit -m x"'), 2)
        self.assertEqual(self.guard("", raw='{"tool_input": "ls"'), 0)
        bad_cwd = json.dumps({"tool_input": {"command": "git merge feature"}, "cwd": "/tmp/\u0000x"})
        self.assertEqual(self.guard("", raw=bad_cwd), 2)
