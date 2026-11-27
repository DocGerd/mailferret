""".claude/hooks/commit_guard.py: one case per review finding. Run: python3 -m unittest discover -s tests/tooling -t ."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

from .support import EMAIL, ENV, GUARD, HOME, RepoCase, git, run

ENV_LINE = "IMAP_PASS" + "WORD=" + "s3cr3t" + "Value9"


class Guard(RepoCase):
    def guard_run(self, command: str, cwd: Path | None = None, raw: str | None = None,
                  env: dict[str, str] | None = None, mode: str = "pii") -> subprocess.CompletedProcess[str]:
        payload = raw if raw is not None else json.dumps(
            {"tool_input": {"command": command}, "cwd": str(cwd or self.repo)})
        res = run(["python3", str(GUARD), mode], self.repo, stdin=payload,
                  env={**ENV, "CLAUDE_PROJECT_DIR": str(self.repo), **(env or {})})
        self.assertNotIn(EMAIL, res.stderr)
        return res

    def guard(self, command: str, cwd: Path | None = None, raw: str | None = None,
              env: dict[str, str] | None = None) -> int:
        return self.guard_run(command, cwd, raw, env).returncode

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

    def test_inherited_git_env_blocks_commits(self) -> None:
        other = self.tmp / "other"
        other.mkdir()
        git(other, "init", "-q")
        cases = {
            "GIT_DIR": {"GIT_DIR": str(other / ".git")},
            "GIT_INDEX_FILE": {"GIT_INDEX_FILE": str(other / ".git" / "index")},
            "GIT_CONFIG_PARAMETERS": {"GIT_CONFIG_PARAMETERS": f"'core.worktree={other}'"},
            "GIT_CONFIG_COUNT": {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.worktree",
                                 "GIT_CONFIG_VALUE_0": str(other)},
            "GIT_CEILING_DIRECTORIES": {"GIT_CEILING_DIRECTORIES": str(self.tmp)},
            "GIT_DISCOVERY_ACROSS_FILESYSTEM": {"GIT_DISCOVERY_ACROSS_FILESYSTEM": str(other)},
        }
        for name, env in cases.items():
            with self.subTest(name=name):
                res = self.guard_run("git commit -a -m x", env=env)
                self.assertEqual(res.returncode, 2)
                self.assertIn(name, res.stderr)
                self.assertNotIn(str(self.tmp), res.stderr)
                self.assertEqual(self.guard("git status", env=env), 0)

    def test_tests_mode_runs_pytest_without_git_env(self) -> None:
        self.write("pyproject.toml", "")
        stub = self.write("bin/uv", '#!/bin/sh\nenv > "$UV_ENV_OUT"\n', root=self.tmp)
        stub.chmod(0o755)
        out = self.tmp / "uv-env"
        env = {"PATH": f"{stub.parent}{os.pathsep}{ENV['PATH']}", "UV_ENV_OUT": str(out), "GIT_PREFIX": "sub/"}
        res = self.guard_run("git commit -m x", env=env, mode="tests")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(out.exists())
        self.assertEqual([line for line in out.read_text().splitlines() if line.startswith("GIT_")], [])

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

    def test_line_continuation_and_process_substitution(self) -> None:
        self.stage_hit(self.repo)
        for command in ("git \\\n  commit -m x", "cat <(git commit -m x)", "diff <(git show HEAD) >(git commit -m x)"):
            with self.subTest(command=command):
                self.assertEqual(self.guard(command), 2)

    def test_line_continuation_keeps_commit_flags(self) -> None:
        self.write("README.md", f"{EMAIL}\n")  # unstaged: only `-a` commits it
        self.assertEqual(self.guard("git commit \\\n  -a -m x"), 2)

    def test_command_running_subcommands_are_ambiguous(self) -> None:
        self.stage_hit(self.repo)
        for command in ("git bisect run sh -c 'git commit -m x'", "git submodule foreach 'git commit -m x'"):
            with self.subTest(command=command):
                self.assertEqual(self.guard(command), 2)

    def test_wrapped_commit_scans_every_worktree_and_its_text(self) -> None:
        wt = self.worktree(self.repo / ".claude" / "worktrees" / "wt")
        self.stage_hit(wt)
        self.assertEqual(self.guard("echo x | xargs git commit -m x"), 2)
        git(wt, "reset", "-q")
        self.assertEqual(self.guard(f'sudo git commit -m "{EMAIL}"'), 2)
        self.assertEqual(self.guard(f'git commit -m x --trailer "Reported-by: R <{EMAIL}>"'), 2)

    def test_every_unknown_message_source_is_replaced_by_the_command(self) -> None:
        spec = importlib.util.spec_from_file_location("commit_guard", GUARD)
        assert spec and spec.loader
        guard = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = guard  # dataclasses resolve their module
        spec.loader.exec_module(guard)
        command = "git commit -F $A && git commit -F -"
        self.assertEqual(guard.analyse(command, self.repo).messages, [command])

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
