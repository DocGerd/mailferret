""".claude/hooks/commit_guard.py: one case per review finding. Run: python3 -m unittest discover -s tests/tooling -t ."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

from .support import EMAIL, ENV, GUARD, HOME, RepoCase, git, run

ENV_LINE = "IMAP_PASS" + "WORD=" + "s3cr3t" + "Value9"
SENTINEL = "sentinel-value-7f3a"
# Hardcoded, not imported from the guard: dropping a name there must fail these tests.
REDIRECTING = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY",
               "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT",
               "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_DISCOVERY_ACROSS_FILESYSTEM", "GIT_CEILING_DIRECTORIES",
               "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS")


class Guard(RepoCase):
    def guard(self, command: str, cwd: Path | None = None, raw: str | None = None,
              env: dict[str, str] | None = None, mode: str = "pii") -> int:
        """Exit code; stderr is kept in self.stderr."""
        payload = raw if raw is not None else json.dumps(
            {"tool_input": {"command": command}, "cwd": str(cwd or self.repo)})
        res = run(["python3", str(GUARD), mode], self.repo, stdin=payload,
                  env={**ENV, "CLAUDE_PROJECT_DIR": str(self.repo), **(env or {})})
        self.assertNotIn(EMAIL, res.stderr)
        self.stderr = res.stderr
        return res.returncode

    def assert_blocked_naming(self, command: str, name: str, env: dict[str, str] | None = None) -> None:
        self.assertEqual(self.guard(command, env=env), 2)
        self.assertIn(name, self.stderr)
        self.assertNotIn(SENTINEL, self.stderr)

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
        for name in REDIRECTING:
            with self.subTest(name=name):
                self.assert_blocked_naming("git commit -a -m x", name, env={name: SENTINEL})
                self.assertEqual(self.guard("git status", env={name: SENTINEL}), 0)

    def test_redirect_set_in_the_command_blocks_commits(self) -> None:
        forms = ("{n}={v} git commit -m x", "export {n}={v}; git commit -m x", "declare -x {n}={v} && git commit -m x",
                 "typeset -x {n}={v}; git commit -m x", "env {n}={v} git commit -m x", "{n}={v}; git commit -m x",
                 "{n}={v} && git commit -m x", "{n}+={v} git commit -m x", "sudo {n}={v} git commit -m x",
                 "bash -c 'export {n}={v}; git commit -m x'", "export {n}; git commit -m x",
                 "{n}={v} git commit -m 'unterminated")
        for name in REDIRECTING:
            for form in forms:
                command = form.format(n=name, v=SENTINEL)
                with self.subTest(command=command):
                    self.assert_blocked_naming(command, name)

    def test_loaders_before_a_commit_block(self) -> None:
        for command, label in (("set -a; . ./vars; git commit -m x", "set -a"), ("set -o allexport; git commit -m x",
                               "set -a"), ("source ./vars && git commit -m x", "source"),
                               (". ./vars && git commit -m x", "."), ('eval "$X"; git commit -m x', "eval"),
                               ('export "$N"=1; git commit -m x', "export"),
                               ('env "$X" git commit -m x', "expanded"), ("env $(cat vars) git commit -m x", "expanded"),
                               ("env FOO=1 $X git commit -m x", "expanded"), ("FOO=$X git commit -m x", "expanded"),
                               ("FOO=`cat v` git commit -m x", "expanded"),
                               ("declare -n r=GIT_DIR; r=x; git commit -m x", "declare -n"),
                               ("typeset -n r=GIT_DIR; git commit -m x", "typeset -n"),
                               ("local -xn r=GIT_DIR; git commit -m x", "local -n")):
            with self.subTest(command=command):
                self.assert_blocked_naming(command, label)

    def test_unrelated_assignments_pass(self) -> None:
        for command in ("GIT_DIR=x git status", "export GIT_DIR=x; git log -1", 'git commit -m "GIT_DIR=x"',
                        "FOO=1 git commit -m x", "export PATH=$PATH:/x && git commit -m x", "set -e; git commit -m x",
                        "GIT_AUTHOR_NAME=x git commit -m x", f"git commit -F - <<'EOF'\nfix: GIT_DIR=x\nEOF",
                        "git add . && git commit -m 'unterminated", "declare -x FOO=1; git commit -m x"):
            with self.subTest(command=command):
                self.assertEqual(self.guard(command), 0, self.stderr)

    def test_tests_mode_runs_pytest_without_git_env(self) -> None:
        self.write("pyproject.toml", "")
        stub = self.write("bin/uv", '#!/bin/sh\nenv > "$UV_ENV_OUT"\n', root=self.tmp)
        stub.chmod(0o755)
        out = self.tmp / "uv-env"
        env = {"PATH": f"{stub.parent}{os.pathsep}{ENV['PATH']}", "UV_ENV_OUT": str(out), "GIT_PREFIX": "sub/"}
        self.assertEqual(self.guard("git commit -m x", env=env, mode="tests"), 0, self.stderr)
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
