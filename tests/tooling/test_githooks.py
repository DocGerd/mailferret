""".githooks: the sh wrappers start Python, commit-msg scans the message content, never its path, and pre-commit
scans the index git names while the tests run without git's env."""

from __future__ import annotations

import os
import shutil

from .support import EMAIL, ENV, HOME, REPO, RepoCase, run


class CommitMsg(RepoCase):
    def test_message_path_is_not_scanned(self) -> None:
        shutil.copytree(REPO / ".githooks", self.repo / ".githooks")
        msg = self.write("q+" + HOME + "/COMMIT_EDITMSG", "fix: clean\n", root=self.tmp)
        hook = str(self.repo / ".githooks" / "commit-msg")
        self.assertEqual(run(["sh", hook, str(msg)], self.repo).returncode, 0)
        msg.write_text(f"fix: {EMAIL}\n")
        res = run(["sh", hook, str(msg)], self.repo)
        self.assertNotEqual(res.returncode, 0)
        self.assertNotIn(EMAIL, res.stdout + res.stderr)


class PreCommit(RepoCase):
    def test_scanner_keeps_git_env_and_tests_drop_it(self) -> None:
        shutil.copytree(REPO / ".githooks", self.repo / ".githooks")
        self.write("pyproject.toml", "")
        stub, out = self.uv_stub()
        alt_index = self.tmp / "alt-index"
        shutil.copy(self.repo / ".git" / "index", alt_index)
        self.write("leak.txt", f"{EMAIL}\n")
        run(["git", "add", "leak.txt"], self.repo, env={**ENV, "GIT_INDEX_FILE": str(alt_index)}, check=True)
        hook = str(self.repo / ".githooks" / "pre-commit")
        hook_env = {**ENV, "PATH": f"{stub.parent}{os.pathsep}{ENV['PATH']}", "UV_ENV_OUT": str(out),
                    "GIT_DIR": str(self.repo / ".git"), "GIT_PREFIX": ""}
        blocked = run(["sh", hook], self.repo, env={**hook_env, "GIT_INDEX_FILE": str(alt_index)})
        self.assertNotEqual(blocked.returncode, 0)
        self.assertNotIn(EMAIL, blocked.stdout + blocked.stderr)
        self.assertFalse(out.exists())
        res = run(["sh", hook], self.repo, env={**hook_env, "GIT_INDEX_FILE": str(self.repo / ".git" / "index")})
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(out.read_text().split(), [])
