"""The fixtures stay in their own repos when a hook in a linked worktree exports GIT_DIR and GIT_INDEX_FILE."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

from .support import ENV, REPO, RepoCase, git, run

INNER = """
import unittest
from pathlib import Path
from tests.tooling.support import RepoCase, git

class Inner(RepoCase):
    def test(self):
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "more")
        self.assertEqual(Path(git(self.repo, "rev-parse", "--absolute-git-dir").strip()), self.repo / ".git")

res = unittest.TextTestRunner(verbosity=0).run(unittest.defaultTestLoader.loadTestsFromTestCase(Inner))
raise SystemExit(not res.wasSuccessful())
"""


def snapshot(git_dir: Path) -> dict[str, str]:
    return {str(p.relative_to(git_dir)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(git_dir.rglob("*")) if p.is_file()}


class InheritedGitEnv(RepoCase):
    def test_fixtures_leave_the_hook_repo_untouched(self) -> None:
        git(self.repo, "worktree", "add", "-q", str(self.tmp / "wt"))
        sentinel = self.repo / ".git"
        wt_dir = sentinel / "worktrees" / "wt"
        before = snapshot(sentinel)
        hook_env = {**ENV, "GIT_DIR": str(wt_dir), "GIT_INDEX_FILE": str(wt_dir / "index"), "GIT_PREFIX": ""}
        res = run([sys.executable, "-c", INNER], REPO, env=hook_env)
        after = snapshot(sentinel)
        self.assertEqual(sorted(k for k in before.keys() | after.keys() if before.get(k) != after.get(k)), [])
        self.assertEqual(res.returncode, 0, res.stderr)
