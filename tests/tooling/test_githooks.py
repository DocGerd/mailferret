""".githooks: the sh wrappers start Python, and commit-msg scans the message content, never its path."""

from __future__ import annotations

import shutil

from support import EMAIL, HOME, REPO, RepoCase, run


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
