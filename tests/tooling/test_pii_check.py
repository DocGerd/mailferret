"""scripts/pii_check.py: one case per review finding. Run: python3 -m unittest discover -s tests/tooling"""

from __future__ import annotations

import importlib.util
import unittest
import zlib

from support import AT, EMAIL, HOME, SCANNER, RepoCase, git

spec = importlib.util.spec_from_file_location("pii_check", SCANNER)
assert spec and spec.loader
pii = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pii)


def hits(line: str, code: bool = False) -> set[str]:
    return set(pii.scan_line(line, [], code))


VALUE = "s3cr3t" + "Value9"


class Patterns(unittest.TestCase):
    def test_secret_assignments(self) -> None:
        for line in (
            "DB_PASS" + "WORD=" + f'"{VALUE}"',
            "imap_pass" + "word = " + f'"{VALUE}"',
            '"client_' + 'secret": ' + f'"{VALUE}"',
            "pass" + "word: " + VALUE,
            "api_" + "key: " + VALUE,
            "export imap_" + "pass=" + VALUE,
            "SMTP_PASS" + "WORD=" + VALUE,
            "token = " + f"'{VALUE}'",
        ):
            with self.subTest(line=line):
                self.assertIn("secret-assignment", hits(line))

    def test_placeholders_and_code_expressions_pass(self) -> None:
        for line, code in (
            ("pass" + "word: <your-password>", False),
            ("pass" + "word = ${IMAP_PASSWORD}", False),
            ('"pass' + 'word": "string"', False),
            ("secret_" + "name = " + f'"{VALUE}"', False),
            ("by" + "pass = " + VALUE, False),
            ("pass" + "word = getpass()", True),
            ("secret: " + "SecretStr = Field()", True),
            ("tok" + "en: ${{ secrets.GITHUB_TOKEN }}", False),
        ):
            with self.subTest(line=line):
                self.assertNotIn("secret-assignment", hits(line, code))

    def test_token_and_key_formats(self) -> None:
        self.assertIn("token", hits("github_" + "pat_" + "A1" * 30))
        self.assertIn("token", hits("key=AI" + "za" + "B" * 35))
        self.assertIn("private-key", hits("-----BEGIN " + "PGP PRIVATE KEY BLOCK-----"))
        self.assertIn("private-key", hits("PuTTY-User-" + "Key-File-3: ssh-ed25519"))

    def test_home_paths_without_trailing_separator(self) -> None:
        for line in (f"cd {HOME}", f'"{HOME}"', "C:\\" + "Users\\jroe", "/var" + HOME + "/x", "/mnt/c/" + "Users/jroe"):
            with self.subTest(line=line):
                self.assertIn("home-path", hits(line))

    def test_generic_accounts_and_noreply_pass(self) -> None:
        for line in ("/" + "home/ubuntu/x", "/" + "home/runner/work", "/" + "home/<user>/", "C:\\" + "Users\\Public",
                     "noreply" + AT + "github.com", "1+x" + AT + "users.noreply.github.com"):
            with self.subTest(line=line):
                self.assertEqual(hits(line), set())


class Diffs(RepoCase):
    def test_plus_plus_line_is_content_not_header(self) -> None:
        self.write("notes.txt", f"a\n++ {EMAIL}\n++ b\n")
        git(self.repo, "add", "notes.txt")
        res = self.scan("--staged")
        self.assertEqual(res.returncode, 1)
        self.assertIn("notes.txt:2: email-address", res.stderr)
        self.assert_clean_output(res)

    def test_matching_file_name_is_redacted(self) -> None:
        self.write(f"{EMAIL}.txt", f"{EMAIL}\n")
        git(self.repo, "add", ".")
        res = self.scan("--staged")
        self.assertEqual(res.returncode, 1)
        self.assertIn("<path redacted #1>:0: email-address", res.stderr)
        self.assertIn("<path redacted #1>:1: email-address", res.stderr)
        self.assert_clean_output(res)

    def test_utf16_staged_and_full(self) -> None:
        self.write("u16.txt", ("hello\n" + EMAIL + "\n").encode("utf-16"))
        git(self.repo, "add", "u16.txt")
        self.assertEqual(self.scan("--staged").returncode, 1)
        git(self.repo, "commit", "-q", "-m", "u16")
        self.assertEqual(self.scan().returncode, 1)
        self.write("u16.txt", ("hello\n" + EMAIL + "\nmore\n" + HOME + "\n").encode("utf-16"))
        self.assertIn("home-path", self.scan("--unstaged").stderr)

    def test_nul_file_full_mode(self) -> None:
        stream = zlib.compress(f"BT ({HOME}/doc) Tj ET".encode())
        pdf = (b"%PDF-1.4\n\x00\x01\x02\n<< /Author (" + EMAIL.encode() + b") >>\nstream\n" + stream
               + b"\nendstream\n")
        self.write("fixture.pdf", pdf)
        git(self.repo, "add", "fixture.pdf")
        git(self.repo, "commit", "-q", "-m", "pdf")
        res = self.scan()
        self.assertEqual(res.returncode, 1)
        self.assertIn("fixture.pdf:0: email-address", res.stderr)
        self.assertIn("fixture.pdf:0: home-path", res.stderr)

    def test_force_added_ignored_file(self) -> None:
        self.write(".env", "IMAP_PASS" + "WORD=" + VALUE + "\n")
        self.assertEqual(self.scan("--include-untracked").returncode, 0)  # ignored: invisible without -f
        res = self.scan("--force-added", ".env")
        self.assertEqual(res.returncode, 1)
        self.assertIn(".env:1: secret-assignment", res.stderr)

    def test_message_file_scans_content_only(self) -> None:
        msg = self.write("q+" + HOME + "/COMMIT_EDITMSG", "fix: clean message\n", root=self.tmp)
        self.assertEqual(self.scan("--message-file", str(msg)).returncode, 0)
        msg.write_text(f"fix: mail {EMAIL}\n")
        res = self.scan("--message-file", str(msg))
        self.assertEqual(res.returncode, 1)
        self.assertIn("commit message #1:1: email-address", res.stderr)
        self.assert_clean_output(res)

    def test_commit_range_history_messages_identity(self) -> None:
        base = git(self.repo, "rev-parse", "HEAD").strip()
        self.write("a.txt", f"{EMAIL}\n")
        git(self.repo, "add", "a.txt")
        git(self.repo, "commit", "-q", "-m", "add")
        self.write("a.txt", "clean\n")
        git(self.repo, "commit", "-q", "-am", f"remove, see {HOME}")
        self.assertEqual(self.scan().returncode, 0)  # the final tree is clean
        res = self.scan("--commits", f"{base}..HEAD")
        self.assertEqual(res.returncode, 1)
        self.assertRegex(res.stderr, r"commit [0-9a-f]{12}:a.txt:1: email-address")
        self.assertRegex(res.stderr, r"commit [0-9a-f]{12} message:1: home-path")
        self.assertNotIn("author-email", res.stderr)
        self.assert_clean_output(res)

    def test_commit_range_flags_non_noreply_author(self) -> None:
        base = git(self.repo, "rev-parse", "HEAD").strip()
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "x", "--author", f"Jane <{EMAIL}>")
        res = self.scan("--commits", f"{base}..HEAD")
        self.assertIn("author-email", res.stderr)
        self.assertNotIn("committer-email", res.stderr)
        self.assert_clean_output(res)


if __name__ == "__main__":
    unittest.main()
