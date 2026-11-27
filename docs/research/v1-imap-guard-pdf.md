# V1: IMAP guard hook, read caps, ESEARCH, PDF limits

Linux, CPython 3.11.18, 3.12.3, 3.13.18, 3.14.10; `imapclient==4.3.0`, `pytest==9.2.0`, `pypdf==7.2.0`. The appendix suite passes on each Python. Windows and macOS: not run, open for C4 (below). Evidence lines are `REPORT` output of the appendix.

Two earlier claims are REFUTED: `_command` is not the single choke point, and the pre-STARTTLS probe reads the wrong buffer on 3.14. See "Contradictions" and "Follow-up design edits (issue #7)": D1, D2 and C4 must not start from the `_command` hook.

## Verdicts

| # | Claim | Verdict | Observed |
|---|---|---|---|
| 1 | `_command` is the single choke point | REFUTED | `search`, `sort`, `thread`, `append`, `multiappend` use `_new_tag()` + `send()`; a `_command`-only guard missed `UID SEARCH/SORT/THREAD` and let `APPEND` out |
| 1a | Guard `_new_tag` and every `send` | VERIFIED | Verbs seen equal wire verbs on all four Pythons. 19 mutations (rw `SELECT`, `STORE` variants, `EXPUNGE`, `APPEND`, `CREATE`, `DELETE`, `RENAME`, `SUBSCRIBE`, `COPY`, `MOVE`, raw `STORE`, `IDLE`, `BODY[]`/`RFC822`/`RFC822.TEXT` fetches) raise before any byte is sent; `BODY.PEEK[]`, `RFC822.HEADER`, `RFC822.SIZE` pass. The FETCH check is a denylist here; A§6's allowlist is D2's |
| 1b | Un-armed `send` fails closed | VERIFIED | The armed line is vetted before any byte is written and may not contain a line break before its closing CRLF. It must end in CRLF, except SEARCH, SORT and THREAD: imapclient's `_raw_command` sends their line unterminated and the CRLF separately, so only they may announce a literal or leave the line open. A line ending in `{n}` or `{n+}` counts as an announcement whatever precedes it (`({n}` and `Date{n}` included). An unterminated or literal-bearing FETCH is refused (probes: `UID FETCH 1 (FLAGS` then ` BODY[])`; a literal inside `HEADER.FIELDS` then `BODY[]`, spaced or not, sync and `{n+}`). `_new_tag` refuses to re-arm while a command is open, awaiting a continuation, in a literal, in AUTHENTICATE or in IDLE, so a re-armed line cannot complete a half-sent one. After the armed line only these `send`s are allowed: literal bytes of the announced length (sync only after this tag's `+` was read; `{n+}` at once), a space, a fragment without line breaks (SEARCH/SORT/THREAD), the closing CRLF, AUTHENTICATE replies (`fullmatch`), `DONE` (case-insensitive) in an active IDLE. A tagged completion closes the gate, so bytes after a refused sync literal or after AUTHENTICATE raise. Removing the gate, the line-break check, the CRLF-or-announcement check, the literal refusal (also the space-led-only regex), the re-arm refusal, the continuation gate, the tagged close or `fullmatch` each fails tests. The wire-level embedded-CRLF test proves the effect on 3.11 and 3.12 only (3.13+ imaplib rejects control characters itself); a stub-based test runs the mixin's own check on every minor |
| 2 | `fetch`, `noop`, `idle`, `expunge` use `_command`; `UID` is `args[0]` | VERIFIED | `_command` logged `UID FETCH`, `NOOP`, `IDLE`, `EXPUNGE` |
| 3 | Guard runs before imaplib's state check | PARTLY | `imaplib.uid()` checks state first (`imaplib.error`). Both fail closed; tests accept either |
| 4 | `DONE` bypasses `_command` | VERIFIED | Wire showed `IDLE`, `DONE`; `_command` never saw `DONE` |
| 5 | Implicit TLS needs the mixin on `IMAP4_TLS` | VERIFIED | `IMAP4_TLS` is not an `IMAP4WithTimeout`; a plain-class TLS branch sent `CREATE`; a non-branching override with `ssl=True` hangs to `TimeoutError`; `GuardedTLS` blocked `CREATE`/`APPEND` |
| 6 | `_create_IMAP4` shape | VERIFIED | Branch on `self.ssl`, refuse `self.stream`, pass `connect_timeout`. Runs inside `__init__`: class-level mixin defaults. Do not name a helper `_log` |
| 7 | `read(size)` override caps literals | VERIFIED | Over-cap literal aborts before any literal byte is read; a 64 MiB literal was not pulled |
| 8 | Per-command caps | VERIFIED | Three 800-byte literals under a 1000-byte literal cap and 2000-byte total abort on the third. Caps are set per command (one-shot `next_caps`, consumed in `_new_tag`, default otherwise); the counter resets in `_new_tag` |
| 9 | `_MAXLINE` caps lines | VERIFIED, wording wrong | `imaplib.IMAP4.error` ("got more than"), not `abort`, on 3.11-3.14; read at call time. Not "before buffering": on 3.14 the overshoot past the cap varied between runs (tens of KB at cap 5,000, up to about 110 KB at the default); the test asserts cap + 256 KiB. Not measurable on 3.11-3.13 (buffer inside `file`). Process-global |
| 10 | `file.peek(1)` sees pre-STARTTLS bytes | REFUTED on 3.14; VERIFIED on 3.11-3.13 | 3.14 reads into `self._readbuf`; the prototype missed the injection and hung |
| 11 | `peek(1)` on an empty buffer does not block | VERIFIED | `(b"", 0.0 s)` with `settimeout(0.0)`; later `readline` works |
| 11a | `MSG_PEEK` kernel probe | VERIFIED (unit) | False when empty, True with kernel-only bytes, timeout restored. Bytes arriving after the probe are not detectable; the handshake then fails with `ssl.SSLError` and no `LOGIN` is sent |
| 12 | `_command_complete("STARTTLS", tag)` runs before the wrap | VERIFIED | Guard abort: no handshake, no `LOGIN`. Clean STARTTLS passes; capabilities re-read over TLS |
| 13 | `starttls()` drops buffered bytes | REFUTED on 3.14 | Dropped on 3.11-3.13; kept in `_readbuf` and parsed inside the TLS session on 3.14 (the injected `XINJECTED` line was read as a CAPABILITY response) |
| 14 | imaplib state errors | VERIFIED | `EXAMINE`/`LIST` before login, `UID`/`UNSELECT` in AUTH raise `imaplib.error`. Raw-path `SEARCH`/`SORT`/`THREAD` do no state check. `ID`, `UNSELECT` are in `imaplib.Commands` |
| 15 | imapclient has no ESEARCH | VERIFIED | Not in the source; public `search(["RETURN", ...])` returns `[]`; the private `_raw_command_untagged(..., response_name="ESEARCH")` returns data |
| 16 | `select_folder(readonly=True)` / `login` verbs | VERIFIED | `EXAMINE`, `LOGIN` (`readonly=False`: `SELECT`, blocked) |
| 17 | Linux `RLIMIT_AS` in the worker | VERIFIED (not re-run) | 512 MiB: `import pypdf` fine; 64 MiB allocations hit `MemoryError` after 7; uncapped 2.5 GiB succeeded; parent survived |
| 18 | Windows job object; macOS | OPEN | Owner C4, windows and macos CI runners (below) |
| 19 | imapclient debug logging (T-03/T-21) | VERIFIED | Stock, root at DEBUG: `imapclient.imaplib` logs every server line (`< ...`), `imapclient.imapclient` logs commands and `Logged in as`. `LOGIN` is redacted (password never appeared); AUTHENTICATE logging not exercised. `debug` forced to 0 leaves `imapclient.imapclient` and `imapclient.util`. `imapclient.util` warns with the raw bytes of an 8-bit NO text and of `str(Address)` (the corpus stringifies one on purpose); a BAD text (imaplib raises first) and an 8-bit folder name logged nothing here. A WARNING pin with `propagate = False` has no handler, so `logging.lastResort` writes it to stderr. A pin at `CRITICAL + 1` with `propagate = False` and a `NullHandler` gives no `imapclient*` record and empty stderr. `disabled = True` on the parent does not cover `imapclient.util` |
| 20 | A `str` secret passed to `login` stays out of exceptions (T-02) | REFUTED for non-ASCII | imaplib's ASCII encoding raises `UnicodeEncodeError` before any byte is sent, with the secret in `args` and `object` (quoted on 3.11, bare on 3.14) and the traceback. With an `isascii()` check, `plain_login` sends UTF-8 through the gate; without AUTH=PLAIN a typed error raised outside any `except` leaves no secret in args, repr, str, traceback, `__context__` or captured output |
| 21 | The logger pin keeps server text out of output (T-03/T-21) | REFUTED for exception text | The `select_folder` NO text `café-Needle rejected` is in the raised `IMAPClientError`; a handler that logs `str(exc)` or a traceback leaks it past the logger pin. A fixed-code mapper keeps it out of every log record, stdout/stderr and the surfaced string, for NO and BAD |

Wire survey (3.14): `CAPABILITY, LOGIN, CAPABILITY, CAPABILITY, NAMESPACE, LIST, STATUS, EXAMINE, UID SEARCH, UID SORT, UID THREAD, UID FETCH, NOOP, ID, UNSELECT, LOGOUT`; the `send` guard saw 16, `_command` 13.

### pypdf 7.2.0

- `pypdf.Configuration` is frozen; `overwrite_configuration(**kw)`, `apply_configuration(...)`, `get_configuration()` exist. Fields: `dataclasses.fields(Configuration)`.
- Defaults above `pdf_stream_bytes` (32 MiB): `maximum_declared_stream_length`, `zlib_/lzw_/run_length_/jbig2_/brotli_maximum_output_length`, `array_based_stream_maximum_output_length`, `image_maximum_buffer_size` (75 MB each); `stream_decoding_work_maximum_length`, `xfa_decoding_work_maximum_length` (300 MB); `embedded_files_maximum_output_length` (250 MB). `page_tree_maximum_entries` 100k, `_depth` 100, `_page_entries` 2M.
- `PdfReader(stream, strict=False, password=None, *, root_object_recovery_limit, xref_stream_maximum_entries, xref_rebuild_maximum_entries)`. No page-count or text cap: the worker loops pages.
- A 200 MB zlib stream in a complete page (about 190 KB file): `extract_text()` and `get_contents()` raised `LimitReachedError` at default and lowered caps; a control page returned text. Without `/Resources` the page returned `""` silently, so bomb fixtures need a complete page. Only the zlib path ran; the cyclic page tree and 100,000-page bombs did not (open for C4).

## Decisions for A§10

1. Item 1: one guard mixin for `IMAP4WithTimeout` and `IMAP4_TLS`, from an `IMAPClient._create_IMAP4` override (row 6).
   - Commands: `_new_tag` arms; the first `send` must parse as `tag [UID] VERB` and is vetted (allowlist, FETCH items) before any byte is written. It must end in CRLF; only SEARCH/SORT/THREAD may be unterminated or announce a literal (`{n}` or `{n+}` ending the line, whatever precedes it). `_new_tag` refuses to re-arm while a command is in flight (open, await, literal, auth, idle). Later `send`s must match a mid-command shape (row 1b), else `ReadOnlyViolation`. Literal bytes wait for this tag's `+`; a tagged completion closes the gate. `_command` is overridden for a clearer error, not as the guarantee.
   - A failed vet leaves the gate armed, so a later `send` is parsed as a command line (fails closed). D2 resets the gate on abort and reconnect. D2 tests: a bare tagged line through `send` raises; a line break in the armed line raises; the fragments `UID FETCH 1 (FLAGS` + ` BODY[])` and a literal in a FETCH raise, including the unspaced `({n}` and `({n+}` forms; `_new_tag` mid-command raises; literal bytes before `+` or after a tagged BAD raise; bytes after a completed AUTHENTICATE raise.
   - Reads: `read(size)` aborts over the active literal cap and the per-command total; the caller sets both per command from the fetched item's L-nn (L-05 header, L-02 part, L-08 attachment, L-01 full fallback), default the smallest, reset in `_new_tag`. Line cap: set `imaplib._MAXLINE` from L-20 once at startup (process-global; L-20's 1 MiB exceeds the stdlib 1,000,000). Line overflow raises `error`: treat `error` and `abort` as fatal, discard the session.
   - STARTTLS: override `_command_complete`; probe by feature, not version: `_readbuf` if the attribute exists, else `file.peek(1)`; then `MSG_PEEK`; restore the socket timeout.
   - Logging: `debug` is a property that reads 0 and ignores sets; the `imapclient` logger is set to `CRITICAL + 1` with `propagate = False` and a `NullHandler` (WARNING is not enough, row 19). Both are required. Pass only `str` to `login`; never stringify an `Address` (format addresses in `content/`). Never log or format `imaplib`/`imapclient` exception messages or tracebacks (they carry server text, folder names and NO/BAD texts); map exceptions to fixed error codes. Test: a corpus with an 8-bit NO and BAD text, folder name and ENVELOPE address, at root DEBUG, records no `imapclient*` LogRecord (via a record factory: a root handler never sees a non-propagating logger) and leaves captured stderr (`capfd`) empty; it fails with the WARNING pin. A second test on the same 8-bit fake asserts the 8-bit NO and BAD text (`café-Needle rejected`) appears in no log record, no captured stdout/stderr and no surfaced error string of the error-mapping helper.
   - Credentials: check `isascii()` on username and secret before `LOGIN` (otherwise imaplib raises `UnicodeEncodeError` carrying the secret). A non-ASCII secret goes to AUTHENTICATE PLAIN (UTF-8, RFC 4616) when advertised, else a typed credential error with fixed text, raised outside any `except` so no `__context__` holds the original. Test on the `imap/` login path: the secret is absent from the exception's args, repr, str and traceback and from captured output.
   - Private API: pin imapclient; run the wire-survey, send-gate and STARTTLS tests on every supported minor. The wire-level embedded-CRLF test is meaningful on 3.11/3.12 only; keep both in the D2 CI matrix, and keep the stub-based test of the mixin's own check, which holds on every minor.
2. Item 2: ESEARCH not exposed or used; plain `UID SEARCH`. L-20 is never raised to fit a SEARCH response; candidates are bounded by windowed UID ranges or the overflow maps to `limit_exceeded`.
3. Item 10:
   - Linux: `RLIMIT_AS` in the worker (row 17); `RLIMIT_CPU` not exercised.
   - Windows job object (`JOBOBJECT_EXTENDED_LIMIT_INFORMATION`, `JOB_OBJECT_LIMIT_PROCESS_MEMORY`) and macOS `RLIMIT_AS` behaviour: not researched or run; open for C4 with windows and macos CI runners. A§10.10 fallback stands meanwhile; T-06's "asserted on Linux and Windows" is unverified.
   - All OSes: pypdf caps from `limits.py` (fields above), page and char caps in the worker, `LimitReachedError` maps to `limit_exceeded`.
4. Vetting: imapclient 4.3.0 and pypdf 7.2.0 are BSD-3; advisories and maintenance are out of scope.

## Contradictions

- A§10.1, A§6, T-10: the hook is `_new_tag` plus every `send`, not `_command`. The T-10 recording-fake-server proof compares the wire with the allowlist, not the guard's log.
- A§2.2, T-07: "`starttls()` drops such bytes silently" holds on 3.11-3.13 only. Suggested: "`starttls()` neither detects nor reliably discards them; a guarded `_command_complete` checks the read buffer."
- T-08: "raises before it is buffered" is wrong for lines. Suggested: "lines are bounded at L-20 plus a bounded overshoot (asserted at 256 KiB on 3.14) on read." The cap is process-global (`imaplib._MAXLINE`); L-20 exceeds the stdlib default.
- T-08, A§4, A§3 step 6: one fixed L-02 literal cap breaks the L-08 and L-01 fetches; the cap is per command (decision 1).
- T-08, L-nn: the per-command response total has no row in SECURITY §5; a batch of L-25 UIDs times L-02 is far above L-19. Needs a new L-nn with a `[limits]` key.
- L-15, L-20: without ESEARCH, `UID SEARCH` returns every match on one line (about 8 bytes per UID); above roughly 130k matches it exceeds L-20 and the session aborts.
- T-03, T-21: "imaplib's debug output is never enabled" is not enough. imapclient sets `debug = 5` after construction (a constructor-time override cannot zero it), and its loggers carry server lines, search criteria and the username. `imapclient.util` also warns with raw 8-bit server bytes, so a WARNING pin leaks to stderr. Needs both controls of decision 1. Exception messages also carry server text (row 21): D2 maps them to fixed codes and never logs them.
- T-02: its verification covers exceptions raised from `auth/`; `login` in `imap/` raises `UnicodeEncodeError` with the secret in `args` (row 20). Extend the test to the `imap/` login path.
- T-10: "un-armed sends are refused" must be a shape gate (decision 1): imapclient arms SEARCH/SORT/THREAD with an unterminated line, so "every armed line ends in CRLF" is false for them. Literal bytes are gated on the `+` continuation.
- T-06: "set pypdf limits from limits.py" must name the fields (above) and derive `page_tree_maximum_*` from L-09.

## Follow-up design edits (issue #7)

Not edited here. This table is the single list issue #7 points to: apply every row. Each blocks its owner.

| Edit | Owner |
|---|---|
| A§10.1, A§6, T-10: hook is `_new_tag` + `send` with the fail-closed gate; allowlist FETCH items; D2 resets the gate on abort and reconnect | SECURITY follow-up (text), D2 (code) |
| T-10, R2: armed line ends in CRLF (SEARCH/SORT/THREAD may be unterminated); literal announcements refused except in SEARCH/SORT/THREAD; `_new_tag` refuses to re-arm mid-command; tests for the `UID FETCH 1 (FLAGS` + ` BODY[])` and literal-in-FETCH probes, spaced and unspaced (`({n}`), sync and `{n+}`, and for `_new_tag` mid-command | D2 |
| T-10, R1: sync literal bytes only after this tag's `+` (`{n+}` at once); AUTHENTICATE replies match with `fullmatch`; the gate closes on tagged completion; `{n+}` bytes only if LITERAL+ was advertised; tests for bytes before `+`, after a tagged BAD, and after AUTHENTICATE | D2 |
| T-10 tests: the line-break check is exercised on every minor by a stub-based test; the wire-level CRLF test counts on 3.11/3.12 only, so the CI matrix keeps both | D2 |
| A§2.2, T-07: reword buffered-bytes sentence; probe by feature (`_readbuf`, then `file.peek`, then `MSG_PEEK`); STARTTLS injection test on every supported minor in CI | SECURITY follow-up, D1 |
| T-08, A§4, A§3 step 6: per-command literal cap from the fetched item's L-nn (L-05/L-02/L-08/L-01), reset in `_new_tag` | SECURITY follow-up, D2 |
| T-08: wording "bounded at L-20 plus a bounded overshoot"; `imaplib._MAXLINE` set once, process-global | SECURITY follow-up, D2 |
| New L-nn: per-command response total, with a `[limits]` key and ceiling | SECURITY follow-up (before D2) |
| L-15, L-20: windowed UID ranges for SEARCH or `limit_exceeded`; L-20 never raised | SECURITY follow-up, D2 |
| T-03, T-21: `debug` forced to 0; `imapclient` logger at `CRITICAL + 1`, `propagate = False`, `NullHandler`; `login` gets `str` only; never stringify `Address` (format in `content/`); corpus test with 8-bit NO/BAD, folder and ENVELOPE values asserting no record and empty `capfd` stderr; D2 never logs or formats `imaplib`/`imapclient` exception messages or tracebacks and maps them to fixed error codes, with a corpus assertion that an 8-bit NO text is in no record, no output and no surfaced error string | SECURITY follow-up, D2, `content/` tasks |
| T-02, T-03: `isascii()` check on username and secret before `LOGIN`; non-ASCII secret to AUTHENTICATE PLAIN (UTF-8) or a typed credential error raised outside any `except`; extend the T-02 test to the `imap/` login path with a non-ASCII secret (absent from args, repr, str, traceback, output) | D2, `auth/` |
| T-06, L-09, L-10: pypdf fields capped at `pdf_stream_bytes`; `page_tree_*` derived from L-09; cyclic-tree and 100,000-page fixtures | SECURITY follow-up, C4 |
| T-06, A§10.10: Windows job object and macOS `RLIMIT_AS`, researched and run on windows and macos CI runners; add a STATUS open item | C4 |

## Appendix: throwaway prototype (not for `tests/`)

Run, per Python, from outside the repository (needs `openssl` for a throwaway certificate; fakes listen on 127.0.0.1 only):
`UV_PYTHON=<ver> uv run --no-project --with imapclient==4.3.0 --with pytest==9.2.0 python -I -m pytest -q -s test_v1_hook.py`.
The pypdf script runs with `--with pypdf==7.2.0`.

### test_v1_hook.py

~~~python
# test_v1_hook.py  (throwaway; 127.0.0.1 fakes only)
import base64
import imaplib
import logging
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import traceback

import pytest
from imapclient import IMAPClient
from imapclient.exceptions import IMAPClientAbortError, IMAPClientError, LoginError
from imapclient.imap4 import IMAP4WithTimeout
from imapclient.tls import IMAP4_TLS

ALLOWED = {"CAPABILITY", "NOOP", "LOGOUT", "STARTTLS", "LOGIN", "AUTHENTICATE", "ID",
           "NAMESPACE", "LIST", "LSUB", "STATUS", "EXAMINE", "CLOSE", "UNSELECT",
           "SEARCH", "FETCH", "SORT", "THREAD", "UID"}
UID_OK = {"SEARCH", "FETCH", "SORT", "THREAD"}
SEEN_ITEMS = re.compile(rb"BODY\[|BINARY\[|RFC822(?!\.(?:HEADER|SIZE)\b)", re.I)
CMD = re.compile(rb"^(\S+) (?:(UID) )?([A-Za-z]+)")
MAX_LITERAL, MAX_RESPONSE = 1000, 2000
ANN_END = re.compile(rb"\{(\d+)(\+?)\}\r\n$")
ANN_START = re.compile(rb"^ ?\{(\d+)(\+?)\}\r\n")  # imapclient sends " {n}\r\n"
AUTH_REPLY = re.compile(rb"[A-Za-z0-9+/=]*|\*|\r\n")  # fullmatch
IN_FLIGHT = {"open", "await", "literal", "auth", "idle"}
RAW_VERBS = {"SEARCH", "SORT", "THREAD"}  # imapclient `_raw_command`: unterminated line, literals
MUTATING = {"SELECT", "STORE", "EXPUNGE", "APPEND", "CREATE", "DELETE", "RENAME",
            "COPY", "MOVE", "SUBSCRIBE", "UNSUBSCRIBE", "UID STORE", "UID COPY",
            "UID MOVE", "UID EXPUNGE"}


def report(key, value):
    print(f"REPORT {key}: {value}")


class ReadOnlyViolation(Exception):
    pass


class CredentialError(Exception):
    """Fixed text; never carries the credential."""


def login_checked(c, user, secret):
    if user.isascii() and secret.isascii():
        return c.login(user, secret)
    if b"AUTH=PLAIN" in c.capabilities():
        return c.plain_login(user, secret)  # PLAIN carries UTF-8 (RFC 4616)
    raise CredentialError("non_ascii_credential")  # outside any `except`: no __context__


def error_code(exc):
    """Fixed codes only: never str(exc), repr(exc), exc.args or a traceback."""
    if isinstance(exc, ReadOnlyViolation):
        return "read_only_violation"
    if isinstance(exc, CredentialError):
        return "credential_error"
    if isinstance(exc, (imaplib.IMAP4.abort, IMAPClientAbortError)):
        return "session_aborted"
    if isinstance(exc, LoginError):
        return "login_failed"
    if isinstance(exc, (IMAPClientError, imaplib.IMAP4.error)):
        return "imap_error"
    return "internal_error"


class GuardMixin:
    strict = True        # False: record only
    guard_send = True    # False: the prototype's `_command`-only guard
    allow_idle = False
    vet_in_command = True
    _state = "closed"    # armed | open | await | literal | auth | idle | closed
    _tag = b""
    _lit_left = 0
    _budget = 0
    _lit_cap = MAX_LITERAL
    _total_cap = MAX_RESPONSE
    next_caps = None     # one-shot (literal, total) caps for the next command

    @property
    def debug(self):     # imapclient sets 5 after construction; stay at 0
        return 0

    @debug.setter
    def debug(self, value):
        pass

    def _rec(self, name, item):
        self.__dict__.setdefault(name, []).append(item)

    def _vet(self, verb, sub):
        if not self.strict:
            return
        ok = verb in ALLOWED and (verb != "UID" or sub in UID_OK)
        if verb == "IDLE" and self.allow_idle:
            ok = True
        if not ok:
            raise ReadOnlyViolation(f"{verb} {sub or ''}".strip())

    def _command(self, name, *args):
        n = name.upper()
        sub = str(args[0]).upper() if n == "UID" and args else None
        self._rec("cmd_seen", f"{n} {sub}" if sub else n)
        if self.vet_in_command:
            self._vet(n, sub)
        return super()._command(name, *args)

    def _new_tag(self):
        if self.strict and self._state in IN_FLIGHT:
            raise ReadOnlyViolation(f"new command while {self._state}")
        self._state = "armed"
        self._lit_left = 0
        self._budget = 0
        self._lit_cap, self._total_cap = self.next_caps or (MAX_LITERAL, MAX_RESPONSE)
        self.next_caps = None
        self._tag = super()._new_tag()
        return self._tag

    def _announce(self, m):
        # `{n}`: bytes only after this tag's `+`; `{n+}` (LITERAL+): at once
        self._lit_left = int(m.group(1))
        self._state = "literal" if m.group(2) else "await"

    def _after_line(self, data, verb):
        m = ANN_END.search(data)
        if verb in RAW_VERBS:
            if m:
                self._announce(m)
            else:
                self._state = "closed" if data.endswith(b"\r\n") else "open"
        elif m or not data.endswith(b"\r\n"):
            raise ReadOnlyViolation(f"{verb}: literal or unterminated line")
        else:
            self._state = {"AUTHENTICATE": "auth", "IDLE": "idle"}.get(verb, "closed")

    def _check_unarmed(self, data):
        """Fail closed: only the shapes imaplib/imapclient send mid-command."""
        st = self._state
        if st == "idle" and data.upper() == b"DONE\r\n" and self.allow_idle:
            self._state = "closed"
        elif st == "auth" and AUTH_REPLY.fullmatch(data):
            return
        elif st == "literal":
            if len(data) != self._lit_left:
                raise ReadOnlyViolation("literal length mismatch")
            self._state = "open"
        elif st == "open":
            m = ANN_START.match(data)
            if m and m.group(2):  # LITERAL+: announcement and bytes in one send
                if len(data) - m.end() != int(m.group(1)):
                    raise ReadOnlyViolation("literal length mismatch")
            elif m:
                if m.end() != len(data):
                    raise ReadOnlyViolation("bytes after literal announcement")
                self._announce(m)
            elif data == b"\r\n":
                self._state = "closed"
            elif b"\r" in data or b"\n" in data:
                raise ReadOnlyViolation("line break inside a command fragment")
        else:
            raise ReadOnlyViolation("send outside a command in flight")

    def send(self, data):
        if self.guard_send:
            if self._state == "armed":
                m = CMD.match(data)
                if not m:
                    raise ReadOnlyViolation("unparseable command line")
                body = data[:-2] if data.endswith(b"\r\n") else data
                if b"\r" in body or b"\n" in body:
                    raise ReadOnlyViolation("line break inside the command line")
                verb = m.group(3).decode().upper()
                if m.group(2):
                    self._rec("send_seen", f"UID {verb}")
                    self._vet("UID", verb)
                else:
                    self._rec("send_seen", verb)
                    self._vet(verb, None)
                if self.strict and verb == "FETCH" and SEEN_ITEMS.search(data):
                    raise ReadOnlyViolation("FETCH item sets \\Seen")
                self._after_line(data, verb)
            else:
                if self.strict:
                    self._check_unarmed(data)
                if data.upper() == b"DONE\r\n":
                    self._rec("send_seen", "DONE")
        return super().send(data)

    def _charge(self, n):
        self._budget += n
        if self._budget > self._total_cap:
            raise self.abort(f"response over {self._total_cap}")

    def read(self, size):
        if self.strict and size > self._lit_cap:
            raise self.abort(f"literal {size} over cap")
        self._charge(size)
        return super().read(size)

    def readline(self):
        line = super().readline()
        self._charge(len(line))
        if self._tag and line.startswith(self._tag + b" "):
            self._state = "closed"  # tagged completion ends the command
        elif self._state == "await" and line.startswith(b"+"):
            self._state = "literal"
        return line

    def _readbuf_pending(self):
        rb = getattr(self, "_readbuf", None)
        if rb is not None:  # 3.14+: imaplib buffers itself
            return any(rb)
        return bool(self.file.peek(1))

    def _pending(self):
        t = self.sock.gettimeout()
        self.sock.settimeout(0.0)
        try:
            if self._readbuf_pending():
                return True
            return bool(self.sock.recv(1, socket.MSG_PEEK))
        except (BlockingIOError, ssl.SSLWantReadError, TimeoutError):
            return False
        finally:
            self.sock.settimeout(t)

    def _command_complete(self, name, tag):
        r = super()._command_complete(name, tag)
        if name.upper() == "STARTTLS" and self._pending():
            raise self.abort("bytes buffered before TLS")
        return r


class GuardedPlain(GuardMixin, IMAP4WithTimeout):
    pass


class GuardedTLS(GuardMixin, IMAP4_TLS):
    pass


class CmdOnlyPlain(GuardedPlain):
    guard_send = False


class CmdOnlyTLS(GuardedTLS):
    guard_send = False


class SendOnlyPlain(GuardedPlain):
    vet_in_command = False


class RecPlain(GuardedPlain):
    strict = False


class IdlePlain(GuardedPlain):
    allow_idle = True


class CmdOnlyIdlePlain(CmdOnlyPlain):
    allow_idle = True


def client_class(plain_cls, tls_cls):
    class C(IMAPClient):
        def _create_IMAP4(self):
            if self.stream:
                raise ValueError("stream mode refused")
            ct = getattr(self._timeout, "connect", None)
            if self.ssl:
                return tls_cls(self.host, self.port, self.ssl_context, ct)
            return plain_cls(self.host, self.port, ct)
    return C


class Fake:
    def __init__(self, mode="normal", ctx=None, implicit=False, size=5000, literal_plus=False,
                 eightbit=False, auth_plain=False):
        self.mode, self.ctx, self.implicit, self.size = mode, ctx, implicit, size
        self.literal_plus = literal_plus
        self.eightbit = eightbit
        self.auth_plain = auth_plain
        self.auth_replies = []
        self.wire, self.events = [], []
        self.sent = threading.Event()
        self.srv = socket.create_server(("127.0.0.1", 0))
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self._guarded_run, daemon=True).start()

    def _guarded_run(self):
        try:
            self.run()
        except (OSError, ssl.SSLError) as e:
            self.events.append(f"server error {type(e).__name__}")

    def caps(self, tls):
        base = "IMAP4rev1 IDLE ID UNSELECT NAMESPACE MOVE SORT THREAD=REFERENCES"
        base += " LITERAL+" if self.literal_plus else ""
        base += " AUTH=PLAIN" if self.auth_plain else ""
        return base if tls or self.implicit else base + " STARTTLS"

    def run(self):
        c, _ = self.srv.accept()
        c.settimeout(15)
        tls = self.implicit
        if tls:
            c = self.ctx.wrap_socket(c, server_side=True)
        f = c.makefile("rb")
        c.sendall(b"* OK ready\r\n")
        while True:
            line = f.readline()
            if not line:
                break
            text = line.decode(errors="replace").rstrip("\r\n")
            refused = False
            while m := re.search(r"\{(\d+)\+?\}$", text):
                if self.mode == "nolit" and not text.endswith("+}"):
                    c.sendall(f"{text.split(' ')[0]} BAD no literals\r\n".encode())
                    refused = True
                    break
                if not text.endswith("+}"):
                    c.sendall(b"+ go\r\n")
                f.read(int(m[1]))
                text += "<lit>" + f.readline().decode(errors="replace").rstrip("\r\n")
            if refused:
                continue
            tag, _, rest = text.partition(" ")
            parts = rest.split(" ")
            verb = parts[0].upper()
            sub = parts[1].upper() if verb == "UID" and len(parts) > 1 else None
            self.wire.append(f"UID {sub}" if sub else verb)
            if self.eightbit and ("Missing" in rest or "XBAD" in rest):
                word = "NO" if "Missing" in rest else "BAD"
                c.sendall(f"{tag} {word} caf\xe9-Needle rejected\r\n".encode("latin-1"))
                continue
            if verb == "CAPABILITY":
                c.sendall(f"* CAPABILITY {self.caps(tls)}\r\n".encode())
            elif verb == "STARTTLS":
                payload = f"{tag} OK go\r\n".encode()
                if self.mode == "extra":
                    payload += b"* CAPABILITY IMAP4rev1 AUTH=PLAIN XINJECTED\r\n"
                c.sendall(payload)
                if self.mode == "late":
                    time.sleep(0.5)
                    c.sendall(b"* CAPABILITY IMAP4rev1 XLATE\r\n")
                if self.ctx is None:
                    f.read()
                    break
                c = self.ctx.wrap_socket(c, server_side=True)
                f = c.makefile("rb")
                tls = True
                self.events.append("handshake")
                continue
            elif verb in ("EXAMINE", "SELECT"):
                c.sendall(b"* 3 EXISTS\r\n* OK [UIDVALIDITY 1] ok\r\n")
            elif sub == "SEARCH":
                if "RETURN" in rest:
                    c.sendall(b'* ESEARCH (TAG "x") UID COUNT 3 MIN 1 MAX 3\r\n')
                else:
                    c.sendall(b"* SEARCH 1 2 3\r\n")
            elif sub == "SORT":
                c.sendall(b"* SORT 3 2 1\r\n")
            elif sub == "THREAD":
                c.sendall(b"* THREAD (1 2)(3)\r\n")
            elif sub == "FETCH":
                if self.mode == "big":
                    c.sendall(b"* 1 FETCH (UID 1 BODY[] {%d}\r\n" % self.size)
                    c.sendall(b"x" * self.size + b")\r\n")
                elif self.mode == "huge":
                    c.sendall(b"* 1 FETCH (UID 1 BODY[] {67108864}\r\n")
                    c.sendall(b"x" * 67108864)
                    self.sent.set()
                elif self.mode == "trio":
                    for i in (1, 2, 3):
                        c.sendall(b"* %d FETCH (UID %d BODY[] {800}\r\n" % (i, i))
                        c.sendall(b"x" * 800 + b")\r\n")
                elif "ENVELOPE" in rest:
                    c.sendall('* 1 FETCH (UID 1 ENVELOPE (NIL "caf\xe9-Needle" (("caf\xe9-Needle" NIL '
                              '"user" "example.com")) NIL NIL NIL NIL NIL NIL NIL))\r\n'.encode("latin-1"))
                else:
                    c.sendall(b"* 1 FETCH (UID 1 FLAGS (\\Seen))\r\n")
            elif verb == "LIST":
                c.sendall(b'* LIST () "/" INBOX\r\n')
                if self.eightbit:
                    c.sendall('* LIST () "/" "caf\xe9-Needle"\r\n'.encode("latin-1"))
            elif verb == "STATUS":
                c.sendall(b"* STATUS INBOX (MESSAGES 3)\r\n")
            elif verb == "NAMESPACE":
                c.sendall(b'* NAMESPACE (("" "/")) NIL NIL\r\n')
            elif verb == "ID":
                c.sendall(b"* ID NIL\r\n")
            elif verb == "NOOP" and self.mode == "longline":
                for _ in range(40):
                    c.sendall(b"x" * 50_000)
                self.sent.set()
                f.read()
                break
            elif verb == "AUTHENTICATE":
                c.sendall(b"+ \r\n")
                self.auth_replies.append(f.readline())
            elif verb == "IDLE":
                c.sendall(b"+ idling\r\n")
                if f.readline().strip().upper() == b"DONE":
                    self.wire.append("DONE")
            elif verb == "LOGOUT":
                c.sendall(b"* BYE bye\r\n")
            c.sendall(f"{tag} OK done\r\n".encode())
            if verb == "LOGOUT":
                break
        c.close()


def connect(mode="normal", plain=GuardedPlain, tls_cls=GuardedTLS, **kw):
    s = Fake(mode, **kw)
    return s, client_class(plain, tls_cls)("127.0.0.1", port=s.port, ssl=False, timeout=5)


def opened(mode="normal", plain=GuardedPlain, **kw):
    s, c = connect(mode, plain, **kw)
    c.login("user@example.com", "x")
    c.select_folder("INBOX", readonly=True)
    return s, c


@pytest.fixture(scope="module")
def certs():
    d = tempfile.mkdtemp(prefix="v1cert")
    crt, key = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                    "-out", crt, "-days", "2", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=IP:127.0.0.1"],
                   check=True, capture_output=True, timeout=60)
    srv = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv.load_cert_chain(crt, key)
    cli = ssl.create_default_context(cafile=crt)
    return srv, cli


def test_versions():
    report("python", sys.version.split()[0])
    import imapclient
    report("imapclient", imapclient.__version__)
    report("_MAXLINE", imaplib._MAXLINE)


def test_choke_point_survey():
    s, c = connect(plain=RecPlain)
    c.login("user@example.com", "x")
    c.capabilities()
    c.namespace()
    c.list_folders()
    c.folder_status("INBOX")
    c.select_folder("INBOX", readonly=True)
    c.search(["ALL"])
    c.sort(["ARRIVAL"], ["ALL"])
    c.thread("REFERENCES", ["ALL"])
    c.fetch([1], ["UID", "FLAGS"])
    c.noop()
    c.id_()
    c.unselect_folder()
    c.logout()
    cmd, snd = c._imap.cmd_seen, c._imap.send_seen
    report("wire", s.wire)
    report("seen by _command", cmd)
    report("seen by new_tag+send", snd)
    report("on wire, missed by _command", [v for v in s.wire if v not in cmd])
    assert snd == s.wire
    assert cmd != s.wire
    assert {"UID SEARCH", "UID SORT", "UID THREAD"}.isdisjoint(cmd)


MUTATIONS = {
    "select rw": lambda c: c.select_folder("INBOX", readonly=False),
    "add_flags": lambda c: c.add_flags([1], [b"\\Seen"]),
    "set_flags": lambda c: c.set_flags([1], [b"\\Seen"]),
    "remove_flags": lambda c: c.remove_flags([1], [b"\\Seen"]),
    "delete_messages": lambda c: c.delete_messages([1]),
    "expunge": lambda c: c.expunge(),
    "uid expunge": lambda c: c.expunge([1]),
    "append": lambda c: c.append("INBOX", b"x"),
    "create": lambda c: c.create_folder("x"),
    "delete": lambda c: c.delete_folder("x"),
    "rename": lambda c: c.rename_folder("x", "y"),
    "subscribe": lambda c: c.subscribe_folder("x"),
    "copy": lambda c: c.copy([1], "x"),
    "move": lambda c: c.move([1], "x"),
    "raw store": lambda c: c._raw_command(b"STORE", [b"1", b"+FLAGS", b"(\\Seen)"]),
    "fetch BODY[]": lambda c: c.fetch([1], ["BODY[]"]),
    "fetch RFC822": lambda c: c.fetch([1], ["RFC822"]),
    "fetch RFC822.TEXT": lambda c: c.fetch([1], ["RFC822.TEXT"]),
    "idle": lambda c: c.idle(),
}


def test_guard_blocks_mutations_and_logs_wire():
    s, c = opened()
    for name, call in MUTATIONS.items():
        with pytest.raises(ReadOnlyViolation):
            call(c)
    c.fetch([1], ["BODY.PEEK[]", "RFC822.HEADER", "RFC822.SIZE"])
    c.logout()
    report("wire (guarded)", s.wire)
    assert MUTATING.isdisjoint(s.wire)
    assert s.wire[-2:] == ["UID FETCH", "LOGOUT"]


def test_command_only_guard_leaks():
    s, c = opened(plain=CmdOnlyPlain)
    leaked = {}
    for name in ("append", "move", "copy", "expunge", "add_flags"):
        try:
            MUTATIONS[name](c)
            leaked[name] = "reached wire"
        except ReadOnlyViolation:
            leaked[name] = "blocked"
        except Exception as e:  # noqa: BLE001
            leaked[name] = f"other {type(e).__name__}"
        time.sleep(0.05)
    report("command-only guard", leaked)
    report("wire (command-only)", s.wire)
    assert leaked["append"] == "reached wire" and "APPEND" in s.wire


def test_guard_runs_before_state_check():
    s, c = connect()
    with pytest.raises(ReadOnlyViolation):
        c._imap._command("STORE", "1", "+FLAGS", "(\\Seen)")
    with pytest.raises(imaplib.IMAP4.error, match="illegal in state"):
        c.delete_messages([1])  # uid() checks state before _command: fails closed, other error
    with pytest.raises(imaplib.IMAP4.error, match="illegal in state"):
        c._imap.uid("STORE", "1", "+FLAGS", "(\\Seen)")
    c.login("user@example.com", "x")
    with pytest.raises(imaplib.IMAP4.error, match="illegal in state"):
        c.delete_messages([1])
    with pytest.raises(ReadOnlyViolation):
        c.append("INBOX", b"x")
    assert "STORE" not in s.wire and "UID STORE" not in s.wire and "APPEND" not in s.wire


def test_state_errors_when_allowed():
    s, c = connect()
    out = {}
    for name, call in {
        "examine before login": lambda: c.select_folder("INBOX", readonly=True),
        "list before login": lambda: c.list_folders(),
    }.items():
        try:
            call()
            out[name] = "ok"
        except Exception as e:  # noqa: BLE001
            out[name] = f"{type(e).__module__}.{type(e).__name__}: {str(e)[:45]}"
    c.login("user@example.com", "x")
    for name, call in {
        "fetch in AUTH state": lambda: c.fetch([1], ["UID"]),
        "search in AUTH state": lambda: c.search(["ALL"]),
        "id in AUTH": lambda: c.id_(),
        "unselect in AUTH": lambda: c.unselect_folder(),
    }.items():
        try:
            call()
            out[name] = "ok"
        except Exception as e:  # noqa: BLE001
            out[name] = f"{type(e).__module__}.{type(e).__name__}: {str(e)[:45]}"
    for k, v in out.items():
        report("state " + k, v)
    report("Commands has ID/UNSELECT", ("ID" in imaplib.Commands, "UNSELECT" in imaplib.Commands))


def test_idle_done_bypass():
    s, c = opened(plain=CmdOnlyIdlePlain)
    c.idle()
    c.idle_done()
    report("wire (command-only guard, idle)", s.wire)
    report("seen by _command", c._imap.cmd_seen)
    assert "DONE" in s.wire and "DONE" not in c._imap.cmd_seen
    s, c = opened(plain=IdlePlain)
    with pytest.raises(ReadOnlyViolation):
        c._imap.send(b"DONE\r\n")
    c.idle()
    c.idle_done()
    report("wire (send guard, idle enabled)", s.wire)
    assert s.wire[-2:] == ["IDLE", "DONE"]
    with pytest.raises(ReadOnlyViolation):
        c._imap.send(b"DONE\r\n")
    s, c = opened()
    with pytest.raises(ReadOnlyViolation):
        c.idle()
    with pytest.raises(ReadOnlyViolation):
        c._imap.send(b"DONE\r\n")
    assert "DONE" not in s.wire and "IDLE" not in s.wire


def test_literal_cap():
    s, c = opened("big")
    with pytest.raises(imaplib.IMAP4.abort, match="over cap"):
        c.fetch([1], ["BODY.PEEK[]"])


def test_literal_cap_is_per_command():
    s, c = opened("big")
    c._imap.next_caps = (6000, 6000)  # caller picks the cap from the fetched item's L-nn
    assert c.fetch([1], ["BODY.PEEK[]"])
    assert c._imap.next_caps is None
    with pytest.raises(imaplib.IMAP4.abort, match="over cap"):  # reset to the default
        c.fetch([1], ["BODY.PEEK[]"])


def test_literal_cap_stops_reading():
    s, c = opened("huge")
    with pytest.raises(imaplib.IMAP4.abort, match="over cap"):
        c.fetch([1], ["BODY.PEEK[]"])
    report("64 MiB literal fully pushed to client", s.sent.wait(1.0))
    buffered = getattr(c._imap, "_readbuf", None)
    if buffered is not None:
        report("bytes in _readbuf after abort", sum(map(len, buffered)))
    assert not s.sent.is_set()


def test_response_total_cap():
    s, c = opened("trio")
    with pytest.raises(imaplib.IMAP4.abort, match="response over"):
        c.fetch([1, 2, 3], ["BODY.PEEK[]"])


def _buffered(c):
    rb = getattr(c._imap, "_readbuf", None)  # 3.14 only; earlier Pythons buffer inside `file`
    return None if rb is None else sum(map(len, rb))


RECV_CHUNK = 256 * 1024  # upper bound on one recv; refined from the REPORT lines


@pytest.mark.parametrize("cap", [5000, None], ids=["maxline-5000", "maxline-default"])
def test_line_cap(cap):
    old = imaplib._MAXLINE
    if cap:
        imaplib._MAXLINE = cap
    effective = imaplib._MAXLINE
    try:
        s, c = opened("longline")
        with pytest.raises(imaplib.IMAP4.error, match="got more than") as ei:
            c.noop()
        assert not isinstance(ei.value, imaplib.IMAP4.abort)
        buffered = _buffered(c)
        report(f"line cap {effective}: exception", f"{type(ei.value).__module__}.{type(ei.value).__name__}")
        report(f"line cap {effective}: bytes buffered at error", buffered)
        report(f"line cap {effective}: server finished 2000000-byte write", s.sent.wait(1.0))
        if buffered is not None:
            assert buffered <= effective + RECV_CHUNK
    finally:
        imaplib._MAXLINE = old


def test_peek_isolated():
    a, b = socket.socketpair()
    f = a.makefile("rb")
    a.settimeout(0.0)
    t0 = time.monotonic()
    r = f.peek(1)
    report("peek(1) on empty buffer, timeout 0.0", (r, round(time.monotonic() - t0, 3)))
    assert r == b""
    a.settimeout(None)
    b.sendall(b"hi\r\n")
    assert f.readline() == b"hi\r\n"
    report("readline works after non-blocking peek", True)
    b.sendall(b"abc\r\n")
    a.settimeout(0.0)
    time.sleep(0.05)
    peeked = f.peek(1)
    report("peek(1) with kernel bytes only", peeked[:1])
    a.settimeout(None)
    assert f.readline() == b"abc\r\n"


def _starttls(mode, certs, plain=GuardedPlain):
    srv, cli = certs
    s = Fake(mode, ctx=srv)
    c = client_class(plain, GuardedTLS)("127.0.0.1", port=s.port, ssl=False, timeout=5)
    return s, c, cli


def test_starttls_clean_passes_with_guard(certs):
    s, c, cli = _starttls("normal", certs)
    c.starttls(cli)
    caps = c.capabilities()
    report("clean STARTTLS caps", caps)
    assert s.events == ["handshake"] and b"STARTTLS" not in caps
    c.login("user@example.com", "x")


def test_starttls_buffered_bytes_detected(certs):
    s, c, cli = _starttls("extra", certs)
    with pytest.raises(imaplib.IMAP4.abort, match="buffered before TLS"):
        c.starttls(cli)
    time.sleep(0.2)
    report("handshake after injection (guarded)", "handshake" in s.events)
    assert "handshake" not in s.events and "LOGIN" not in s.wire


def test_starttls_buffered_bytes_unguarded(certs):
    srv, cli = certs
    s = Fake("extra", ctx=srv)
    caught = []

    class Plain(IMAP4WithTimeout):
        def _get_capabilities(self):
            typ, dat = self.capability()
            caught.append(dat)
            self.capabilities = tuple(str(dat[-1], self._encoding).upper().split())

    c = client_class(Plain, IMAP4_TLS)("127.0.0.1", port=s.port, ssl=False, timeout=5)
    c.starttls(cli)
    report("unguarded: CAPABILITY responses seen by imaplib after TLS", caught)
    caps_imaplib = c._imap.capabilities
    caps_client = c.capabilities()
    poisoned = any(b"XINJECTED" in x for resp in caught for x in resp)
    report("unguarded STARTTLS, imaplib.capabilities", caps_imaplib)
    report("injected plaintext line survives into TLS session", poisoned)


def test_starttls_probe_without_tls_server():
    s = Fake("extra")
    c = client_class(GuardedPlain, GuardedTLS)("127.0.0.1", port=s.port, ssl=False, timeout=5)
    with pytest.raises(imaplib.IMAP4.abort, match="buffered before TLS"):
        c.starttls(ssl.create_default_context())


def test_implicit_tls(certs):
    srv, cli = certs
    s = Fake("normal", ctx=srv, implicit=True)
    c = client_class(GuardedPlain, GuardedTLS)("127.0.0.1", port=s.port, ssl=True,
                                                ssl_context=cli, timeout=5)
    c.login("user@example.com", "x")
    with pytest.raises(ReadOnlyViolation):
        c.create_folder("x")
    with pytest.raises(ReadOnlyViolation):
        c.append("INBOX", b"x")
    assert "CREATE" not in s.wire and "APPEND" not in s.wire
    report("IMAP4_TLS MRO base", [k.__name__ for k in IMAP4_TLS.__mro__])
    report("GuardedTLS MRO", [k.__name__ for k in GuardedTLS.__mro__])


def test_implicit_tls_unguarded_without_mixin(certs):
    srv, cli = certs
    s = Fake("normal", ctx=srv, implicit=True)
    c = client_class(GuardedPlain, IMAP4_TLS)("127.0.0.1", port=s.port, ssl=True,
                                               ssl_context=cli, timeout=5)
    c.login("user@example.com", "x")
    c.create_folder("x")
    report("wire (override returns plain IMAP4_TLS in TLS branch)", s.wire)
    assert "CREATE" in s.wire


def test_non_branching_override_with_ssl_true(certs):
    srv, cli = certs
    s = Fake("normal", ctx=srv, implicit=True)

    class Prototype(IMAPClient):
        def _create_IMAP4(self):
            return GuardedPlain(self.host, self.port, 5)

    t0 = time.monotonic()
    with pytest.raises(Exception) as ei:
        Prototype("127.0.0.1", port=s.port, ssl=True, ssl_context=cli, timeout=5)
    report("non-branching override, ssl=True ->", f"{type(ei.value).__name__} after {time.monotonic() - t0:.1f}s")


def test_stream_refused():
    with pytest.raises(ValueError, match="stream mode refused"):
        client_class(GuardedPlain, GuardedTLS)("true", ssl=False, stream=True)


def test_esearch_not_exposed_but_reachable_privately():
    import imapclient
    src = "".join(open(os.path.join(os.path.dirname(imapclient.__file__), f), encoding="utf-8").read()
                  for f in os.listdir(os.path.dirname(imapclient.__file__)) if f.endswith(".py"))
    report("'esearch' appears in imapclient source", "esearch" in src.lower())
    s, c = opened()
    r = c.search(["RETURN", "(COUNT)", "ALL"])
    report("public search() with RETURN: result (ESEARCH response is dropped)", r)
    assert r == []
    data = c._raw_command_untagged(b"SEARCH", [b"RETURN", b"(COUNT)", b"ALL"], response_name="ESEARCH")
    report("private ESEARCH round trip", data)
    assert data and b"COUNT 3" in data[0]


def test_send_guard_alone_blocks_every_mutation():
    s, c = opened(plain=SendOnlyPlain)
    for name, call in MUTATIONS.items():
        with pytest.raises(ReadOnlyViolation):
            call(c)
    assert MUTATING.isdisjoint(s.wire) and "DONE" not in s.wire
    with pytest.raises(ReadOnlyViolation):
        c._imap.send(b"DONE\r\n")
    c.fetch([1], ["BODY.PEEK[]"])
    report("wire (send-only guard)", s.wire)


def test_starttls_late_bytes_not_caught_but_handshake_fails(certs):
    s, c, cli = _starttls("late", certs)
    with pytest.raises(Exception) as ei:
        c.starttls(cli)
    time.sleep(0.2)
    report("late injected bytes after OK", f"{type(ei.value).__module__}.{type(ei.value).__name__}")
    assert "handshake" not in s.events and "LOGIN" not in s.wire


def test_pending_probe_kernel_only_bytes():
    a, b = socket.socketpair()

    class Stub(GuardMixin):
        pass

    st = Stub()
    st.sock = a
    uses_readbuf = hasattr(connect()[1]._imap, "_readbuf")
    st._readbuf = [] if uses_readbuf else None
    st.file = a.makefile("rb")
    a.settimeout(7.0)
    assert st._pending() is False
    assert a.gettimeout() == 7.0
    b.sendall(b"* injected\r\n")
    time.sleep(0.05)
    assert st._pending() is True
    assert a.gettimeout() == 7.0
    if uses_readbuf:
        st._readbuf = [b"x"]
        assert st._readbuf_pending() is True


class Recorder:
    """Records every LogRecord created whose logger name starts with `prefix`, wherever it is routed."""

    def __init__(self, prefix="imapclient"):
        self.prefix = prefix

    def __enter__(self):
        self.items = []
        self.old = logging.getLogRecordFactory()
        old, items, prefix = self.old, self.items, self.prefix

        def factory(*a, **kw):
            rec = old(*a, **kw)
            if rec.name.startswith(prefix):
                items.append((rec.name, rec.levelname, rec.getMessage()))
            return rec

        logging.setLogRecordFactory(factory)
        self.root = logging.getLogger()
        self.null, self.level = logging.NullHandler(), self.root.level
        self.root.addHandler(self.null)
        self.root.setLevel(logging.DEBUG)
        return self

    def __exit__(self, *exc):
        logging.setLogRecordFactory(self.old)
        self.root.removeHandler(self.null)
        self.root.setLevel(self.level)


def pin_critical_plus_one(lg):
    lg.setLevel(logging.CRITICAL + 1)
    lg.propagate = False
    lg.addHandler(logging.NullHandler())


def pin_warning(lg):  # the round-1 pin: mutation, must leak
    lg.setLevel(logging.WARNING)
    lg.propagate = False


def _corpus(plain, only=None):
    """8-bit server values: a folder name, a NO and a BAD text, an ENVELOPE address."""
    s, c = connect(plain=plain, tls_cls=GuardedTLS, eightbit=True)
    c.login("user@example.com", "S3cretPw")

    def step(name, fn):
        if only in (None, name):
            try:
                fn()
            except (IMAPClientError, imaplib.IMAP4.error):
                pass

    step("folder", c.list_folders)
    step("no", lambda: c.select_folder("Missing", readonly=True))
    c.select_folder("INBOX", readonly=True)
    c.search(["SUBJECT", "needle"])
    step("bad", lambda: c.search(["SUBJECT", "XBAD"]))
    c.fetch([1], ["FLAGS"])
    step("envelope", lambda: str(c.fetch([1], ["ENVELOPE"])[1][b"ENVELOPE"].from_[0]))
    c.logout()


def _run_logged(fn, pin=None, prefix="imapclient"):
    lg = logging.getLogger("imapclient")
    saved = (lg.level, lg.propagate, lg.disabled, list(lg.handlers))
    if pin:
        pin(lg)
    try:
        with Recorder(prefix) as rec:
            fn()
    finally:
        lg.setLevel(saved[0])
        lg.propagate, lg.disabled = saved[1], saved[2]
        lg.handlers[:] = saved[3]
    return rec.items


def _show(capfd, cap):
    with capfd.disabled():  # capfd would otherwise swallow the REPORT lines
        print(cap.out, end="")


def test_imapclient_logging_corpus_at_root_debug(capfd):
    class Stock(IMAP4WithTimeout):
        pass

    stock = _run_logged(lambda: _corpus(Stock))
    capfd.readouterr()
    names = sorted({n for n, _, _ in stock})
    report("stock imapclient at root DEBUG: logger names", names)
    report("stock: records with the password", sum("S3cretPw" in m for _, _, m in stock))
    report("stock: server lines (`<`) logged", [m for _, _, m in stock if m.startswith("<")][:2])
    report("stock: records naming the folder/user", sum("INBOX" in m or "user@example.com" in m for _, _, m in stock))
    _show(capfd, capfd.readouterr())
    assert not any("S3cretPw" in m for _, _, m in stock)
    assert any(n == "imapclient.imaplib" and m.lstrip().startswith("<") for n, _, m in stock)
    assert any(n == "imapclient.imapclient" for n, _, _ in stock)

    only_debug0 = _run_logged(lambda: _corpus(GuardedPlain))
    capfd.readouterr()
    report("debug=0 only: remaining logger names", sorted({n for n, _, _ in only_debug0}))
    _show(capfd, capfd.readouterr())
    assert not any(n == "imapclient.imaplib" for n, _, _ in only_debug0)
    assert any(n == "imapclient.imapclient" for n, _, _ in only_debug0)

    both = _run_logged(lambda: _corpus(GuardedPlain), pin_critical_plus_one)
    cap = capfd.readouterr()
    report("debug=0 plus logger tree pinned: imapclient* records", len(both))
    report("debug=0 plus logger tree pinned: stderr bytes", len(cap.err))
    _show(capfd, capfd.readouterr())
    assert both == []
    assert cap.err == ""


@pytest.mark.parametrize("item", ["folder", "no", "bad", "envelope"])
def test_warning_pin_leaks_8bit_server_text_to_stderr(item, capfd):
    """Mutation of the pin: at WARNING an 8-bit value reaches stderr via lastResort."""
    recs = _run_logged(lambda: _corpus(GuardedPlain, only=item), pin_warning)
    cap = capfd.readouterr()
    leaked = bool(recs) and "Needle" in cap.err
    report(f"WARNING pin, {item}: leaks to stderr", (len(recs), leaked))
    _show(capfd, capfd.readouterr())
    if item in ("no", "envelope"):
        assert leaked
    clean = _run_logged(lambda: _corpus(GuardedPlain, only=item), pin_critical_plus_one)
    assert clean == [] and capfd.readouterr().err == ""


def test_debug_property_ignores_set():
    s, c = connect()
    assert c._imap.debug == 0
    c._imap.debug = 5
    assert c._imap.debug == 0


def test_unarmed_send_fails_closed():
    s, c = opened()
    for data in (b"X9 STORE 1 +FLAGS (\\Seen)\r\n", b"DONE\r\n", b"done\r\n", b"\r\n", b" ", b"x"):
        with pytest.raises(ReadOnlyViolation):
            c._imap.send(data)
    c.noop()
    with pytest.raises(ReadOnlyViolation):
        c._imap.send(b"X9 STORE 1 +FLAGS (\\Seen)\r\n")
    assert "STORE" not in s.wire and "DONE" not in s.wire


def test_done_matches_case_insensitively_while_idle_is_active():
    s, c = opened(plain=IdlePlain)
    c.idle()
    c._imap.send(b"done\r\n")
    c._consume_until_tagged_response(c._idle_tag, "IDLE")
    assert s.wire[-2:] == ["IDLE", "DONE"]
    with pytest.raises(ReadOnlyViolation):
        c._imap.send(b"done\r\n")


def test_mid_command_shapes_pass_and_stray_fragments_fail():
    st = GuardedPlain.__new__(GuardedPlain)
    st._state, st._lit_left = "auth", 0
    for ok in (b"AHVzZXIAcGFzcw==", b"\r\n", b"*"):
        st._check_unarmed(ok)
    for bad in (b"X9 STORE 1\r\n", b"A B", b"AHVz\r\nX9", b"AAAA\n", b"\n"):
        with pytest.raises(ReadOnlyViolation):
            st._check_unarmed(bad)
    st._state, st._lit_left = "await", 5
    with pytest.raises(ReadOnlyViolation):
        st._check_unarmed(b"abcde")
    st._state, st._lit_left = "literal", 5
    st._check_unarmed(b"abcde")
    assert st._state == "open"
    st._check_unarmed(b" ")
    st._check_unarmed(b"\r\n")
    assert st._state == "closed"
    with pytest.raises(ReadOnlyViolation):
        st._check_unarmed(b" ")
    st._state = "literal"
    st._lit_left = 5
    with pytest.raises(ReadOnlyViolation):
        st._check_unarmed(b"abcdef")


def _injection_probes(c):
    inj = "X9 STORE 1 +FLAGS (\\Seen)"
    return {
        "raw select": lambda: c._imap.select("INBOX\r\n" + inj, readonly=True),
        "fetch item": lambda: c.fetch([1], ["FLAGS)\r\n" + inj + " ("]),
        "folder name": lambda: c.select_folder("INBOX\r\n" + inj, readonly=True),
        "search term": lambda: c.search(["SUBJECT", "a\r\n" + inj]),
        "search 8-bit": lambda: c.search(["SUBJECT", "\u00e9\r\n" + inj], charset="UTF-8"),
    }


@pytest.mark.parametrize("guarded", [True, False], ids=["guarded", "armed-line-check-off"])
def test_embedded_line_break_never_adds_a_verb(guarded):
    class NoLineCheck(GuardedPlain):
        def send(self, data):
            if self._state == "armed":
                data_check = data
                self._state = "open"  # skip the armed-line check, keep the rest
                return super(GuardMixin, self).send(data_check)
            return super().send(data)

    s, c = opened(plain=GuardedPlain if guarded else NoLineCheck)
    outcome = {}
    for name, call in _injection_probes(c).items():
        try:
            call()
            outcome[name] = "no error"
        except Exception as e:  # noqa: BLE001
            outcome[name] = type(e).__name__
    report(f"{'guarded' if guarded else 'unchecked'} injection probes", outcome)
    report("wire", s.wire)
    if guarded:
        assert MUTATING.isdisjoint(s.wire)
    else:  # 3.13+ imaplib rejects control characters itself; 3.11/3.12 do not
        assert "STORE" in s.wire or outcome["raw select"] == "ValueError"


@pytest.mark.parametrize("literal_plus", [False, True], ids=["sync", "literal+"])
def test_real_literals_pass_the_strict_guard(literal_plus):
    s, c = opened(literal_plus=literal_plus)
    assert c.search(["SUBJECT", "\u00e9"], charset="UTF-8") == [1, 2, 3]
    assert c.search(["SUBJECT", "\u00e9", "FROM", "x"], charset="UTF-8") == [1, 2, 3]
    assert s.wire[-1] == "UID SEARCH"
    assert c.sort(["ARRIVAL"], ["SUBJECT", "\u00e9"], charset="UTF-8") == [3, 2, 1]
    assert s.wire[-1] == "UID SORT"
    assert c._imap._state == "closed"


def test_authenticate_passes_the_strict_guard():
    s, c = connect()
    c.plain_login("user@example.com", "x")
    assert "AUTHENTICATE" in s.wire
    assert s.auth_replies and s.auth_replies[0].endswith(b"\r\n")
    report("AUTHENTICATE PLAIN reply line", len(s.auth_replies[0]))


class Sink:
    def __init__(self):
        self.wrote = []

    def sendall(self, data):
        self.wrote.append(data)


def _stub(state="armed"):
    st = GuardedPlain.__new__(GuardedPlain)
    st._state, st.sock = state, Sink()
    return st


ARMED_REFUSED = {
    "embedded line break": b"X1 NOOP\r\nX9 STORE 1 +FLAGS (\\Seen)\r\n",
    "unterminated FETCH line": b"X1 UID FETCH 1 (FLAGS",
    "literal in FETCH": b"X1 UID FETCH 1 (BODY.PEEK[HEADER.FIELDS (Date {7}\r\n",
    "literal+ in FETCH": b"X1 UID FETCH 1 (BODY.PEEK[HEADER.FIELDS (Date {7+}\r\n",
    "literal in NOOP": b"X1 NOOP {3}\r\n",
}


@pytest.mark.parametrize("name", ARMED_REFUSED)
def test_armed_line_shapes_refused_on_every_minor(name):
    """Seam: the mixin's own check, with imaplib's control-character check out of play."""
    st = _stub()
    with pytest.raises(ReadOnlyViolation):
        st.send(ARMED_REFUSED[name])
    assert st.sock.wrote == []


@pytest.mark.parametrize("data,state", [
    (b"X1 UID SEARCH ALL", "open"),
    (b"X1 UID SORT (ARRIVAL) UTF-8 SUBJECT {2}\r\n", "await"),
    (b"X1 UID THREAD REFERENCES UTF-8 SUBJECT {2+}\r\n", "literal"),
    (b"X1 UID SEARCH ALL\r\n", "closed"),
    (b"X1 NOOP\r\n", "closed"),
])
def test_armed_line_shapes_allowed(data, state):
    st = _stub()
    st.send(data)
    assert st._state == state and st.sock.wrote == [data]


def test_fetch_extension_fragments_refused():
    s, c = opened()
    im = c._imap
    tag = im._new_tag()
    with pytest.raises(ReadOnlyViolation):
        im.send(tag + b" UID FETCH 1 (FLAGS")
    for stray in (b" BODY[])", b"\r\n"):  # the gate stays armed: stray sends fail closed
        with pytest.raises(ReadOnlyViolation):
            im.send(stray)
    tag = im._new_tag()
    with pytest.raises(ReadOnlyViolation):
        im.send(tag + b" UID FETCH 1 (BODY.PEEK[HEADER.FIELDS (Date {7}\r\n")
    for stray in (b"Subject", b")] BODY[])", b"\r\n"):
        with pytest.raises(ReadOnlyViolation):
            im.send(stray)
    time.sleep(0.3)
    report("wire (FETCH fragment probes)", s.wire)
    assert "UID FETCH" not in s.wire


def test_sync_literal_bytes_wait_for_the_continuation():
    st = _stub()
    inj = b"X9 UID STORE 1 +FLAGS (\\Seen)".ljust(31) + b"\r\n"
    st.send(b"X1 UID SEARCH CHARSET UTF-8 SUBJECT {%d}\r\n" % len(inj))
    assert st._state == "await"
    with pytest.raises(ReadOnlyViolation):
        st.send(inj)
    assert len(st.sock.wrote) == 1


def test_sync_literal_refused_by_server_closes_the_gate():
    s, c = opened("nolit")
    stray = b"X9 UID STORE 1 +FLAGS (\\Seen)".ljust(32) + b"\r\n"
    with pytest.raises(Exception) as ei:  # server answers BAD instead of `+`
        c.search(["SUBJECT", "\u00e9" * (len(stray) // 2)], charset="UTF-8")
    report("sync literal answered by tagged BAD ->", f"{type(ei.value).__name__}")
    assert c._imap._state == "closed"
    with pytest.raises(ReadOnlyViolation):
        c._imap.send(stray)
    time.sleep(0.2)
    assert "UID STORE" not in s.wire


def test_auth_state_closes_on_tagged_completion():
    s, c = connect()
    im = c._imap
    tag = im._new_tag()
    im.send(tag + b" AUTHENTICATE PLAIN\r\n")
    assert im._state == "auth"
    im._get_response()  # the `+` continuation
    im.send(b"AAAA")
    im.send(b"\r\n")
    im._command_complete("AUTHENTICATE", tag)
    assert im._state == "closed"
    for stray in (b"AAAA", b"AAAA\n", b"\r\n"):
        with pytest.raises(ReadOnlyViolation):
            im.send(stray)


@pytest.mark.parametrize("plus", [b"", b"+"], ids=["sync", "literal+"])
@pytest.mark.parametrize("line", [
    b"X1 UID FETCH 1 (BODY.PEEK[HEADER.FIELDS ({7%s}\r\n",
    b"X1 UID FETCH 1 (BODY.PEEK[HEADER.FIELDS (Date{7%s}\r\n",
    b"X1 NOOP{3%s}\r\n",
], ids=["after-paren", "after-atom", "noop"])
def test_unspaced_literal_announcement_refused_outside_raw_verbs(line, plus):
    st = _stub()
    with pytest.raises(ReadOnlyViolation):
        st.send(line % plus)
    assert st.sock.wrote == []


@pytest.mark.parametrize("plus", [b"", b"+"], ids=["sync", "literal+"])
def test_unspaced_literal_fetch_probe_never_reaches_the_wire(plus):
    """Round-3 probe: `({n}` in a FETCH, then a re-armed NOOP that completes it with `BODY[]`."""
    s, c = opened()
    im = c._imap
    t1 = im._new_tag()
    with pytest.raises(ReadOnlyViolation):
        im.send(t1 + b" UID FETCH 1 (BODY.PEEK[HEADER.FIELDS ({%d%s}\r\n" % (len(t1) + 5, plus))
    t2 = im._new_tag()  # the gate stayed armed, so this re-arms; the completion vets as a NOOP
    im.send(t2 + b" NOOP)] BODY[])\r\n")
    time.sleep(0.3)
    report("wire (unspaced literal probe)", s.wire)
    assert not any("FETCH" in v for v in s.wire)


@pytest.mark.parametrize("state", sorted(IN_FLIGHT))
def test_new_tag_refuses_while_a_command_is_in_flight(state):
    s, c = opened()
    im = c._imap
    im._state = state
    with pytest.raises(ReadOnlyViolation):
        im._new_tag()
    assert im._state == state
    for ok in ("armed", "closed"):
        im._state = ok
        im._new_tag()
        assert im._state == "armed"


def test_new_tag_refuses_after_a_real_raw_announcement():
    s, c = opened()
    im = c._imap
    tag = im._new_tag()
    im.send(tag + b" UID SEARCH CHARSET UTF-8 SUBJECT ({3}\r\n")
    assert im._state == "await"
    with pytest.raises(ReadOnlyViolation):
        im._new_tag()
    time.sleep(0.2)
    assert "NOOP" not in s.wire


NON_ASCII = "S3cr\u00e9tPw"


def _everything_about(exc):
    return [repr(exc), str(exc), "".join(map(str, exc.args)), "".join(traceback.format_exception(exc))]


def test_stock_login_leaks_a_non_ascii_secret_in_the_exception():
    """Control: the failure the check prevents."""
    s, c = connect()
    with pytest.raises(UnicodeEncodeError) as ei:
        c.login("user@example.com", NON_ASCII)
    report("stock login, non-ASCII secret: leak in repr/args", (NON_ASCII in repr(ei.value), NON_ASCII in str(ei.value.args)))
    assert NON_ASCII in repr(ei.value) or NON_ASCII in str(ei.value.args) or NON_ASCII in str(ei.value.object)
    assert s.wire == ["CAPABILITY"]


@pytest.mark.parametrize("user,secret", [("user@example.com", NON_ASCII), ("us\u00e9r@example.com", "x")],
                         ids=["secret", "username"])
def test_non_ascii_credential_raises_a_typed_error_without_the_secret(user, secret, capfd):
    s, c = connect()
    err = None
    with Recorder("") as rec:
        try:
            login_checked(c, user, secret)
        except Exception as e:  # noqa: BLE001
            err = e
    cap = capfd.readouterr()
    assert isinstance(err, CredentialError)
    assert err.__context__ is None and err.__cause__ is None
    for text in _everything_about(err) + [cap.out, cap.err] + [m for _, _, m in rec.items]:
        assert NON_ASCII not in text and "S3cr" not in text and "\u00e9" not in text
    assert s.wire == ["CAPABILITY"]


def test_non_ascii_secret_goes_to_authenticate_plain_as_utf8():
    s, c = connect(auth_plain=True)
    login_checked(c, "user@example.com", NON_ASCII)
    assert "AUTHENTICATE" in s.wire and "LOGIN" not in s.wire
    assert base64.b64decode(s.auth_replies[0].strip()) == b"\x00user@example.com\x00" + NON_ASCII.encode()


def test_ascii_credentials_still_use_login():
    s, c = connect(auth_plain=True)
    login_checked(c, "user@example.com", "x")
    assert "LOGIN" in s.wire and "AUTHENTICATE" not in s.wire


NEEDLE_CORPUS = ("Needle", "rejected", "caf")


def test_imap_error_text_reaches_no_log_record_output_or_surfaced_string(capfd):
    """`caf\u00e9-Needle rejected` (NO and BAD) is in the exceptions; only fixed codes get out."""
    log = logging.getLogger("proto.errors")
    surfaced = []

    def surface(exc):
        code = error_code(exc)
        log.warning("imap error: %s", code)
        surfaced.append(code)
        return code

    raised = []

    def run():
        s, c = connect(plain=GuardedPlain, tls_cls=GuardedTLS, eightbit=True)
        c.login("user@example.com", "x")
        for call in (lambda: c.select_folder("Missing", readonly=True), lambda: c.search(["SUBJECT", "XBAD"])):
            try:
                call()
            except (IMAPClientError, imaplib.IMAP4.error) as e:
                raised.append(e)
                surface(e)

    records = _run_logged(run, pin_critical_plus_one, prefix="")
    cap = capfd.readouterr()
    assert len(raised) == 2
    assert any("Needle" in str(e) for e in raised)  # control: the exception text does carry it
    assert surfaced == ["imap_error", "imap_error"]
    for word in NEEDLE_CORPUS:
        assert not any(word in m for _, _, m in records), word
        assert word not in cap.out and word not in cap.err
        assert not any(word in x for x in surfaced)
    assert any(m.startswith("imap error: ") for _, _, m in records)  # control: the log path ran


def test_error_code_is_fixed_for_every_class():
    for exc, code in ((ReadOnlyViolation("caf\u00e9-Needle"), "read_only_violation"),
                      (CredentialError("x"), "credential_error"),
                      (imaplib.IMAP4.abort("caf\u00e9-Needle"), "session_aborted"),
                      (IMAPClientAbortError("caf\u00e9-Needle"), "session_aborted"),
                      (LoginError("caf\u00e9-Needle"), "login_failed"),
                      (IMAPClientError("caf\u00e9-Needle"), "imap_error"),
                      (imaplib.IMAP4.error("caf\u00e9-Needle"), "imap_error"),
                      (OSError("caf\u00e9-Needle"), "internal_error")):
        assert error_code(exc) == code
~~~

### Linux memory cap (rlimit_worker.py)

~~~python
import resource, sys
mode = sys.argv[1]
cap = 512 * 1024 * 1024
if mode != "nocap":
    resource.setrlimit(resource.RLIMIT_AS, (cap, resource.getrlimit(resource.RLIMIT_AS)[1]))
print("RLIMIT_AS", resource.getrlimit(resource.RLIMIT_AS), flush=True)
try:
    import pypdf  # baseline import under the cap
    print("pypdf import ok", flush=True)
    chunks = []
    for i in range(40):
        chunks.append(bytearray(64 * 1024 * 1024))
    print("allocated 2560 MiB without error", flush=True)
except MemoryError:
    print("MemoryError after", len(chunks), "x 64 MiB", flush=True)
    sys.exit(3)
~~~

### pypdf bomb (pypdf_bomb.py)

~~~python
import io, logging, zlib
from pypdf import PdfReader, overwrite_configuration
from pypdf.errors import LimitReachedError


def build(stream_raw):
    comp = zlib.compress(stream_raw, 9)
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R"
            b" /Resources << /Font << /F1 5 0 R >> >> >>",
            b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(comp) + comp + b"\nendstream",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    out, offs = b"%PDF-1.4\n", []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    x = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for o in offs:
        out += b"%010d 00000 n \n" % o
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, x)
    return out


class H(logging.Handler):
    def emit(self, rec):
        print("LOG", rec.levelname, rec.getMessage()[:90])


logging.getLogger("pypdf").addHandler(H())
head = b"BT /F1 12 Tf 10 100 Td (hello) Tj ET\n"
control = build(head)
bomb_valid_prefix = build(head + b" " * 200_000_000)
bomb_raw = build(b"A" * 200_000_000)


def extract(label, data, strict=False):
    try:
        r = PdfReader(io.BytesIO(data), strict=strict)
        print(label, "extract_text ->", repr(r.pages[0].extract_text()))
    except BaseException as e:
        print(label, "raised", type(e).__module__ + "." + type(e).__name__, str(e)[:90])


def contents(label, data):
    try:
        c = PdfReader(io.BytesIO(data)).pages[0].get_contents()
        print(label, "get_contents len", len(c.get_data()))
    except LimitReachedError as e:
        print(label, "get_contents raised LimitReachedError")


extract("control", control)
for label, d in (("bomb (valid text + 200 MB padding)", bomb_valid_prefix), ("bomb (200 MB junk)", bomb_raw)):
    extract(label + " default caps", d)
    extract(label + " strict", d, strict=True)
    contents(label, d)
overwrite_configuration(zlib_maximum_output_length=1_000_000, stream_decoding_work_maximum_length=5_000_000)
extract("bomb (valid text + 200 MB padding) lowered caps", bomb_valid_prefix)
extract("control lowered caps", control)
~~~
