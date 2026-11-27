# V1: IMAP guard hook, read caps, ESEARCH, PDF limits

Linux, CPython 3.11.18, 3.12.3, 3.13.18, 3.14.10; `imapclient==4.3.0`, `pytest==9.2.0`, `pypdf==7.2.0`. The appendix suite passes on each Python. Windows and macOS: not run, open for C4 (below). Evidence lines are `REPORT` output of the appendix.

Two earlier claims are REFUTED: `_command` is not the single choke point, and the pre-STARTTLS probe reads the wrong buffer on 3.14. See "Contradictions" and "Follow-up design edits (issue #7)": D1, D2 and C4 must not start from the `_command` hook.

## Verdicts

| # | Claim | Verdict | Observed |
|---|---|---|---|
| 1 | `_command` is the single choke point | REFUTED | `search`, `sort`, `thread`, `append`, `multiappend` use `_new_tag()` + `send()`; a `_command`-only guard missed `UID SEARCH/SORT/THREAD` and let `APPEND` out |
| 1a | Guard `_new_tag` and every `send` | VERIFIED | Verbs seen equal wire verbs on all four Pythons. 19 mutations (rw `SELECT`, `STORE` variants, `EXPUNGE`, `APPEND`, `CREATE`, `DELETE`, `RENAME`, `SUBSCRIBE`, `COPY`, `MOVE`, raw `STORE`, `IDLE`, `BODY[]`/`RFC822`/`RFC822.TEXT` fetches) raise before any byte is sent; `BODY.PEEK[]`, `RFC822.HEADER`, `RFC822.SIZE` pass. The FETCH check is a denylist here; A§6's allowlist is D2's |
| 1b | Un-armed `send` fails closed | VERIFIED | The armed line may not contain a line break before its closing CRLF (without that check a raw `select` with an embedded CRLF put `STORE` on the wire on 3.11 and 3.12; 3.13+ imaplib rejects control characters itself). After it, only these `send`s are allowed: literal bytes of the announced length (sync and `LITERAL+`, exercised with `search(..., charset="UTF-8")`), a space, the closing CRLF, AUTHENTICATE replies (exercised with `plain_login`), `DONE` (case-insensitive) in an active IDLE. A bare tagged line, `DONE` outside IDLE and line breaks inside a fragment raise. Mutation runs: removing the gate or the armed-line check fails tests |
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
| 19 | imapclient debug logging (T-03/T-21) | VERIFIED | Stock, root at DEBUG: `imapclient.imaplib` logs every server line (`< ...`), `imapclient.imapclient` logs commands, `Logged in as`. `LOGIN` is redacted (password never appeared); AUTHENTICATE logging not exercised. `debug` forced to 0 leaves `imapclient.imapclient`; with the logger tree also pinned to WARNING, no `imapclient*` record |

Wire survey (3.14): `CAPABILITY, LOGIN, CAPABILITY, CAPABILITY, NAMESPACE, LIST, STATUS, EXAMINE, UID SEARCH, UID SORT, UID THREAD, UID FETCH, NOOP, ID, UNSELECT, LOGOUT`; the `send` guard saw 16, `_command` 13.

### pypdf 7.2.0

- `pypdf.Configuration` is frozen; `overwrite_configuration(**kw)`, `apply_configuration(...)`, `get_configuration()` exist. Fields: `dataclasses.fields(Configuration)`.
- Defaults above `pdf_stream_bytes` (32 MiB): `maximum_declared_stream_length`, `zlib_/lzw_/run_length_/jbig2_/brotli_maximum_output_length`, `array_based_stream_maximum_output_length`, `image_maximum_buffer_size` (75 MB each); `stream_decoding_work_maximum_length`, `xfa_decoding_work_maximum_length` (300 MB); `embedded_files_maximum_output_length` (250 MB). `page_tree_maximum_entries` 100k, `_depth` 100, `_page_entries` 2M.
- `PdfReader(stream, strict=False, password=None, *, root_object_recovery_limit, xref_stream_maximum_entries, xref_rebuild_maximum_entries)`. No page-count or text cap: the worker loops pages.
- A 200 MB zlib stream in a complete page (about 190 KB file): `extract_text()` and `get_contents()` raised `LimitReachedError` at default and lowered caps; a control page returned text. Without `/Resources` the page returned `""` silently, so bomb fixtures need a complete page. Only the zlib path ran; the cyclic page tree and 100,000-page bombs did not (open for C4).

## Decisions for A§10

1. Item 1: one guard mixin for `IMAP4WithTimeout` and `IMAP4_TLS`, from an `IMAPClient._create_IMAP4` override (row 6).
   - Commands: `_new_tag` arms; the first `send` must parse as `tag [UID] VERB` and is vetted (allowlist, FETCH items) before any byte is written; later `send`s must match a mid-command shape (row 1b), else `ReadOnlyViolation`. `_command` is overridden for a clearer error, not as the guarantee.
   - A failed vet leaves the gate armed, so a later `send` is parsed as a command line (fails closed). D2 resets the gate on abort and reconnect. D2 tests: a bare tagged line through `send` raises; a line break in the armed line raises.
   - Reads: `read(size)` aborts over the active literal cap and the per-command total; the caller sets both per command from the fetched item's L-nn (L-05 header, L-02 part, L-08 attachment, L-01 full fallback), default the smallest, reset in `_new_tag`. Line cap: set `imaplib._MAXLINE` from L-20 once at startup (process-global; L-20's 1 MiB exceeds the stdlib 1,000,000). Line overflow raises `error`: treat `error` and `abort` as fatal, discard the session.
   - STARTTLS: override `_command_complete`; probe by feature, not version: `_readbuf` if the attribute exists, else `file.peek(1)`; then `MSG_PEEK`; restore the socket timeout.
   - Logging: `debug` is a property that reads 0 and ignores sets; the `imapclient` logger tree is pinned to WARNING with `propagate = False`. Both are required. Test: corpus at root DEBUG yields no `imapclient*` record.
   - Private API: pin imapclient; run the wire-survey, send-gate and STARTTLS tests on every supported minor.
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
- T-08, A§4, A§6 step 6: one fixed L-02 literal cap breaks the L-08 and L-01 fetches; the cap is per command (decision 1).
- T-08, L-nn: the per-command response total has no row in SECURITY §5; a batch of L-25 UIDs times L-02 is far above L-19. Needs a new L-nn with a `[limits]` key.
- L-15, L-20: without ESEARCH, `UID SEARCH` returns every match on one line (about 8 bytes per UID); above roughly 130k matches it exceeds L-20 and the session aborts.
- T-03, T-21: "imaplib's debug output is never enabled" is not enough. imapclient sets `debug = 5` after construction (a constructor-time override cannot zero it), and its loggers carry server lines, search criteria and the username. Needs both controls of decision 1.
- T-06: "set pypdf limits from limits.py" must name the fields (above) and derive `page_tree_maximum_*` from L-09.

## Follow-up design edits (issue #7)

Not edited here. Each blocks its owner.

| Edit | Owner |
|---|---|
| A§10.1, A§6, T-10: hook is `_new_tag` + `send` with the fail-closed gate; allowlist FETCH items | SECURITY follow-up (text), D2 (code) |
| A§2.2, T-07: reword buffered-bytes sentence; probe by feature (`_readbuf`, then `file.peek`, then `MSG_PEEK`); STARTTLS injection test on every supported minor in CI | SECURITY follow-up, D1 |
| T-08, A§4, A§6 step 6: per-command literal cap from the fetched item's L-nn (L-05/L-02/L-08/L-01), reset in `_new_tag` | SECURITY follow-up, D2 |
| T-08: wording "bounded at L-20 plus a bounded overshoot"; `imaplib._MAXLINE` set once, process-global | SECURITY follow-up, D2 |
| New L-nn: per-command response total, with a `[limits]` key and ceiling | SECURITY follow-up (before D2) |
| L-15, L-20: windowed UID ranges for SEARCH or `limit_exceeded`; L-20 never raised | SECURITY follow-up, D2 |
| T-03, T-21: `debug` forced to 0 and the `imapclient` logger tree pinned to WARNING, with the root-DEBUG corpus test | SECURITY follow-up, D2 |
| T-06, L-09, L-10: pypdf fields capped at `pdf_stream_bytes`; `page_tree_*` derived from L-09; cyclic-tree and 100,000-page fixtures | SECURITY follow-up, C4 |
| T-06, A§10.10: Windows job object and macOS `RLIMIT_AS`, researched and run on windows and macos CI runners; add a STATUS open item | C4 |

## Appendix: throwaway prototype (not for `tests/`)

Run, per Python, from outside the repository (needs `openssl` for a throwaway certificate; fakes listen on 127.0.0.1 only):
`UV_PYTHON=<ver> uv run --no-project --with imapclient==4.3.0 --with pytest==9.2.0 python -I -m pytest -q -s test_v1_hook.py`.
The pypdf script runs with `--with pypdf==7.2.0`.

### test_v1_hook.py

~~~python
# test_v1_hook.py  (throwaway; 127.0.0.1 fakes only)
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

import pytest
from imapclient import IMAPClient
from imapclient.imap4 import IMAP4WithTimeout
from imapclient.tls import IMAP4_TLS

ALLOWED = {"CAPABILITY", "NOOP", "LOGOUT", "STARTTLS", "LOGIN", "AUTHENTICATE", "ID",
           "NAMESPACE", "LIST", "LSUB", "STATUS", "EXAMINE", "CLOSE", "UNSELECT",
           "SEARCH", "FETCH", "SORT", "THREAD", "UID"}
UID_OK = {"SEARCH", "FETCH", "SORT", "THREAD"}
SEEN_ITEMS = re.compile(rb"BODY\[|BINARY\[|RFC822(?!\.(?:HEADER|SIZE)\b)", re.I)
CMD = re.compile(rb"^(\S+) (?:(UID) )?([A-Za-z]+)")
MAX_LITERAL, MAX_RESPONSE = 1000, 2000
ANN_END = re.compile(rb" \{(\d+)\+?\}\r\n$")
ANN_START = re.compile(rb"^ ?\{(\d+)(\+?)\}\r\n")
AUTH_REPLY = re.compile(rb"^(?:[A-Za-z0-9+/=]*|\*|\r\n)$")
MUTATING = {"SELECT", "STORE", "EXPUNGE", "APPEND", "CREATE", "DELETE", "RENAME",
            "COPY", "MOVE", "SUBSCRIBE", "UNSUBSCRIBE", "UID STORE", "UID COPY",
            "UID MOVE", "UID EXPUNGE"}


def report(key, value):
    print(f"REPORT {key}: {value}")


class ReadOnlyViolation(Exception):
    pass


class GuardMixin:
    strict = True        # False: record only
    guard_send = True    # False: the prototype's `_command`-only guard
    allow_idle = False
    vet_in_command = True
    _state = "closed"    # armed | open | literal | auth | idle | closed
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
        self._state = "armed"
        self._lit_left = 0
        self._budget = 0
        self._lit_cap, self._total_cap = self.next_caps or (MAX_LITERAL, MAX_RESPONSE)
        self.next_caps = None
        return super()._new_tag()

    def _after_line(self, data, verb):
        m = ANN_END.search(data)
        if verb == "AUTHENTICATE":
            self._state = "auth"
        elif verb == "IDLE":
            self._state = "idle"
        elif m:
            self._state, self._lit_left = "literal", int(m.group(1))
        elif data.endswith(b"\r\n"):
            self._state = "closed"
        else:
            self._state = "open"

    def _check_unarmed(self, data):
        """Fail closed: only the shapes imaplib/imapclient send mid-command."""
        st = self._state
        if st == "idle" and data.upper() == b"DONE\r\n" and self.allow_idle:
            self._state = "closed"
        elif st == "auth" and AUTH_REPLY.match(data):
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
                self._state, self._lit_left = "literal", int(m.group(1))
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
    def __init__(self, mode="normal", ctx=None, implicit=False, size=5000, literal_plus=False):
        self.mode, self.ctx, self.implicit, self.size = mode, ctx, implicit, size
        self.literal_plus = literal_plus
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
            while m := re.search(r"\{(\d+)\+?\}$", text):
                if not text.endswith("+}"):
                    c.sendall(b"+ go\r\n")
                f.read(int(m[1]))
                text += "<lit>" + f.readline().decode(errors="replace").rstrip("\r\n")
            tag, _, rest = text.partition(" ")
            parts = rest.split(" ")
            verb = parts[0].upper()
            sub = parts[1].upper() if verb == "UID" and len(parts) > 1 else None
            self.wire.append(f"UID {sub}" if sub else verb)
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
                else:
                    c.sendall(b"* 1 FETCH (UID 1 FLAGS (\\Seen))\r\n")
            elif verb == "LIST":
                c.sendall(b'* LIST () "/" INBOX\r\n')
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


class Records(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.items = []

    def emit(self, rec):
        self.items.append((rec.name, rec.getMessage()))


def _corpus(plain):
    s, c = connect(plain=plain, tls_cls=GuardedTLS)
    c.login("user@example.com", "S3cretPw")
    c.list_folders()
    c.select_folder("INBOX", readonly=True)
    c.search(["SUBJECT", "needle"])
    c.fetch([1], ["FLAGS"])
    c.logout()


def _root_debug(fn, pin):
    root = logging.getLogger()
    h, old_level = Records(), root.level
    root.addHandler(h)
    root.setLevel(logging.DEBUG)
    lg = logging.getLogger("imapclient")
    saved = (lg.level, lg.propagate)
    if pin:
        lg.setLevel(logging.WARNING)
        lg.propagate = False
    try:
        fn()
    finally:
        root.removeHandler(h)
        root.setLevel(old_level)
        lg.setLevel(saved[0])
        lg.propagate = saved[1]
    return [(n, m) for n, m in h.items if n.startswith("imapclient")]


def test_imapclient_logging_corpus_at_root_debug():
    class Stock(IMAP4WithTimeout):
        pass

    stock = _root_debug(lambda: _corpus(Stock), pin=False)
    names = sorted({n for n, _ in stock})
    report("stock imapclient at root DEBUG: logger names", names)
    report("stock: records with the password", sum("S3cretPw" in m for _, m in stock))
    report("stock: server lines (`<`) logged", [m for _, m in stock if m.startswith("<")][:2])
    report("stock: records naming the folder/user", sum("INBOX" in m or "user@example.com" in m for _, m in stock))
    assert not any("S3cretPw" in m for _, m in stock)
    assert any(n == "imapclient.imaplib" and m.lstrip().startswith("<") for n, m in stock)
    assert any(n == "imapclient.imapclient" for n, _ in stock)

    only_debug0 = _root_debug(lambda: _corpus(GuardedPlain), pin=False)
    report("debug=0 only: remaining logger names", sorted({n for n, _ in only_debug0}))
    assert not any(n == "imapclient.imaplib" for n, _ in only_debug0)
    assert any(n == "imapclient.imapclient" for n, _ in only_debug0)

    both = _root_debug(lambda: _corpus(GuardedPlain), pin=True)
    report("debug=0 plus logger tree pinned: imapclient* records", len(both))
    assert both == []


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
    for bad in (b"X9 STORE 1\r\n", b"A B", b"AHVz\r\nX9"):
        with pytest.raises(ReadOnlyViolation):
            st._check_unarmed(bad)
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


def test_real_literals_pass_the_strict_guard():
    s, c = opened()
    assert c.search(["SUBJECT", "\u00e9"], charset="UTF-8") == [1, 2, 3]
    assert s.wire[-1] == "UID SEARCH"
    s, c = opened(literal_plus=True)
    assert c.search(["SUBJECT", "\u00e9"], charset="UTF-8") == [1, 2, 3]
    assert s.wire[-1] == "UID SEARCH"
    assert c._imap._state == "closed"


def test_authenticate_passes_the_strict_guard():
    s, c = connect()
    c.plain_login("user@example.com", "x")
    assert "AUTHENTICATE" in s.wire
    assert s.auth_replies and s.auth_replies[0].endswith(b"\r\n")
    report("AUTHENTICATE PLAIN reply line", len(s.auth_replies[0]))
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
