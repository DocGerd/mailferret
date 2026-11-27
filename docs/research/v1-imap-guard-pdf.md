# V1: IMAP guard hook, read caps, ESEARCH, PDF limits

Executed on Linux, CPython 3.11.18, 3.12.3, 3.13.18 and 3.14.10 (project floor `>=3.11`; the read path differs on 3.14), imapclient 4.3.0 (BSD-3, no deps), pypdf 7.2.0 (BSD-3). The prototype in the appendix passes on each Python. Windows and macOS: not run here. Sources: imapclient `imapclient.py`, `imap4.py`, `tls.py`; CPython `Lib/imaplib.py`; pypdf introspection; `resource` on Linux.

Two earlier claims were REFUTED and the design changes: `_command` is not the single choke point, and the pre-STARTTLS probe reads the wrong buffer on 3.14. See "Contradictions".

## Verdicts

| # | Claim | Verdict | Observed |
|---|---|---|---|
| 1 | `_command` is the single choke point for every command | REFUTED | `search`, `sort`, `thread`, `append`, `multiappend` and the other `_raw_command` users call `_new_tag()` then `send()` and never reach `_command`. A `_command`-only guard let `APPEND` reach the wire. On the survey below `_command` missed `UID SEARCH`, `UID SORT`, `UID THREAD` |
| 1a | Replacement: guard `_new_tag` plus the first `send` after it, and `send` of exactly `DONE\r\n` | VERIFIED | The same mutation list also passed with the `send` guard alone (vetting in `_command` disabled). Verbs seen equal the wire verbs for the whole survey on all four Pythons. Every mutation tried (rw `SELECT`, `STORE` via add/set/remove flags and delete, `EXPUNGE`, UID `EXPUNGE`, `APPEND`, `CREATE`, `DELETE`, `RENAME`, `SUBSCRIBE`, `COPY`, `MOVE`, raw `STORE`, `IDLE`, FETCH of `BODY[]`, `RFC822`, `RFC822.TEXT`) raised before any byte was sent; `BODY.PEEK[]`, `RFC822.HEADER`, `RFC822.SIZE` passed. The FETCH check in the prototype is a denylist of `\Seen`-setting items on the first chunk; A§6 specifies an allowlist, left to D2 |
| 2 | `fetch`, `noop`, `idle`, `expunge` use `_command`; `UID` arrives as `name == "UID"` with `args[0]` the sub-command | VERIFIED | `_command` logged `UID FETCH`, `NOOP`, `IDLE`, `EXPUNGE` |
| 3 | The guard must run before imaplib's state check | PARTLY | True for a direct `_command` call. `imaplib.uid()` checks state first, so `delete_messages` before `SELECT` raises `imaplib.error` ("illegal in state"), not the guard error. Both fail closed: nothing is sent. Tests must accept either |
| 4 | `DONE` bypasses `_command` (it goes through `send`) | VERIFIED | With a `_command`-only guard and IDLE allowed, the wire shows `IDLE`, `DONE` and `_command` never saw `DONE`. With the `send` guard, `DONE` is refused unless IDLE is enabled and active. Match `DONE\r\n` exactly: `send` also carries literals and AUTHENTICATE replies |
| 5 | Implicit-TLS mode needs the same mixin on `IMAP4_TLS` | VERIFIED | `tls.IMAP4_TLS` derives from `imaplib.IMAP4`, not from `IMAP4WithTimeout`. An override whose TLS branch returned the plain class sent `CREATE`. A non-branching override returning the plain-socket class with `ssl=True` fails (`TimeoutError` after the 5 s timeout, TLS server). `GuardedTLS(GuardMixin, IMAP4_TLS)` blocked `CREATE` and `APPEND` and sent neither |
| 6 | `_create_IMAP4` signature and body | VERIFIED | `_create_IMAP4(self)`. `stream` returns `imaplib.IMAP4_stream(self.host)`. `connect_timeout = getattr(self._timeout, "connect", None)`. `ssl` returns `tls.IMAP4_TLS(host, port, self.ssl_context, connect_timeout)`; otherwise `imap4.IMAP4WithTimeout(host, port, connect_timeout)`. The prototype hard-coded the timeout and ignored `ssl`; the override must branch on `self.ssl` and refuse `self.stream`. It runs inside `__init__`, so mixin state needs class-level defaults. Do not name helpers `_log` (imaplib uses it) |
| 7 | A `read(size)` override caps literals | VERIFIED | A `{n}` literal over the cap raised `abort` before any literal byte was read; a 64 MiB literal was not pulled (the server's write stayed blocked, `_readbuf` empty) |
| 8 | Per-command total cap | VERIFIED | Three 800-byte literals under a 1000-byte literal cap and a 2000-byte total aborted on the third. Reset the counter in `_new_tag`, not `_command` (raw path) |
| 9 | `_MAXLINE` is 1,000,000 and enforced in `readline()` | VERIFIED | Overflow raises `imaplib.IMAP4.error` ("got more than N bytes"), not `abort`, on 3.11-3.14. Bytes buffered at the error: about 1.0-1.1 MB at the default (3.14), 32-88 KB with `imaplib._MAXLINE = 5000`. The module attribute is read at call time on all four Pythons, so a smaller line cap needs no `readline` override. A subclass `readline` can only check after the line is buffered |
| 10 | The `file.peek(1)` probe sees pre-STARTTLS bytes | REFUTED on 3.14, VERIFIED on 3.11-3.13 | 3.14 reads with `sock.recv` into `self._readbuf`; `file` is a warning property over an unused `makefile`, and the kernel `MSG_PEEK` finds nothing because the bytes were already moved. The prototype missed the injection and the handshake hung. Probe `_readbuf` on 3.14, `file.peek(1)` on 3.11-3.13, then `MSG_PEEK` on all |
| 11 | `peek(1)` on an empty buffer returns `b""` without blocking | VERIFIED | `(b"", 0.0 s)` with `settimeout(0.0)` on a `socketpair`; a later `readline` still works; with bytes only in the kernel buffer `peek(1)` returned `b"a"` |
| 11a | The `MSG_PEEK` / kernel-buffer probe | VERIFIED (unit level) | On a `socketpair` stub `_pending()` was False when empty, True with kernel-only bytes, and restored the socket timeout. In the end-to-end STARTTLS test the injected line always arrived with the OK, so the first probe caught it. Bytes arriving after the probe (server sleeps 0.5 s, then sends plaintext) are not detectable: the TLS handshake then failed with `ssl.SSLError` and no `LOGIN` was sent |
| 12 | `_command_complete("STARTTLS", tag)` runs after the tagged OK and before the wrap | VERIFIED | The guard raised `abort`; the fake saw no handshake and no `LOGIN` (3.11-3.14). A clean STARTTLS passed over a throwaway self-signed certificate and capabilities re-read over TLS no longer listed `STARTTLS` |
| 13 | `starttls()` drops buffered bytes silently | REFUTED on 3.14 | 3.11-3.13: dropped. 3.14: kept in `_readbuf` and parsed as TLS-session data: the injected plaintext `* CAPABILITY ... XINJECTED` was the first CAPABILITY response read after the handshake. imaplib takes `dat[-1]`, so capabilities stayed correct here, but any injected untagged line (`BYE`, `EXISTS`, `ALERT`) is processed |
| 14 | imaplib state errors when the guard allows a verb | VERIFIED | `imaplib.error: command X illegal in state S` for `EXAMINE`/`LIST` before login and for `UID`, `UNSELECT` in AUTH. `SEARCH`/`SORT`/`THREAD` (raw path) do no state check: a `SEARCH` in AUTH state went to the wire. `ID` (allowed in AUTH) and `UNSELECT` are in `imaplib.Commands`: no `KeyError` |
| 15 | imapclient has no ESEARCH support | VERIFIED | "esearch" appears nowhere in the 4.3.0 source. `search(["RETURN", "(COUNT)", "ALL"])` sends the command but returns `[]` (the `ESEARCH` response is dropped). The private `_raw_command_untagged(b"SEARCH", [b"RETURN", b"(COUNT)", b"ALL"], response_name="ESEARCH")` returns the data (duplicated in the list) |
| 16 | Verbs emitted by `select_folder(readonly=True)` and `login` | VERIFIED | `EXAMINE` and `LOGIN`; `readonly=False` emits `SELECT` (blocked). imapclient also issues extra `CAPABILITY` commands |
| 17 | Linux `RLIMIT_AS` in the worker | VERIFIED | 512 MiB cap: `import pypdf` fine (VmPeak about 50 MB); 64 MiB allocations raised `MemoryError` after 7; without the cap 2.5 GiB succeeded; a single 1 GiB `bytearray` raised `MemoryError`. The parent survived (child exit 3) |
| 18 | Windows job object; macOS `RLIMIT_AS` | not run here | |

### Wire survey (3.14, login through logout)

`CAPABILITY, LOGIN, CAPABILITY, CAPABILITY, NAMESPACE, LIST, STATUS, EXAMINE, UID SEARCH, UID SORT, UID THREAD, UID FETCH, NOOP, ID, UNSELECT, LOGOUT`. The `send` guard saw all 16; `_command` saw 13.

### pypdf 7.2.0

- `pypdf.Configuration` is a frozen dataclass; `overwrite_configuration(configuration=None, **overwrites)`, `apply_configuration(...)` (context manager) and `get_configuration()` exist and are exported from `pypdf`.
- Fields present (default): `maximum_declared_stream_length`, `zlib_`/`lzw_`/`run_length_`/`jbig2_`/`brotli_maximum_output_length`, `array_based_stream_maximum_output_length` and `image_maximum_buffer_size` (all 75 MB), `stream_decoding_work_maximum_length` 300 MB, `stream_filters_maximum_length` 16, `stream_parsing_work_maximum_count` 2M, `xform_maximum_invocations_per_extraction` 5000, `page_tree_maximum_entries` 100k, `page_tree_maximum_depth` 100, `page_tree_maximum_page_entries` 2M, `embedded_files_maximum_count` 1000, `embedded_files_maximum_output_length` 250 MB, `zlib_maximum_recovery_input_length` 5 MB, `flate_maximum_columns`, `flate_maximum_row_length`, `array_`/`dictionary_maximum_element_count` 100k, plus outline, form field, named destination, annotation and XMP caps. Read the rest from `dataclasses.fields(Configuration)`.
- `PdfReader(stream, strict=False, password=None, *, root_object_recovery_limit=10000, xref_stream_maximum_entries=2000000, xref_rebuild_maximum_entries=2000000)`.
- Module-level `*_MAX_*` constants in `pypdf.filters` still exist (deprecated); not used.
- No page-count or extracted-text cap: the worker loops pages itself.
- A 200 MB deflate stream in a page content stream (about 190 KB file, with `/Resources` and a font): `page.extract_text()` raised `pypdf.errors.LimitReachedError` at the default caps, with `strict=True`, and at lowered caps (`zlib_maximum_output_length` 1 MB); `page.get_contents()` raised it too; a control page returned its text. The configuration is honoured. A first attempt without `/Resources` returned `""` silently without decoding, so bomb fixtures need a complete page.
- T-06 fixtures: assert `LimitReachedError` maps to `limit_exceeded`.

## Decisions for A§10

1. Item 1: one guard mixin for both `IMAP4WithTimeout` and `IMAP4_TLS`, returned from an `IMAPClient._create_IMAP4` override that branches on `self.ssl`, mirrors the upstream constructor arguments and refuses `self.stream`.
   - Commands: `_new_tag` arms a flag; the first `send` after it must parse as `tag [UID] VERB` and is checked against the allowlist and the FETCH items before any byte is written. `_command` is also overridden (earlier, clearer error) but is not the guarantee.
   - `send(b"DONE\r\n")`: refused unless IDLE is enabled and active.
   - Reads: `read(size)` aborts over L-02 and over the per-command total (reset in `_new_tag`). Line cap through `imaplib._MAXLINE` set from L-20; L-20's 1 MiB is above the stdlib 1,000,000, so set it explicitly. Line overflow raises `error`, not `abort`: treat both as fatal and discard the session.
   - STARTTLS: override `_command_complete`; probe `_readbuf` (3.14) or `file.peek(1)` (<=3.13), then `MSG_PEEK`, restoring the socket timeout.
   - The fallback (own socket wrapper) is not needed, but this uses private imapclient/imaplib API: pin imapclient and run the wire-survey and STARTTLS tests in CI on 3.11 and 3.14.
2. Item 2: not exposed; not used. Plain `UID SEARCH`.
3. Item 10:
   - Linux: `RLIMIT_AS` set inside the worker (verified). `RLIMIT_CPU` was not exercised.
   - Windows job object and macOS: not run here; the A§10.10 design and fallback stand.
   - All OSes: set `pypdf.Configuration` limits from `limits.py` at worker start; page and char caps in the worker; `LimitReachedError` maps to `limit_exceeded`.
4. Vetting: imapclient 4.3.0 and pypdf 7.2.0 are BSD-3; advisory and maintenance status are out of this spike's scope.

## Contradictions

- A§10.1, A§6 (hook point), T-10: the guard cannot sit on `_command` alone; `APPEND` and the SEARCH/SORT/THREAD family bypass it. The hook is `_new_tag` plus `send`. The T-10 recording-fake-server proof must compare the wire against the allowlist, not the guard's own log.
- A§2.2 and T-07: "imaplib's `starttls()` drops such bytes silently" holds on 3.11-3.13 only; on 3.14 they are kept and parsed inside the TLS session, and the earlier `file.peek` probe fails there. Suggested wording: "`starttls()` neither detects them nor discards them reliably; a guarded `_command_complete` checks the read buffer."
- L-20 (1 MiB) is above the stdlib `_MAXLINE` (1,000,000): the effective cap is smaller unless `imaplib._MAXLINE` is set.
- T-03: imapclient sets `_imap.debug = 5` on every connection and routes it to the `imapclient.imaplib` logger (every line, including fetched content). Its adapter redacts `LOGIN` and `AUTHENTICATE` command lines (observed: `LOGIN **REDACTED**`, the test password never appeared); AUTHENTICATE continuation lines were not exercised. T-03's "imaplib's debug output is never enabled" needs the override to reset `_imap.debug = 0` after construction, or the logger kept above DEBUG.

## Throwaway appendix

Run: `UV_PYTHON=<ver> uv run --no-project --with imapclient --with pytest python -I -m pytest -q -s test_v1_hook.py` (needs `openssl` for a throwaway certificate; `REPORT` lines are the evidence above). Not for `tests/`.

### test_v1_hook.py

~~~python
# test_v1_hook.py  (throwaway; 127.0.0.1 fakes only)
import imaplib
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
    _expect = False
    _idling = False
    _budget = 0

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
        self._expect = True
        self._budget = 0
        return super()._new_tag()

    def send(self, data):
        if self.guard_send:
            if self._expect:
                self._expect = False
                m = CMD.match(data)
                if not m:
                    raise ReadOnlyViolation("unparseable command line")
                verb = m.group(3).decode().upper()
                if m.group(2):
                    self._rec("send_seen", f"UID {verb}")
                    self._vet("UID", verb)
                else:
                    self._rec("send_seen", verb)
                    self._vet(verb, None)
                if self.strict and verb == "FETCH" and SEEN_ITEMS.search(data):
                    raise ReadOnlyViolation("FETCH item sets \\Seen")
                self._idling = verb == "IDLE"
            elif data == b"DONE\r\n":
                if self.strict and not (self.allow_idle and self._idling):
                    raise ReadOnlyViolation("DONE")
                self._rec("send_seen", "DONE")
                self._idling = False
        return super().send(data)

    def _charge(self, n):
        self._budget += n
        if self._budget > MAX_RESPONSE:
            raise self.abort(f"response over {MAX_RESPONSE}")

    def read(self, size):
        if self.strict and size > MAX_LITERAL:
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
    def __init__(self, mode="normal", ctx=None, implicit=False, size=5000):
        self.mode, self.ctx, self.implicit, self.size = mode, ctx, implicit, size
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
            elif verb == "IDLE":
                c.sendall(b"+ idling\r\n")
                if f.readline().strip() == b"DONE":
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


def test_line_cap_via_module_maxline():
    old = imaplib._MAXLINE
    imaplib._MAXLINE = 5000
    try:
        s, c = opened("longline")
        with pytest.raises(Exception) as ei:
            c.noop()
        report("endless line with _MAXLINE=5000 raised", f"{type(ei.value).__module__}.{type(ei.value).__name__}: {str(ei.value)[:60]}")
        rb = getattr(c._imap, "_readbuf", None)
        if rb is not None:
            report("bytes buffered at error", sum(map(len, rb)))
        report("server completed 2000000-byte write", s.sent.wait(1.0))
    finally:
        imaplib._MAXLINE = old


def test_line_cap_default_maxline_error_type():
    s, c = opened("longline")
    with pytest.raises(Exception) as ei:
        c.noop()
    report("endless line, default _MAXLINE, raised", f"{type(ei.value).__module__}.{type(ei.value).__name__}: {str(ei.value)[:60]}")
    rb = getattr(c._imap, "_readbuf", None)
    if rb is not None:
        report("bytes buffered at error (default)", sum(map(len, rb)))


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
    st._readbuf = [] if sys.version_info >= (3, 14) else None
    st.file = a.makefile("rb")
    a.settimeout(7.0)
    assert st._pending() is False
    assert a.gettimeout() == 7.0
    b.sendall(b"* injected\r\n")
    time.sleep(0.05)
    assert st._pending() is True
    assert a.gettimeout() == 7.0
    if sys.version_info >= (3, 14):
        st._readbuf = [b"x"]
        assert st._readbuf_pending() is True


def test_imapclient_debug_logging_leaks_login_password():
    import logging
    records = []

    class H(logging.Handler):
        def emit(self, rec):
            records.append(rec.getMessage())

    lg = logging.getLogger("imapclient.imaplib")
    h = H()
    lg.addHandler(h)
    lg.setLevel(logging.DEBUG)
    try:
        s, c = connect()
        c.login("user@example.com", "S3cretPw")
    finally:
        lg.removeHandler(h)
    leaked = [r for r in records if "S3cretPw" in r]
    report("imapclient.imaplib DEBUG records containing the password", len(leaked))
    report("records total / LOGIN records", (len(records), [r for r in records if "LOGIN" in r][:2]))
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
