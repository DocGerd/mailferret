"""R1, R2, T-10: the send gate, driven through ``_new_tag`` + ``send`` as imapclient does.

Each denial raises ``ReadOnlyViolation`` before a byte is sent, so ``sink.sent`` stays empty.
A vet placed in ``_command`` would not catch any of these: none goes through it.
"""

from __future__ import annotations

import pytest

from mailferret.imap import ReadOnlyViolation
from mailferret.imap.errors import VIOLATION_MESSAGES
from tests.unit.imap.support import Sink, arm, line, make_sink

CRLF = b"\r\n"


def _denied(imap: Sink, *sends: bytes, reason: str | None = None) -> None:
    for data in sends[:-1]:
        imap.send(data)
    sent = list(imap.sent)
    with pytest.raises(ReadOnlyViolation) as err:
        imap.send(sends[-1])
    assert imap.sent == sent
    if reason is not None:
        assert err.value.reason == reason
    assert err.value.__context__ is None


@pytest.mark.parametrize(
    "command",
    [
        b"SELECT INBOX",
        b"STORE 1 +FLAGS (\\Seen)",
        b"UID STORE 1 +FLAGS (\\Seen)",
        b"COPY 1 Archive",
        b"UID COPY 1 Archive",
        b"MOVE 1 Archive",
        b"UID MOVE 1 Archive",
        b"EXPUNGE",
        b"UID EXPUNGE 1",
        b"APPEND INBOX {5}",
        b"CREATE X",
        b"DELETE X",
        b"RENAME X Y",
        b"SUBSCRIBE X",
        b"UNSUBSCRIBE X",
        b"SETACL X me lrswi",
        b"ENABLE UTF8=ACCEPT",
        b"IDLE",
        b"DONE",
        b"XLIST",
        b"UID",
        b"UID  FETCH 1 (UID)",
        b"uid store 1 +flags (\\Seen)",
        b"FETCHX 1 (UID)",
    ],
)
def test_denied_verbs_raise_before_any_byte(command: bytes) -> None:
    imap = make_sink()
    tag = arm(imap)
    _denied(imap, line(tag, command + CRLF))
    assert imap.sent == []


@pytest.mark.parametrize(
    "command",
    [
        b"CAPABILITY",
        b"NOOP",
        b"LOGOUT",
        b"STARTTLS",
        b'LOGIN "user" "pass"',
        b"ID NIL",
        b"NAMESPACE",
        b'LIST "" "*"',
        b'LSUB "" "*"',
        b'STATUS "INBOX" (MESSAGES)',
        b'EXAMINE "INBOX"',
        b"CLOSE",
        b"UNSELECT",
        b"SEARCH ALL",
        b"UID SEARCH ALL",
        b"UID SORT (REVERSE DATE) UTF-8 ALL",
        b"UID THREAD REFERENCES UTF-8 ALL",
        b"UID fetch 1 (UID)",
    ],
)
def test_allowed_verbs_pass(command: bytes) -> None:
    imap = make_sink()
    tag = arm(imap)
    imap.send(line(tag, command + CRLF))
    assert imap.sent == [line(tag, command + CRLF)]


@pytest.mark.parametrize(
    "items",
    [
        b"(UID)",
        b"UID",
        b"(UID FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODYSTRUCTURE RFC822.HEADER)",
        b"(BODY.PEEK[])",
        b"(BODY.PEEK[]<0.1024>)",
        b"(BODY.PEEK[HEADER])",
        b"(BODY.PEEK[TEXT])",
        b"(BODY.PEEK[1])",
        b"(BODY.PEEK[1.2.MIME])",
        b"(BODY.PEEK[1.2.TEXT]<0.512>)",
        b"(UID BODY.PEEK[HEADER.FIELDS (From To Delivered-To)])",
        b'(BODY.PEEK[HEADER.FIELDS.NOT ("X-Spam" Subject)])',
        b"(body.peek[header.fields (from)])",
    ],
)
@pytest.mark.parametrize("prefix", [b"FETCH 1:*", b"UID FETCH 1,3:5"])
def test_fetch_items_allowlist_passes(prefix: bytes, items: bytes) -> None:
    imap = make_sink()
    tag = arm(imap)
    imap.send(line(tag, prefix + b" " + items + CRLF))
    assert len(imap.sent) == 1


@pytest.mark.parametrize(
    "items",
    [
        b"(BODY[])",
        b"(BODY[HEADER])",
        b"(UID BODY[1])",
        b"(BODY)",
        b"BODY",
        b"(RFC822)",
        b"RFC822",
        b"(RFC822.TEXT)",
        b"(BINARY[])",
        b"(BINARY.PEEK[])",
        b"(BINARY.SIZE[1])",
        b"(X-GM-LABELS)",
        b"(MODSEQ)",
        b"ALL",
        b"FAST",
        b"FULL",
        b"(UID) (CHANGEDSINCE 1)",
        b"(UID BODY.PEEK[] BODY[])",
        b"(UID)x",
        b"(BODY.PEEK[HEADER.FIELDS (From)]x)",
        b"(BODY.PEEK[HEADER.FIELDS ()])",
        b"(BODY.PEEK[]<0.1> BODY[])",
        b"(UID BODY.PEEK[1.])",
        b"(UID BODY.PEEK[0])",
        b"()",
        b"",
    ],
)
def test_fetch_items_outside_the_allowlist_are_denied(items: bytes) -> None:
    imap = make_sink()
    tag = arm(imap)
    _denied(imap, line(tag, b"UID FETCH 1 " + items + CRLF), reason="fetch_item_not_allowed")


def test_a_bare_tagged_line_through_send_is_denied() -> None:
    imap = make_sink()
    _denied(imap, b"A9 UID STORE 1 +FLAGS (\\Seen)\r\n", reason="send_outside_command")


def test_a_line_with_another_tag_is_denied() -> None:
    imap = make_sink()
    arm(imap)
    _denied(imap, b"A99 NOOP\r\n", reason="foreign_tag")


@pytest.mark.parametrize(
    "tail",
    [
        b"NOOP\r\nA2 UID STORE 1 +FLAGS (\\Seen)\r\n",
        b"NOOP\nA2 NOOP\r\n",
        b"NOOP\rA2 NOOP\r\n",
        b"NOOP\r\n\r\n",
    ],
)
def test_a_line_break_inside_the_armed_line_is_denied(tail: bytes) -> None:
    imap = make_sink()
    tag = arm(imap)
    _denied(imap, line(tag, tail), reason="line_break_in_command")


@pytest.mark.parametrize("junk", [b"\x00", b"\x01", b"\x7f", b"\xc3\xa9", b"\x1b"])
def test_control_and_8bit_bytes_in_a_command_line_are_denied(junk: bytes) -> None:
    imap = make_sink()
    tag = arm(imap)
    _denied(imap, line(tag, b'SEARCH TEXT "a' + junk + b'"\r\n'), reason="illegal_bytes")


def test_a_login_with_an_embedded_crlf_carries_none_of_its_bytes() -> None:
    secret = b"hunter2-CANARY"
    imap = make_sink()
    tag = arm(imap)
    with pytest.raises(ReadOnlyViolation) as err:
        imap.send(line(tag, b'LOGIN "user" "' + secret + b'"\r\nA2 NOOP\r\n'))
    shown = repr(err.value) + str(err.value) + repr(err.value.args) + repr(err.value.reason)
    assert secret.decode() not in shown
    assert err.value.args[0] in VIOLATION_MESSAGES.values()
    assert imap.sent == []


def test_a_non_bytes_send_is_denied() -> None:
    imap = make_sink()
    arm(imap)
    with pytest.raises(ReadOnlyViolation):
        imap.send("A1 NOOP\r\n")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "first",
    [
        b"UID FETCH 1 (FLAGS",
        b"UID FETCH 1 (UID)",
        b"FETCH 1 (UID)",
    ],
)
def test_an_unterminated_fetch_is_denied(first: bytes) -> None:
    """The fragments ``UID FETCH 1 (FLAGS`` then `` BODY[])`` never get to complete."""
    imap = make_sink()
    tag = arm(imap)
    _denied(imap, line(tag, first))
    assert imap.sent == []


def test_the_fetch_fragment_attack_is_stopped_at_the_second_send() -> None:
    imap = make_sink()
    tag = arm(imap)
    with pytest.raises(ReadOnlyViolation):
        imap.send(line(tag, b"UID FETCH 1 (FLAGS"))
    imap._mf.dead = False  # isolate the gate: it must still be armed, so a fragment is a line
    _denied(imap, b" BODY[])\r\n", reason="foreign_tag")


@pytest.mark.parametrize(
    "announcement",
    [
        b"{5}\r\n",
        b"{5+}\r\n",
        b"({5}\r\n",
        b"({5+}\r\n",
        b"(UID BODY.PEEK[HEADER.FIELDS {5}\r\n",
        b"BODY.PEEK[HEADER.FIELDS ({5+}\r\n",
    ],
)
@pytest.mark.parametrize("verb", [b"FETCH 1 ", b"UID FETCH 1 "])
def test_a_literal_inside_a_fetch_is_denied(verb: bytes, announcement: bytes) -> None:
    imap = make_sink()
    tag = arm(imap)
    _denied(imap, line(tag, verb + announcement))


@pytest.mark.parametrize("verb", [b"LOGIN user {5}\r\n", b'LIST "" {3}\r\n', b"NOOP {1}\r\n"])
def test_a_literal_in_a_command_that_may_not_carry_one_is_denied(verb: bytes) -> None:
    imap = make_sink()
    tag = arm(imap)
    _denied(imap, line(tag, verb), reason="literal_in_command")


@pytest.mark.parametrize(
    "verb", [b"SEARCH", b"UID SEARCH", b"UID SORT (DATE) UTF-8", b"UID THREAD REFERENCES UTF-8"]
)
def test_literal_plus_is_refused_in_search_sort_and_thread(verb: bytes) -> None:
    """Refused whether or not the server advertised LITERAL+: the gate never looks."""
    imap = make_sink()
    tag = arm(imap)
    imap.send(line(tag, verb + b" TEXT"))
    _denied(imap, b" {8+}\r\n", reason="literal_plus_refused")
    assert imap.sent == [line(tag, verb + b" TEXT")]


def test_the_issue_7_probe_never_reaches_the_wire_as_a_command() -> None:
    """A SEARCH whose literal carries ``UID STORE ... \\Seen``."""
    probe = b"x\r\nA9 UID STORE 1:* +FLAGS (\\Seen)\r\n"
    plus = make_sink()
    tag = arm(plus)
    plus.send(line(tag, b"UID SEARCH TEXT"))
    _denied(plus, b" {%d+}\r\n" % len(probe) + probe)
    assert probe not in b"".join(plus.sent)

    sync = make_sink(incoming=[b"A0 BAD no literals\r\n"])
    tag = arm(sync)
    sync.send(line(tag, b"UID SEARCH TEXT"))
    sync.send(b" {%d}\r\n" % len(probe))
    sync.readline()  # the server answered the announcement with a tagged BAD
    sync._mf.tag = tag
    _denied(sync, probe, reason="send_outside_command")
    assert probe not in b"".join(sync.sent)


def test_a_sync_literal_is_sent_only_after_the_continuation() -> None:
    literal = b"caf\xc3\xa9"
    imap = make_sink(incoming=[b"+ go ahead\r\n"])
    tag = arm(imap)
    imap.send(line(tag, b"UID SEARCH CHARSET UTF-8 SUBJECT"))
    imap.send(b" {5}\r\n")
    _denied(imap, literal, reason="literal_before_continuation")
    imap._mf.dead = False
    imap.readline()
    imap.send(literal)
    imap.send(b" ")
    imap.send(b"\r\n")
    assert b"".join(imap.sent).endswith(literal + b" \r\n")
    _denied(imap, b"A9 NOOP\r\n", reason="send_outside_command")


def test_literal_bytes_after_a_tagged_bad_are_denied() -> None:
    imap = make_sink(incoming=[b"A0 BAD literals refused\r\n"])
    tag = arm(imap)
    imap.send(line(tag, b"UID SEARCH SUBJECT"))
    imap.send(b" {5}\r\n")
    imap._mf.tag = tag
    imap.incoming[:] = [tag + b" BAD literals refused\r\n"]
    imap._mf.vetted.add(tag)
    imap.readline()
    _denied(imap, b"abcde", reason="send_outside_command")


def test_literal_bytes_of_the_wrong_length_are_denied() -> None:
    imap = make_sink(incoming=[b"+ go\r\n"])
    tag = arm(imap)
    imap.send(line(tag, b"UID SEARCH SUBJECT"))
    imap.send(b" {5}\r\n")
    imap.readline()
    _denied(imap, b"abcdef", reason="literal_length_mismatch")


def test_an_announcement_split_across_fragments_is_still_an_announcement() -> None:
    """``x{5}`` then CRLF makes the server wait for 5 bytes: it is gated like any literal."""
    imap = make_sink(incoming=[b"+ go\r\n"])
    tag = arm(imap)
    imap.send(line(tag, b"UID SEARCH TEXT x"))
    imap.send(b"{5}")
    imap.send(CRLF)
    _denied(imap, b"abcde", reason="literal_before_continuation")
    plus = make_sink()
    tag = arm(plus)
    plus.send(line(tag, b"UID SEARCH TEXT x"))
    plus.send(b"{5+}")
    _denied(plus, CRLF, reason="literal_plus_refused")
    lone = make_sink()
    tag = arm(lone)
    _denied(lone, line(tag, b"UID SEARCH TEXT x{5}"), reason="unterminated_command")


def test_a_fragment_with_a_line_break_is_denied() -> None:
    imap = make_sink()
    tag = arm(imap)
    imap.send(line(tag, b"UID SEARCH TEXT"))
    _denied(imap, b" x\r\nA2 NOOP\r\n", reason="line_break_in_command")


def test_a_search_may_be_completed_by_a_closing_crlf_only_once() -> None:
    imap = make_sink()
    tag = arm(imap)
    imap.send(line(tag, b"UID SEARCH ALL"))
    imap.send(CRLF)
    _denied(imap, CRLF, reason="send_outside_command")


@pytest.mark.parametrize("phase", ["open", "await", "literal", "auth"])
def test_new_tag_mid_command_is_denied(phase: str) -> None:
    imap = make_sink(incoming=[b"+ go\r\n"])
    tag = arm(imap)
    if phase == "open":
        imap.send(line(tag, b"UID SEARCH TEXT"))
    elif phase == "await":
        imap.send(line(tag, b"UID SEARCH TEXT"))
        imap.send(b" {2}\r\n")
    elif phase == "literal":
        imap.send(line(tag, b"UID SEARCH TEXT"))
        imap.send(b" {2}\r\n")
        imap.readline()
    else:
        imap.send(line(tag, b"AUTHENTICATE PLAIN\r\n"))
    with pytest.raises(ReadOnlyViolation) as err:
        imap._new_tag()
    assert err.value.reason == "command_in_flight"


def test_new_tag_after_a_failed_vet_re_arms_and_never_completes_the_old_line() -> None:
    imap = make_sink()
    tag = arm(imap)
    with pytest.raises(ReadOnlyViolation):
        imap.send(line(tag, b"UID FETCH 1 (FLAGS"))
    imap._mf.dead = False
    new = arm(imap)
    assert new != tag
    imap.send(line(new, b"NOOP\r\n"))


def test_authenticate_replies_are_matched_with_fullmatch() -> None:
    imap = make_sink()
    tag = arm(imap)
    imap.send(line(tag, b"AUTHENTICATE PLAIN\r\n"))
    imap.send(b"AGxvZ2luAHNlY3JldA==")
    imap.send(CRLF)
    imap.send(b"*")
    for bad in (b"AGx vZ2lu\r\n", b"A2 NOOP\r\n", b"AGxv\r\nA2 NOOP", b"\r\n\r\n", b"AG\x00"):
        _denied(imap, bad, reason="send_outside_command")
        imap._mf.dead = False


def test_bytes_after_a_completed_authenticate_are_denied() -> None:
    imap = make_sink(incoming=[b"A0 OK done\r\n"])
    tag = arm(imap)
    imap._mf.vetted.add(tag)
    imap.send(line(tag, b"AUTHENTICATE PLAIN\r\n"))
    imap.incoming[:] = [tag + b" OK authenticated\r\n"]
    imap.readline()
    _denied(imap, b"AGxvZ2luAHNlY3JldA==", reason="send_outside_command")
    imap._mf.dead = False
    _denied(imap, CRLF, reason="send_outside_command")


def test_a_denied_session_stays_dead_and_never_sends_again() -> None:
    imap = make_sink()
    tag = arm(imap)
    with pytest.raises(ReadOnlyViolation):
        imap.send(line(tag, b"STORE 1 +FLAGS (\\Seen)\r\n"))
    assert imap.discarded
    for action in (lambda: imap._new_tag(), lambda: imap.send(b"A1 NOOP\r\n")):
        with pytest.raises(ReadOnlyViolation) as err:
            action()
        assert err.value.reason == "session_discarded"
    assert imap.sent == []


def test_command_gives_a_clearer_error_but_is_not_the_guard() -> None:
    imap = make_sink()
    with pytest.raises(ReadOnlyViolation) as err:
        imap._command("STORE", "1", "+FLAGS", "(\\Seen)")
    assert err.value.reason == "verb_not_allowed"
    assert imap._mf.tag == b""  # nothing armed: refused before _new_tag
    other = make_sink()
    with pytest.raises(ReadOnlyViolation):
        other._command("UID", "STORE", "1")


_ZEROS = b"0" * 40
_PLUS_FORMS = [
    b"{5+}",
    b"{05+}",
    b"{00000000005+}",
    b"{" + _ZEROS + b"5+}",
    b"{" + b"0" * 5000 + b"5+}",
    b"{" + b"9" * 5000 + b"+}",
]


@pytest.mark.parametrize("announcement", _PLUS_FORMS)
def test_every_non_synchronising_announcement_is_refused_whatever_its_digits(
    announcement: bytes,
) -> None:
    armed = make_sink()
    tag = arm(armed)
    _denied(
        armed, line(tag, b"UID SEARCH TEXT " + announcement + CRLF), reason="literal_plus_refused"
    )
    fragment = make_sink()
    tag = arm(fragment)
    fragment.send(line(tag, b"UID SEARCH TEXT"))
    fragment.send(b" ")
    _denied(fragment, announcement + CRLF, reason="literal_plus_refused")


@pytest.mark.parametrize("announcement", _PLUS_FORMS)
def test_a_plus_announcement_split_across_many_sends_is_refused(announcement: bytes) -> None:
    imap = make_sink()
    tag = arm(imap)
    imap.send(line(tag, b"UID SEARCH TEXT x"))
    pieces = [announcement[i : i + 7] for i in range(0, len(announcement), 7)]
    for piece in pieces:
        imap.send(piece)
    _denied(imap, CRLF, reason="literal_plus_refused")
    assert CRLF not in b"".join(imap.sent)


def test_a_leading_zero_sync_announcement_is_the_literal_it_says() -> None:
    imap = make_sink(incoming=[b"+ go\r\n"])
    tag = arm(imap)
    imap.send(line(tag, b"UID SEARCH TEXT"))
    imap.send(b" {" + _ZEROS + b"5}\r\n")
    _denied(imap, b"abcde", reason="literal_before_continuation")
    imap._mf.dead = False
    imap.readline()
    imap.send(b"abcde")


@pytest.mark.parametrize("digits", [b"1" + b"0" * 10, b"9" * 5000])
def test_a_sync_announcement_too_large_to_be_real_is_refused_not_a_crash(digits: bytes) -> None:
    imap = make_sink()
    tag = arm(imap)
    imap.send(line(tag, b"UID SEARCH TEXT"))
    _denied(imap, b" {" + digits + b"}\r\n", reason="literal_length_mismatch")
    assert imap.discarded


def test_a_brace_that_is_not_at_the_line_end_is_not_an_announcement() -> None:
    imap = make_sink()
    tag = arm(imap)
    imap.send(line(tag, b"UID SEARCH TEXT {5+}x"))
    imap.send(b"{5+} ")
    imap.send(CRLF)
