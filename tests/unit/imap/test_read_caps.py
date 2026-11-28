"""T-08: limits enforced on read, lines and literals, per command (A§2.2, L-20, L-26)."""

from __future__ import annotations

import gc
import imaplib
import tracemalloc
from typing import Any

import pytest

from mailferret.imap import (
    CommandCaps,
    HookBypassed,
    LimitBreach,
    LiteralItem,
    ReadOnlySession,
    fetch_caps,
    max_messages,
)
from mailferret.imap.caps import default_caps, unclamped_total
from mailferret.limits import KIB, LINE_OVERHEAD_BYTES, MIB, Limits
from tests.support.imap_fake import FakeImapServer, Flood, Literal
from tests.unit.imap.conftest import Opener
from tests.unit.imap.support import arm, make_sink

OK = "{tag} OK done\r\n"
# Worst measured ratio of peak traced bytes to the total (nested tokens), times a margin of 1.5.
MEASURED_AMPLIFICATION = 27.6
AMPLIFICATION_BUDGET = MEASURED_AMPLIFICATION * 1.5


def _logged_in(server: FakeImapServer, opener: Opener, limits: Limits | None = None) -> Any:
    server.on("EXAMINE", [b"* 3 EXISTS\r\n* OK [UIDVALIDITY 7] ok\r\n", OK])
    session = opener(server, limits)
    session.login("user@example.com", "secret")
    session.examine("INBOX")
    return session


@pytest.fixture
def read_calls(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Sizes imaplib itself was asked to read: a literal over the cap must never appear."""
    calls: list[int] = []
    real = imaplib.IMAP4.read

    def counting(self: imaplib.IMAP4, size: int) -> bytes:
        calls.append(size)
        return real(self, size)

    monkeypatch.setattr(imaplib.IMAP4, "read", counting)
    return calls


def _message(n: int, size: int) -> Literal:
    return Literal(size, prefix=b"* %d FETCH (UID %d BODY[HEADER] " % (n, n))


def test_a_literal_over_the_cap_is_never_pulled(
    server: FakeImapServer, opener: Opener, read_calls: list[int]
) -> None:
    server.on("UID FETCH", [Literal(3 * MIB), OK])
    session = _logged_in(server, opener)
    caps = CommandCaps(literal_cap=1000, total=10 * MIB, limit="L-02")
    read_calls.clear()
    with pytest.raises(LimitBreach) as err:
        session.fetch([1], ["BODY.PEEK[1]"], caps=caps)
    assert (err.value.kind, err.value.limit) == ("literal_over_cap", "L-02")
    assert read_calls == []
    assert not session.usable


def test_literals_each_under_the_cap_abort_on_the_crossing_one(
    server: FakeImapServer, opener: Opener, read_calls: list[int]
) -> None:
    server.on("UID FETCH", [_message(1, 800), _message(2, 800), _message(3, 800), OK])
    session = _logged_in(server, opener)
    per_message = 800 + 2 * LINE_OVERHEAD_BYTES + 60
    caps = CommandCaps(literal_cap=1000, total=2 * per_message + 100, limit="L-02")
    read_calls.clear()
    with pytest.raises(LimitBreach) as err:
        session.fetch([1, 2, 3], ["BODY.PEEK[HEADER]"], caps=caps)
    assert (err.value.kind, err.value.limit) == ("response_over_total", "L-26")
    assert read_calls == [800, 800]


def test_a_response_within_its_total_completes(server: FakeImapServer, opener: Opener) -> None:
    server.on("UID FETCH", [_message(1, 800), _message(2, 800), OK])
    session = _logged_in(server, opener)
    limits = Limits()
    result = session.fetch(
        [1, 2], ["BODY.PEEK[HEADER]"], caps=fetch_caps(limits, LiteralItem.HEADER, 2)
    )
    assert sorted(result) == [1, 2]
    assert session.usable


def test_a_batch_sized_by_the_batch_layer_with_every_message_at_its_cap_completes(
    server: FakeImapServer, opener: Opener
) -> None:
    limits = Limits(
        max_header_bytes=2 * KIB, max_line_bytes=8 * KIB, max_command_response_bytes=MIB
    )
    n = max_messages(limits, LiteralItem.HEADER)
    assert n >= 5
    server.on("UID FETCH", [*(_message(i, 2 * KIB) for i in range(1, n + 1)), OK])
    session = _logged_in(server, opener, limits)
    result = session.fetch(
        list(range(1, n + 1)),
        ["BODY.PEEK[HEADER]"],
        caps=fetch_caps(limits, LiteralItem.HEADER, n),
    )
    assert len(result) == n


def test_a_line_over_l20_is_a_typed_breach_not_imaplibs_abort(
    server: FakeImapServer, opener: Opener
) -> None:
    server.on("NOOP", [Flood(100_000, terminate=True), OK])
    session = _logged_in(server, opener, Limits(max_line_bytes=4 * KIB))
    assert imaplib._MAXLINE == 4 * KIB  # type: ignore[attr-defined]
    with pytest.raises(LimitBreach) as err:
        session.noop()
    assert (err.value.kind, err.value.limit) == ("line_over_limit", "L-20")
    assert not session.usable


def test_the_readline_hook_checks_l20_even_if_imaplib_ignores_maxline(
    server: FakeImapServer, opener: Opener, monkeypatch: pytest.MonkeyPatch
) -> None:
    server.on("NOOP", [Flood(100_000, terminate=True), OK])
    session = _logged_in(server, opener, Limits(max_line_bytes=4 * KIB))
    monkeypatch.setattr(imaplib, "_MAXLINE", 10**9)
    with pytest.raises(LimitBreach) as err:
        session.noop()
    assert err.value.kind == "line_over_limit"


def _flood(count: int, data: str = "") -> bytes:
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return b"".join(
        f"* {''.join(letters[(i // 26**k) % 26] for k in range(4))}{data}\r\n".encode()
        for i in range(count)
    )


def test_a_flood_of_distinct_untagged_types_aborts_at_the_total_within_the_memory_budget(
    server: FakeImapServer, opener: Opener
) -> None:
    total = 2 * MIB
    server.on("NOOP", [_flood(60_000), OK])
    session = _logged_in(server, opener, Limits(max_command_response_bytes=total))
    gc.collect()
    tracemalloc.start()
    try:
        before = tracemalloc.get_traced_memory()[0]
        with pytest.raises(LimitBreach) as err:
            session.noop()
        gc.collect()
        retained = tracemalloc.get_traced_memory()[0] - before
    finally:
        tracemalloc.stop()
    assert err.value.kind == "response_over_total"
    kept = sum(len(v) for v in session._imap.untagged_responses.values())
    assert 0 < kept < 60_000
    assert retained <= total


def test_a_flood_spread_over_several_commands_stays_within_one_total(
    server: FakeImapServer, opener: Opener
) -> None:
    server.on("NOOP", [_flood(3_000), OK])
    session = _logged_in(server, opener)
    for _ in range(8):
        session.noop()
        assert sum(len(v) for v in session._imap.untagged_responses.values()) <= 3_100


def test_untagged_responses_are_reset_in_new_tag() -> None:
    imap = make_sink()
    imap.untagged_responses["EXISTS"] = [b"3"]
    arm(imap)
    assert imap.untagged_responses == {}


def test_what_imapclient_reads_after_a_command_survives_until_the_next_one(
    server: FakeImapServer, opener: Opener
) -> None:
    server.on("NOOP", [b"* 4 EXISTS\r\n", OK])
    session = _logged_in(server, opener)
    session.noop()
    assert session._imap.untagged_responses.get("EXISTS") == [b"4"]
    session.noop()
    assert session._imap.untagged_responses.get("EXISTS") == [b"4"]
    server.on("CAPABILITY", ["* CAPABILITY IMAP4rev1\r\n", OK])
    session._client._imap._new_tag()
    assert "EXISTS" not in session._imap.untagged_responses


@pytest.mark.parametrize("token", [b"\\a ", b"(a) ", b"NIL "])
def test_dense_token_fetch_parse_stays_within_a_multiple_of_the_total(
    server: FakeImapServer, opener: Opener, token: bytes
) -> None:
    """imapclient turns each token into objects: the parse amplifies the wire bytes.

    A FETCH response at its total, made of the densest tokens, is parsed by imapclient; the peak
    must stay under ``AMPLIFICATION_BUDGET`` times the total. The PR reports the measured ratio
    and the worst case it implies at the `L-26` ceiling.
    """
    total = 2 * MIB
    line = b"* %d FETCH (UID %d FLAGS (" + token * ((total // 2 - 2_000) // len(token)) + b"))\r\n"
    server.on("UID FETCH", [line % (1, 1), line % (2, 2), OK])
    limits = Limits(max_line_bytes=MIB, max_command_response_bytes=total)
    session = _logged_in(server, opener, limits)
    caps = CommandCaps(literal_cap=limits.max_header_bytes, total=total, limit="L-05")
    gc.collect()
    tracemalloc.start()
    try:
        baseline = tracemalloc.get_traced_memory()[0]
        tracemalloc.reset_peak()
        result = session.fetch([1, 2], ["FLAGS"], caps=caps)
        peak = tracemalloc.get_traced_memory()[1] - baseline
    finally:
        tracemalloc.stop()
    assert sorted(result) == [1, 2]
    assert peak <= AMPLIFICATION_BUDGET * total, f"parse amplification {peak / total:.1f}x"


def test_a_read_that_bypasses_the_hook_is_caught_at_the_next_line() -> None:
    """A ``{n}`` literal that did not go through ``read(n)``: abort before any further command."""
    imap = make_sink(incoming=[b"* 1 FETCH (UID 1 BODY[] {5}\r\n", b")\r\n"])
    arm(imap)
    imap.readline()
    with pytest.raises(HookBypassed) as err:
        imap.readline()
    assert err.value.check == "literal_read"
    assert imap.discarded


def test_a_read_of_the_wrong_size_is_caught() -> None:
    imap = make_sink(incoming=[b"* 1 FETCH (UID 1 BODY[] {5}\r\n", b"abcde"])
    arm(imap)
    imap.readline()
    with pytest.raises(HookBypassed):
        imap.read(4)


def test_a_read_without_an_announced_literal_is_caught() -> None:
    imap = make_sink(incoming=[b"* OK hi\r\n", b"abcde"])
    arm(imap)
    imap.readline()
    with pytest.raises(HookBypassed):
        imap.read(5)


def test_a_tagged_line_ending_in_a_brace_is_not_a_literal() -> None:
    imap = make_sink(incoming=[b"A0 OK took {5}\r\n", b"+ ready {3}\r\n", b"A9 OK done\r\n"])
    tag = arm(imap)
    imap._mf.vetted.add(tag)
    imap.readline()
    imap.readline()
    assert imap._mf.pending_literal is None


def test_a_literal_chain_is_followed_through_its_trailer() -> None:
    imap = make_sink(
        incoming=[b"* 1 FETCH (BODY[1] {3}\r\n", b"abc", b" BODY[2] {2}\r\n", b"de", b")\r\n"]
    )
    arm(imap)
    imap.readline()
    imap.read(3)
    imap.readline()
    assert imap._mf.pending_literal == 2
    imap.read(2)
    imap.readline()
    assert imap._mf.pending_literal is None


def test_the_unvetted_tag_tripwire_fires_on_a_foreign_tagged_completion() -> None:
    imap = make_sink(incoming=[b"A7 OK sneaked\r\n"])
    arm(imap)
    with pytest.raises(HookBypassed) as err:
        imap.readline()
    assert err.value.check == "unvetted_tag"


def test_caps_helpers_follow_the_formula_and_clamp_to_l26() -> None:
    limits = Limits()
    one = fetch_caps(limits, LiteralItem.PART, 1)
    assert one.literal_cap == limits.max_part_bytes and one.limit == "L-02"
    assert one.total == limits.max_part_bytes + 2 * limits.max_line_bytes
    assert fetch_caps(limits, None, 3).total == 4 * limits.max_line_bytes
    assert fetch_caps(limits, None, 3).limit == "L-05"
    full = fetch_caps(limits, LiteralItem.MESSAGE, 1)
    assert full.total == limits.max_command_response_bytes
    assert fetch_caps(limits, LiteralItem.MESSAGE, 50).total == limits.max_command_response_bytes
    assert default_caps(limits).total == limits.max_command_response_bytes
    assert (
        unclamped_total(limits, LiteralItem.HEADER, 2)
        == 2 * (limits.max_header_bytes + limits.max_line_bytes) + limits.max_line_bytes
    )
    with pytest.raises(ValueError, match="at least one"):
        fetch_caps(limits, None, 0)


def test_a_lowered_l01_or_l20_lowers_the_total_and_the_batch() -> None:
    lowered = Limits(max_message_bytes=MIB, max_line_bytes=64 * KIB)
    assert fetch_caps(lowered, LiteralItem.MESSAGE, 1).total == MIB + 2 * 64 * KIB
    assert max_messages(Limits(), LiteralItem.MESSAGE) == 1
    assert max_messages(lowered, LiteralItem.MESSAGE) > max_messages(Limits(), LiteralItem.MESSAGE)
    tiny = Limits(max_message_bytes=MIB, max_command_response_bytes=MIB)
    assert max_messages(tiny, LiteralItem.MESSAGE) == 0


def test_caps_apply_to_one_command_only(server: FakeImapServer, opener: Opener) -> None:
    server.on("UID FETCH", [_message(1, 800), OK])
    session = _logged_in(server, opener)
    small = CommandCaps(literal_cap=10, total=MIB, limit="L-05")
    with pytest.raises(LimitBreach):
        session.fetch([1], ["BODY.PEEK[HEADER]"], caps=small)
    other = _logged_in(server, opener)
    other.fetch([1], ["BODY.PEEK[HEADER]"], caps=fetch_caps(Limits(), LiteralItem.HEADER, 1))
    assert isinstance(other, ReadOnlySession)


def test_a_completion_for_an_unvetted_tag_aborts_in_command_complete() -> None:
    """The tripwire in ``_command_complete`` on its own, not only the one in ``readline``."""
    imap = make_sink()
    tag = arm(imap)
    with pytest.raises(HookBypassed) as err:
        imap._command_complete("NOOP", tag)
    assert err.value.check == "unvetted_tag"
    assert imap.discarded
