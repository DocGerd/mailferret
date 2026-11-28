"""T-08: limits enforced on read, lines and literals, per command (A§2.2, L-20, L-26)."""

from __future__ import annotations

import gc
import imaplib
import tracemalloc
from collections.abc import Callable
from typing import Any

import pytest

from mailferret.imap import (
    CommandCaps,
    HookBypassed,
    LimitBreach,
    LiteralItem,
    ReadOnlySession,
    SessionError,
    fetch_caps,
    max_messages,
)
from mailferret.imap.caps import default_caps, unclamped_total
from mailferret.limits import (
    FETCH_LINE_ALLOWANCE_BYTES,
    KIB,
    LINE_OVERHEAD_BYTES,
    LIST_LINE_ALLOWANCE_BYTES,
    MIB,
    Limits,
)
from tests.support.imap_fake import FakeImapServer, Flood, Literal
from tests.unit.imap.conftest import Opener
from tests.unit.imap.support import arm, line, make_sink

OK = "{tag} OK done\r\n"


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
    caps = CommandCaps(literal_cap=1000, total=10 * MIB, limit="L-02", line_total=10 * MIB)
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
    caps = CommandCaps(
        literal_cap=1000, total=2 * per_message + 100, limit="L-02", line_total=10 * MIB
    )
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
    total = MIB
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


def _fetch_flood(unit: bytes, line_bytes: int, wire_bytes: int) -> list[bytes]:
    """Distinct-UID ``FLAGS (<unit>...)`` lines of ``line_bytes``, ``wire_bytes`` in all."""
    lines = []
    k = 1
    while sum(len(x) for x in lines) < wire_bytes:
        head, tail = b"* %d FETCH (UID %d FLAGS (" % (k, k), b"))\r\n"
        lines.append(head + unit * ((line_bytes - len(head) - len(tail)) // len(unit)) + tail)
        k += 1
    return lines


def _list_flood(line_bytes: int, wire_bytes: int) -> list[bytes]:
    line = b"* LIST " + b"%" * (line_bytes - 9) + b"\r\n"
    return [line] * (wire_bytes // len(line) + 1)


def _peak(call: Callable[[], Any]) -> tuple[int, SessionError | None]:
    gc.collect()
    tracemalloc.start()
    try:
        baseline = tracemalloc.get_traced_memory()[0]
        tracemalloc.reset_peak()
        failure: SessionError | None = None
        try:
            call()
        except SessionError as exc:
            failure = exc
        return tracemalloc.get_traced_memory()[1] - baseline, failure
    finally:
        tracemalloc.stop()


# The budget is a fixed memory figure, not a multiple fitted to a measurement: 256 MiB at the
# default L-32 (2.5 MiB), scaled to the lowered L-32 these tests run with.
BUDGET_PER_LINE_BYTE = 256 * MIB / (5 * MIB // 2)
REDUCED = Limits(
    max_line_bytes=64 * KIB,
    max_response_line_bytes=256 * KIB,
    max_command_response_bytes=16 * MIB,
)
SHAPES = [b"%", b"\x01", b"(a) ", b"\\a ", b"NIL "]


@pytest.mark.parametrize("unit", SHAPES)
def test_a_fetch_over_the_line_total_breaches_within_the_memory_budget(
    server: FakeImapServer, opener: Opener, unit: bytes
) -> None:
    """Dense short tokens: imapclient's parse amplifies lines, so the lines are capped (L-32)."""
    caps = fetch_caps(REDUCED, None, 4)
    server.on("UID FETCH", [*_fetch_flood(unit, 60 * KIB, 8 * MIB), OK])
    session = _logged_in(server, opener, REDUCED)
    peak, failure = _peak(lambda: session.fetch([1, 2, 3, 4], ["FLAGS"], caps=caps))
    assert isinstance(failure, LimitBreach)
    assert (failure.kind, failure.limit) == ("response_over_line_total", "L-32")
    assert peak <= BUDGET_PER_LINE_BYTE * REDUCED.max_response_line_bytes


@pytest.mark.parametrize("unit", SHAPES)
def test_a_fetch_just_under_the_line_total_parses_within_the_memory_budget(
    server: FakeImapServer, opener: Opener, unit: bytes
) -> None:
    caps = fetch_caps(REDUCED, None, 4)
    wire = _fetch_flood(unit, 40 * KIB, caps.line_total - 4 * LINE_OVERHEAD_BYTES - 40 * KIB)
    server.on("UID FETCH", [*wire, OK])
    session = _logged_in(server, opener, REDUCED)
    peak, failure = _peak(lambda: session.fetch([1, 2, 3, 4], ["FLAGS"], caps=caps))
    assert failure is None
    assert peak <= BUDGET_PER_LINE_BYTE * REDUCED.max_response_line_bytes


def test_a_list_over_the_line_total_breaches_within_the_memory_budget(
    server: FakeImapServer, opener: Opener
) -> None:
    server.on("LIST", [*_list_flood(60 * KIB, 8 * MIB), OK])
    session = _logged_in(server, opener, REDUCED)
    peak, failure = _peak(lambda: session.list_folders())
    assert isinstance(failure, LimitBreach)
    assert (failure.kind, failure.limit) == ("response_over_line_total", "L-32")
    assert peak <= BUDGET_PER_LINE_BYTE * REDUCED.max_response_line_bytes


def test_a_list_just_under_the_line_total_parses_within_the_memory_budget(
    server: FakeImapServer, opener: Opener
) -> None:
    line_total = default_caps(REDUCED).line_total
    server.on("LIST", [*_list_flood(40 * KIB, line_total - 100 * KIB), OK])
    session = _logged_in(server, opener, REDUCED)
    peak, failure = _peak(lambda: session.list_folders())
    assert not isinstance(failure, LimitBreach)  # imapclient may fail to parse it
    assert peak <= BUDGET_PER_LINE_BYTE * REDUCED.max_response_line_bytes


def test_literals_do_not_count_against_the_line_total(
    server: FakeImapServer, opener: Opener
) -> None:
    server.on("UID FETCH", [_message(1, 800 * KIB), OK])
    session = _logged_in(server, opener, REDUCED)
    caps = CommandCaps(
        literal_cap=MIB, total=2 * MIB, limit="L-05", line_total=REDUCED.max_response_line_bytes
    )
    assert session.fetch([1], ["BODY.PEEK[HEADER]"], caps=caps)


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
    small = CommandCaps(literal_cap=10, total=MIB, limit="L-05", line_total=MIB)
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


def test_a_second_tagged_line_for_a_completed_tag_trips_the_wire() -> None:
    """A completed tag leaves ``vetted`` as soon as its line is read, not only in the hook."""
    imap = make_sink()
    tag = arm(imap)
    imap.incoming[:] = [tag + b" OK done\r\n", tag + b" OK again\r\n"]
    imap.send(line(tag, b"NOOP\r\n"))
    imap.readline()
    assert tag not in imap._mf.vetted
    with pytest.raises(HookBypassed) as err:
        imap.readline()
    assert err.value.check == "unvetted_tag"


def test_line_totals_follow_the_split_charge_formula() -> None:
    limits = Limits()
    assert default_caps(limits).line_total == min(
        limits.max_response_line_bytes,
        limits.max_line_bytes
        + limits.max_folders * (LINE_OVERHEAD_BYTES + LIST_LINE_ALLOWANCE_BYTES),
    )
    assert default_caps(limits).line_total > limits.max_line_bytes
    assert (
        fetch_caps(limits, None, 1).line_total == FETCH_LINE_ALLOWANCE_BYTES + limits.max_line_bytes
    )
    many = fetch_caps(limits, LiteralItem.HEADER, 500)
    assert many.line_total == limits.max_response_line_bytes
    assert many.total <= limits.max_command_response_bytes


def test_a_batch_fits_under_the_line_ceiling_as_well_as_the_response_total() -> None:
    limits = Limits()
    by_lines = (
        limits.max_response_line_bytes - limits.max_line_bytes
    ) // FETCH_LINE_ALLOWANCE_BYTES
    n = max_messages(limits, None)
    assert 1 <= n <= by_lines
    assert fetch_caps(limits, None, n).line_total == (
        FETCH_LINE_ALLOWANCE_BYTES * n + limits.max_line_bytes
    )
    lowered = Limits(max_response_line_bytes=limits.max_line_bytes + 3 * FETCH_LINE_ALLOWANCE_BYTES)
    assert max_messages(lowered, None) == 3


@pytest.mark.parametrize(
    "limits",
    [
        Limits(),
        Limits(max_line_bytes=64 * KIB),
        Limits(max_response_line_bytes=300 * KIB, max_line_bytes=64 * KIB),
        Limits(max_command_response_bytes=4 * MIB),
    ],
)
@pytest.mark.parametrize("item", [None, LiteralItem.HEADER, LiteralItem.PART])
def test_a_sized_batch_keeps_its_line_allowance_under_l32(
    limits: Limits, item: LiteralItem | None
) -> None:
    n = max_messages(limits, item)
    assert n >= 1
    assert n * FETCH_LINE_ALLOWANCE_BYTES + limits.max_line_bytes <= limits.max_response_line_bytes
