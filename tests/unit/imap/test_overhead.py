"""L-26 per-line overhead: measured with ``tracemalloc`` on every supported minor (T-08, A§2.2).

The constant must be at least what imaplib keeps for one untagged line. The worst case is a
line whose type is new, so every line adds a dict entry, its key, a list and the bytes object.
"""

from __future__ import annotations

import gc
import string
import tracemalloc

import pytest

from mailferret.imap.caps import LINE_OVERHEAD_BYTES
from tests.support.imap_fake import FakeImapServer
from tests.unit.imap.conftest import Opener

LINES = 20_000


def _type_name(i: int, width: int = 4) -> str:
    letters = string.ascii_uppercase
    return "".join(letters[(i // 26**k) % 26] for k in range(width))


def distinct_type_lines(count: int, data: str = "") -> bytes:
    return b"".join(f"* {_type_name(i)}{data}\r\n".encode() for i in range(count))


def same_type_lines(count: int) -> bytes:
    return b"* OK x\r\n" * 0 + b"".join(b"* 1 EXISTS\r\n" for _ in range(count))


def _retained_per_line(server: FakeImapServer, opener: Opener, payload: bytes, count: int) -> float:
    server.on("NOOP", [payload, "{tag} OK done\r\n"])
    session = opener(server)
    gc.collect()
    tracemalloc.start()
    try:
        before = tracemalloc.get_traced_memory()[0]
        session.noop()
        gc.collect()
        after = tracemalloc.get_traced_memory()[0]
    finally:
        tracemalloc.stop()
    entries = session._imap.untagged_responses
    assert sum(len(v) for v in entries.values()) >= count
    return (after - before) / count


@pytest.mark.parametrize("count", [4_000, 11_000, 20_000, 45_000])
@pytest.mark.parametrize("data", ["", " x", " (\\Seen \\Flagged)"])
def test_distinct_type_lines_cost_less_than_the_constant(
    server: FakeImapServer,
    opener: Opener,
    count: int,
    data: str,
) -> None:
    payload = distinct_type_lines(count, data)
    per_line = _retained_per_line(server, opener, payload, count)
    wire = len(payload) / count
    assert per_line - wire <= LINE_OVERHEAD_BYTES, (
        f"imaplib keeps {per_line:.0f} B for a {wire:.0f} B line: raise LINE_OVERHEAD_BYTES"
    )


def test_same_type_lines_cost_less_than_the_constant(
    server: FakeImapServer, opener: Opener
) -> None:
    payload = same_type_lines(LINES)
    per_line = _retained_per_line(server, opener, payload, LINES)
    wire = len(payload) / LINES
    assert per_line - wire <= LINE_OVERHEAD_BYTES


def test_the_constant_is_not_so_large_that_default_fetches_fail() -> None:
    assert 64 <= LINE_OVERHEAD_BYTES <= 1024
