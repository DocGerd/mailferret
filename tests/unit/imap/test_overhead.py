"""L-26 per-line overhead: measured with ``tracemalloc`` on every supported minor (T-08, A§2.2).

Method: the peak traced bytes of one imaplib command that receives N untagged lines, less only
the data bytes imaplib keeps (not the ``* `` prefix, not the CRLF), per line. The worst case is a
line whose type is new, so every line adds a dict entry, its key, a list and the bytes object.
The constant must cover the largest measurement times ``MIN_MARGIN``; the CI imap job runs
this on every minor, so a minor that keeps more fails here.
"""

from __future__ import annotations

import gc
import string
import tracemalloc

import pytest

from mailferret.limits import LINE_OVERHEAD_BYTES
from tests.support.imap_fake import FakeImapServer
from tests.unit.imap.conftest import Opener

LINES = 20_000
# The constant was derived as the largest measurement times 2, rounded up; the test only
# requires the measurement to stay under it with MIN_MARGIN, so a minor that keeps more fails.
MIN_MARGIN = 1.5
REPEATS = 3


def _type_name(i: int, width: int = 4) -> str:
    letters = string.ascii_uppercase
    return "".join(letters[(i // 26**k) % 26] for k in range(width))


def distinct_type_lines(count: int, data: str = "") -> bytes:
    return b"".join(f"* {_type_name(i)}{data}\r\n".encode() for i in range(count))


def same_type_lines(count: int) -> bytes:
    return b"* OK x\r\n" * 0 + b"".join(b"* 1 EXISTS\r\n" for _ in range(count))


def _overhead_per_line(server: FakeImapServer, opener: Opener, payload: bytes, count: int) -> float:
    """Peak traced bytes per line, less only the data bytes imaplib keeps (not ``* ``, not CRLF)."""
    chunks = [payload[i : i + 4096] for i in range(0, len(payload), 4096)]
    server.on("NOOP", [*chunks, "{tag} OK done\r\n"])
    session = opener(server)
    gc.collect()
    tracemalloc.start()
    peaks: list[int] = []
    try:
        for _ in range(REPEATS):  # harness noise only inflates a peak: the minimum is the signal
            session._imap.untagged_responses.clear()
            gc.collect()
            baseline = tracemalloc.get_traced_memory()[0]
            tracemalloc.reset_peak()
            session._imap.noop()  # imaplib's own: imapclient's noop parses every line too
            peaks.append(tracemalloc.get_traced_memory()[1] - baseline)
    finally:
        tracemalloc.stop()
    peak = min(peaks)
    entries = session._imap.untagged_responses
    assert sum(len(v) for v in entries.values()) >= count
    kept = sum(len(item) for v in entries.values() for item in v)
    overhead = (peak - kept) / count
    return overhead


@pytest.mark.parametrize("count", [11_000, 20_000, 45_000])
@pytest.mark.parametrize("data", ["", " x", " (\\Seen \\Flagged)"])
def test_distinct_type_lines_cost_less_than_the_constant(
    server: FakeImapServer,
    opener: Opener,
    count: int,
    data: str,
) -> None:
    payload = distinct_type_lines(count, data)
    overhead = _overhead_per_line(server, opener, payload, count)
    assert overhead * MIN_MARGIN <= LINE_OVERHEAD_BYTES, (
        f"{overhead:.0f} B per line: raise LINE_OVERHEAD_BYTES"
    )


def test_same_type_lines_cost_less_than_the_constant(
    server: FakeImapServer, opener: Opener
) -> None:
    payload = same_type_lines(LINES)
    assert _overhead_per_line(server, opener, payload, LINES) * MIN_MARGIN <= LINE_OVERHEAD_BYTES


def test_the_constant_is_not_so_large_that_default_fetches_fail() -> None:
    assert 64 <= LINE_OVERHEAD_BYTES <= 1024
