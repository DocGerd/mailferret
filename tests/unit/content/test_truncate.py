from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from mailferret.content.truncate import (
    Truncated,
    drop_incomplete_utf8_tail,
    truncate_chars,
    truncate_text_bytes,
    truncate_utf8_bytes,
)

SAMPLES = ["abc", "Grüße", "日本語のテキスト", "a😀b😀", "́x"]
texts = st.text(alphabet=st.characters(codec="utf-8"), max_size=60)


def test_truncate_chars_flags_only_a_real_cut() -> None:
    assert truncate_chars("abcd", 4) == Truncated("abcd", False)
    assert truncate_chars("abcde", 4) == Truncated("abcd", True)
    assert truncate_chars("abc", 0) == Truncated("", True)


def test_negative_limits_are_rejected_without_echoing_input() -> None:
    with pytest.raises(ValueError, match="negative") as info:
        truncate_chars("secret-subject", -1)
    assert "secret-subject" not in str(info.value)
    with pytest.raises(ValueError, match="negative"):
        truncate_utf8_bytes(b"x", -1)


@pytest.mark.parametrize("sample", SAMPLES)
def test_every_cut_point_keeps_whole_codepoints(sample: str) -> None:
    data = sample.encode()
    for limit in range(len(data) + 2):
        kept, truncated = truncate_utf8_bytes(data, limit)
        assert len(kept) <= limit
        assert data.startswith(kept)
        assert truncated == (len(data) > limit)
        assert kept.decode("utf-8") == sample[: len(kept.decode("utf-8"))]


@given(texts, st.integers(0, 200))
def test_truncate_utf8_bytes_is_valid_and_maximal(text: str, limit: int) -> None:
    data = text.encode()
    kept, _ = truncate_utf8_bytes(data, limit)
    decoded = kept.decode("utf-8")
    assert len(kept) <= limit
    rest = data[len(kept) :]
    if rest:
        next_char = text[len(decoded)].encode()
        assert len(kept) + len(next_char) > limit


@given(texts, st.integers(0, 200))
def test_truncate_text_bytes_fits_and_is_a_prefix(text: str, limit: int) -> None:
    result = truncate_text_bytes(text, limit)
    assert len(result.text.encode()) <= limit
    assert text.startswith(result.text)
    assert result.truncated == (len(text.encode()) > limit)


@given(st.binary(max_size=64), st.integers(0, 80))
def test_truncate_arbitrary_bytes_never_raises(data: bytes, limit: int) -> None:
    kept, truncated = truncate_utf8_bytes(data, limit)
    assert len(kept) <= limit
    assert data.startswith(kept)
    assert truncated == (len(data) > limit)


@given(texts, st.data())
@settings(max_examples=200)
def test_incomplete_tail_is_dropped_and_complete_data_is_kept(
    text: str, data: st.DataObject
) -> None:
    raw = text.encode()
    cut = data.draw(st.integers(0, len(raw)))
    kept = drop_incomplete_utf8_tail(raw[:cut])
    kept.decode("utf-8")
    assert raw.startswith(kept)
    assert drop_incomplete_utf8_tail(raw) == raw


def test_tail_of_each_sequence_length() -> None:
    for char in "é日😀":
        raw = ("a" + char).encode()
        for cut in range(1, len(raw)):
            assert drop_incomplete_utf8_tail(raw[:cut]) == b"a"
        assert drop_incomplete_utf8_tail(raw) == raw


@given(st.binary(max_size=32))
def test_drop_tail_never_raises(data: bytes) -> None:
    assert data.startswith(drop_incomplete_utf8_tail(data))
