"""T-16: the persistent and time-boxed markers (file format, expiry, fail-closed reads)."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from mailferret.auth import PAUSE_SECONDS, AuthMarkers, marker_path
from mailferret.auth.markers import MarkerKind
from tests.unit.auth.conftest import key_for


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


def test_no_marker_means_not_blocked(tmp_path: Path) -> None:
    assert AuthMarkers(tmp_path / "data").blocked(key_for()) is None


def test_a_rejection_persists_for_every_process_and_never_expires(tmp_path: Path) -> None:
    clock = Clock()
    AuthMarkers(tmp_path / "data", clock).record_rejected(key_for())
    clock.now += 10 * PAUSE_SECONDS
    assert AuthMarkers(tmp_path / "data", clock).blocked(key_for()) == "rejected"


def test_an_indeterminate_marker_blocks_for_the_time_box_only(tmp_path: Path) -> None:
    clock = Clock()
    markers = AuthMarkers(tmp_path / "data", clock)
    markers.record_indeterminate(key_for())
    other = AuthMarkers(tmp_path / "data", clock)
    assert other.blocked(key_for()) == "indeterminate"
    clock.now += PAUSE_SECONDS - 1
    assert other.blocked(key_for()) == "indeterminate"
    clock.now += 1
    assert other.blocked(key_for()) is None


def test_a_marker_is_per_login_and_host(tmp_path: Path) -> None:
    markers = AuthMarkers(tmp_path / "data")
    markers.record_rejected(key_for())
    assert markers.blocked(key_for("other@example.com")) is None


def test_the_file_name_is_hashed_and_holds_no_secret(tmp_path: Path) -> None:
    markers = AuthMarkers(tmp_path / "data")
    markers.record_rejected(key_for())
    path = marker_path(tmp_path / "data", key_for())
    assert "user" not in path.name
    assert json.loads(path.read_bytes())["username"] == key_for().username
    assert [p.name for p in path.parent.iterdir()] == [path.name]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_the_file_is_private(tmp_path: Path) -> None:
    AuthMarkers(tmp_path / "data").record_rejected(key_for())
    mode = stat.S_IMODE(os.stat(marker_path(tmp_path / "data", key_for())).st_mode)
    assert mode == 0o600


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"not json",
        b"[1, 2]",
        b'{"username": "someone@else", "kind": "indeterminate", "at": 1}',
        b'{"username": "user@example.com@127.0.0.1", "kind": "indeterminate"}',
        b'{"username": "user@example.com@127.0.0.1", "kind": "indeterminate", "at": "x"}',
        b"[" * 4000,
        b"x" * 5000,
    ],
)
@pytest.mark.parametrize("kind", ["rejected", "indeterminate"])
def test_an_unreadable_or_corrupt_marker_counts_as_present(
    tmp_path: Path, content: bytes, kind: MarkerKind
) -> None:
    data = tmp_path / "data"
    data.mkdir()
    marker_path(data, key_for(), kind).write_bytes(content)
    assert AuthMarkers(data).blocked(key_for()) == "rejected"


def test_a_marker_that_cannot_be_written_still_blocks_this_process(tmp_path: Path) -> None:
    blocker = tmp_path / "data"
    blocker.write_bytes(b"a file where the directory should be")
    markers = AuthMarkers(blocker)
    markers.record_rejected(key_for())
    assert markers.blocked(key_for()) == "rejected"
    assert AuthMarkers(blocker).blocked(key_for()) is None


def test_clear_removes_either_kind(tmp_path: Path) -> None:
    markers = AuthMarkers(tmp_path / "data")
    markers.record_rejected(key_for())
    markers.clear(key_for())
    assert markers.blocked(key_for()) is None
    markers.record_indeterminate(key_for())
    markers.clear(key_for())
    assert AuthMarkers(tmp_path / "data").blocked(key_for()) is None
    markers.clear(key_for())


def test_the_two_kinds_live_in_two_files(tmp_path: Path) -> None:
    markers = AuthMarkers(tmp_path / "data")
    markers.record_indeterminate(key_for())
    markers.record_rejected(key_for())
    assert marker_path(tmp_path / "data", key_for(), "rejected").exists()
    assert marker_path(tmp_path / "data", key_for(), "indeterminate").exists()


def test_a_later_time_box_never_replaces_a_rejection(tmp_path: Path) -> None:
    """Two processes that raced through login: the slower one's time box lands last."""
    clock = Clock()
    AuthMarkers(tmp_path / "data", clock).record_rejected(key_for())
    AuthMarkers(tmp_path / "data", clock).record_indeterminate(key_for())
    clock.now += 100 * PAUSE_SECONDS
    assert AuthMarkers(tmp_path / "data", clock).blocked(key_for()) == "rejected"


def test_an_unwritten_rejection_wins_over_an_expired_time_box_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = Clock()
    data = tmp_path / "data"
    AuthMarkers(data, clock).record_indeterminate(key_for())
    clock.now += PAUSE_SECONDS
    markers = AuthMarkers(data, clock)
    assert markers.blocked(key_for()) is None

    def refuse(*args: object) -> None:
        raise OSError("read-only")

    monkeypatch.setattr(os, "replace", refuse)
    markers.record_rejected(key_for())
    monkeypatch.undo()
    assert marker_path(data, key_for(), "indeterminate").exists()
    assert not marker_path(data, key_for(), "rejected").exists()
    assert markers.blocked(key_for()) == "rejected"


def test_an_unwritten_time_box_blocks_beside_an_expired_file(tmp_path: Path) -> None:
    clock = Clock()
    data = tmp_path / "data"
    AuthMarkers(data, clock).record_indeterminate(key_for())
    clock.now += PAUSE_SECONDS
    markers = AuthMarkers(data, clock)
    markers._unwritten[(key_for().username, "indeterminate")] = clock.now
    assert markers.blocked(key_for()) == "indeterminate"


def test_the_strictest_of_file_and_memory_wins_in_either_order(tmp_path: Path) -> None:
    clock = Clock()
    data = tmp_path / "data"
    markers = AuthMarkers(data, clock)
    markers.record_rejected(key_for())
    markers._unwritten[(key_for().username, "indeterminate")] = clock.now
    assert markers.blocked(key_for()) == "rejected"
    markers.clear(key_for())
    markers._unwritten[(key_for().username, "rejected")] = clock.now
    AuthMarkers(data, clock).record_indeterminate(key_for())
    assert markers.blocked(key_for()) == "rejected"
