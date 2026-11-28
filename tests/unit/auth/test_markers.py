"""T-16: the persistent and time-boxed markers (file format, expiry, fail-closed reads)."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from mailferret.auth import PAUSE_SECONDS, AuthMarkers, marker_path
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
        b'{"username": "user@example.com@127.0.0.1", "kind": "other", "at": 1}',
        b"[" * 4000,
        b"x" * 5000,
    ],
)
def test_an_unreadable_or_corrupt_marker_counts_as_present(tmp_path: Path, content: bytes) -> None:
    data = tmp_path / "data"
    data.mkdir()
    marker_path(data, key_for()).write_bytes(content)
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


def test_a_success_clears_a_time_box_but_never_a_rejection(tmp_path: Path) -> None:
    markers = AuthMarkers(tmp_path / "data")
    markers.record_indeterminate(key_for())
    markers.clear_indeterminate(key_for())
    assert markers.blocked(key_for()) is None
    markers.record_rejected(key_for())
    markers.clear_indeterminate(key_for())
    assert markers.blocked(key_for()) == "rejected"
