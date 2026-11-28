from __future__ import annotations

import pytest

from mailferret.credentials.dbus import check_bus_address
from mailferret.credentials.detect import classify
from mailferret.credentials.wsl import is_wsl


@pytest.mark.parametrize("value", [None, ""])
def test_unset_is_unavailable(value: str | None) -> None:
    check = check_bus_address(value)
    assert check.status == "unset"
    assert not check.usable


@pytest.mark.parametrize(
    "entry",
    [
        "unixexec:path=/bin/sh,argv1=-c",
        "autolaunch:",
        "autolaunch:scope=*user",
        "tcp:host=localhost,port=1234",
        "nonce-tcp:host=localhost,port=1,noncefile=/x",
        "launchd:env=DBUS_LAUNCHD_SESSION_BUS_SOCKET",
        "systemd:",
        "unix:",
        "unix:guid=abcd",
        "unix:path=/run/bus,abstract=/tmp/x",
        "unix:tmpdir=/tmp",
        "unix:dir=/tmp",
        "unix:runtime=yes",
        "unix:path=/run/bus,extra=1",
        "unix:path=/run/bus,path=/run/bus",
        "unix:path",
        "UNIX:path=/run/bus",
    ],
)
def test_refused_transports(entry: str) -> None:
    check = check_bus_address(entry, exists=lambda _p: True)
    assert not check.usable
    assert check.accepted == ()
    assert check.status == "refused"


def test_missing_path_is_unavailable() -> None:
    check = check_bus_address("unix:path=/nonexistent/bus", exists=lambda _p: False)
    assert not check.usable
    assert check.status == "missing_path"


def test_accepts_unix_path_and_abstract() -> None:
    check = check_bus_address("unix:path=/run/bus,guid=ab", exists=lambda p: p == "/run/bus")
    assert check.accepted == ("unix:path=/run/bus,guid=ab",)
    check = check_bus_address("unix:abstract=/tmp/dbus-x", exists=lambda _p: False)
    assert check.accepted == ("unix:abstract=/tmp/dbus-x",)


def test_percent_escapes_are_decoded_for_the_existence_check() -> None:
    seen: list[str] = []

    def exists(path: str) -> bool:
        seen.append(path)
        return True

    assert check_bus_address("unix:path=/run/a%20b/bus", exists=exists).usable
    assert seen == ["/run/a b/bus"]


def test_list_mixing_entries_hands_only_accepted_ones_on() -> None:
    value = (
        "unixexec:path=/bin/sh;autolaunch:;unix:path=/missing;"
        "unix:path=/run/bus;tcp:host=x,port=1;unix:abstract=/a;"
    )
    check = check_bus_address(value, exists=lambda p: p == "/run/bus")
    assert check.accepted == ("unix:path=/run/bus", "unix:abstract=/a")
    assert check.address == "unix:path=/run/bus;unix:abstract=/a"


class _Fail:
    pass


_Fail.__module__ = "keyring.backends.fail"
_Fail.__name__ = _Fail.__qualname__ = "Keyring"


class _Null:
    pass


_Null.__module__ = "keyring.backends.null"
_Null.__name__ = _Null.__qualname__ = "Keyring"


class _Alt:
    pass


_Alt.__module__ = "keyrings.alt.file"
_Alt.__name__ = _Alt.__qualname__ = "PlaintextKeyring"


class _Real:
    pass


class ChainerBackend:
    def __init__(self, *backends: object) -> None:
        self.backends = list(backends)


@pytest.mark.parametrize(
    ("backend", "reason"),
    [
        (_Fail(), "fail"),
        (_Null(), "null"),
        (_Alt(), "plaintext"),
        (ChainerBackend(), "chainer_empty"),
        (ChainerBackend(_Real(), _Alt()), "plaintext"),
        (ChainerBackend(_Null()), "null"),
    ],
)
def test_detect_refuses(backend: object, reason: str) -> None:
    verdict = classify(backend)
    assert not verdict.usable
    assert verdict.reason == reason


def test_detect_accepts_real_backends() -> None:
    assert classify(_Real()).usable
    assert classify(ChainerBackend(_Real())).usable


def test_detect_with_real_keyring_fail_backend() -> None:
    fail = pytest.importorskip("keyring.backends.fail")
    assert not classify(fail.Keyring()).usable


def test_wsl_detection() -> None:
    assert is_wsl({"WSL_DISTRO_NAME": "x"}, platform="linux", read_osrelease=lambda: "")
    assert is_wsl({"WSL_INTEROP": "/run/x"}, platform="linux", read_osrelease=lambda: "")
    assert is_wsl({}, platform="linux", read_osrelease=lambda: "5.15.1-microsoft-standard-WSL2")
    assert not is_wsl({}, platform="linux", read_osrelease=lambda: "6.1.0-generic")
    assert not is_wsl({"WSL_DISTRO_NAME": "x"}, platform="win32")
    assert not is_wsl({"WSL_DISTRO_NAME": "x"}, platform="darwin")
