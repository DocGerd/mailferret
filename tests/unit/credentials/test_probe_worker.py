from __future__ import annotations

import io
import json
import types
from collections.abc import Callable
from typing import Any

import pytest

from mailferret.credentials import probe_protocol as proto
from mailferret.credentials.keyring_probe import run


class _Errors(types.ModuleType):
    pass


def _errors() -> types.ModuleType:
    mod = types.ModuleType("keyring.errors")
    mod.KeyringError = type("KeyringError", (Exception,), {})  # type: ignore[attr-defined]
    for name in ("NoKeyringError", "KeyringLocked", "PasswordDeleteError", "InitError"):
        setattr(mod, name, type(name, (mod.KeyringError,), {}))  # type: ignore[attr-defined]
    return mod


class _Backend:
    pass


def _fake(**overrides: Any) -> tuple[Callable[[str], types.ModuleType], types.ModuleType]:
    errors = _errors()
    kr = types.ModuleType("keyring")
    store: dict[tuple[str, str], str] = {}
    kr.get_keyring = lambda: _Backend()  # type: ignore[attr-defined]
    kr.get_password = lambda s, u: store.get((s, u))  # type: ignore[attr-defined]
    kr.set_password = lambda s, u, p: store.__setitem__((s, u), p)  # type: ignore[attr-defined]
    kr.delete_password = lambda s, u: store.pop((s, u))  # type: ignore[attr-defined]
    kr.store = store  # type: ignore[attr-defined]
    for name, value in overrides.items():
        setattr(kr, name, value)
    mods = {"keyring": kr, "keyring.errors": errors}

    def load(name: str) -> types.ModuleType:
        if name not in mods:
            raise ImportError(name)
        return mods[name]

    return load, kr


def call(
    argv: list[str], load: Callable[[str], types.ModuleType], stdin: bytes = b""
) -> tuple[int, bytes]:
    out = io.BytesIO()
    code = run(argv, io.BytesIO(stdin), out, load)
    return code, out.getvalue()


def test_get_set_delete_round_trip() -> None:
    load, kr = _fake()
    assert call(["set", "svc", "u@h"], load, b"pw")[0] == proto.OK
    assert kr.store == {("svc", "u@h"): "pw"}  # type: ignore[attr-defined]
    assert call(["get", "svc", "u@h"], load) == (proto.OK, b"pw\n")
    assert call(["get", "svc", "other@h"], load)[0] == proto.NOT_FOUND
    assert call(["delete", "svc", "u@h"], load)[0] == proto.OK


@pytest.mark.parametrize("data", [b"", b"a\nb", b"a\r", b"a\0", b"x" * 5000, b"\xff"])
def test_set_refuses_bad_secret(data: bytes) -> None:
    load, kr = _fake()
    assert call(["set", "s", "u"], load, data)[0] == proto.ERROR
    assert kr.store == {}  # type: ignore[attr-defined]


def test_get_refuses_stored_value_with_forbidden_characters() -> None:
    load, kr = _fake()
    kr.store[("s", "u")] = "line1\nlogin: x"  # type: ignore[attr-defined]
    code, out = call(["get", "s", "u"], load)
    assert code == proto.ERROR
    assert out == b""


@pytest.mark.parametrize("exc", [FileNotFoundError, ConnectionRefusedError, TimeoutError])
def test_raw_dbus_errors_are_unavailable(exc: type[Exception]) -> None:
    def boom(*_a: object) -> None:
        raise exc("detail with secret")

    load, _ = _fake(get_password=boom)
    assert call(["get", "s", "u"], load)[0] == proto.UNAVAILABLE
    load, _ = _fake(get_keyring=boom)
    assert call(["describe"], load)[0] == proto.UNAVAILABLE


def test_keyring_errors_map_to_exit_codes() -> None:
    load, kr = _fake()
    errors = load("keyring.errors")

    def raising(name: str) -> Callable[..., None]:
        def boom(*_a: object) -> None:
            raise getattr(errors, name)()

        return boom

    kr.get_password = raising("KeyringLocked")  # type: ignore[attr-defined]
    assert call(["get", "s", "u"], load)[0] == proto.LOCKED
    kr.get_password = raising("NoKeyringError")  # type: ignore[attr-defined]
    assert call(["get", "s", "u"], load)[0] == proto.UNAVAILABLE
    kr.delete_password = raising("PasswordDeleteError")  # type: ignore[attr-defined]
    assert call(["delete", "s", "u"], load)[0] == proto.NOT_FOUND
    kr.get_password = lambda *_a: (_ for _ in ()).throw(RuntimeError("x"))  # type: ignore[attr-defined]
    assert call(["get", "s", "u"], load)[0] == proto.ERROR


def test_missing_keyring_is_unavailable() -> None:
    def load(name: str) -> types.ModuleType:
        raise ImportError(name)

    assert call(["describe"], load)[0] == proto.UNAVAILABLE


@pytest.mark.parametrize(
    "module", ["keyring.backends.fail", "keyring.backends.null", "keyrings.alt.file"]
)
def test_unusable_backends_report_unavailable_and_are_never_used(module: str) -> None:
    backend = type("Keyring" if module != "keyrings.alt.file" else "PlaintextKeyring", (), {})
    backend.__module__ = module
    used: list[str] = []
    load, _ = _fake(
        get_keyring=lambda: backend(),
        get_password=lambda *_a: used.append("get"),
        set_password=lambda *_a: used.append("set"),
    )
    assert call(["get", "s", "u"], load)[0] == proto.UNAVAILABLE
    assert call(["set", "s", "u"], load, b"pw")[0] == proto.UNAVAILABLE
    code, out = call(["describe"], load)
    assert code == proto.UNAVAILABLE
    assert json.loads(out)["secure"] is False
    assert used == []


def test_describe_names_the_chosen_backend() -> None:
    load, _ = _fake()
    code, out = call(["describe"], load)
    assert code == proto.OK
    body = json.loads(out)
    assert body["secure"] is True
    assert body["backend"].endswith("_Backend")


@pytest.mark.parametrize("argv", [[], ["nope"], ["get"], ["describe", "x"], ["get", "a"]])
def test_bad_usage_is_an_error(argv: list[str]) -> None:
    load, _ = _fake()
    assert call(argv, load)[0] == proto.ERROR
