from __future__ import annotations

import contextlib
import logging
import socket
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from mailferret.credentials import (
    CredentialBackendError,
    CredentialBackendUnavailable,
    CredentialError,
    CredentialLimitExceeded,
    CredentialLocked,
    CredentialNotFound,
    CredentialRejected,
    CredentialTimeout,
    EntryKey,
    Secret,
)
from mailferret.credentials import probe as probe_module
from mailferret.credentials.keyring_backend import KeyringBackend
from mailferret.credentials.probe import probe_env, run_probe
from mailferret.limits import CEILINGS, Limits
from tests.unit.credentials.helpers import FAKE_KEYRING, py

KEY = EntryKey("work", "user", "imap.example.com")
SECRET = 'pa"ss\\w0rd-é'  # noqa: S105
linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Secret Service")


@pytest.fixture
def bus(tmp_path: Path) -> Iterator[str]:
    """A bus address that passes the pre-check, so the probe is spawned on Linux."""
    path = tmp_path / "bus"
    path.write_text("")
    yield f"unix:path={path}"


def env_for(tmp_path: Path, bus: str, **extra: str) -> dict[str, str]:
    import os

    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp_path),
        "XDG_CONFIG_HOME": str(tmp_path),
    }
    if "SYSTEMROOT" in os.environ:
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    if sys.platform.startswith("linux"):
        env["DBUS_SESSION_BUS_ADDRESS"] = bus
    env.update(extra)
    return env


def backend(tmp_path: Path, bus: str, code: str = FAKE_KEYRING, **kw: Any) -> KeyringBackend:
    store = tmp_path / "store"
    store.mkdir(exist_ok=True)
    environ = env_for(tmp_path, bus, XDG_CONFIG_HOME=str(store))
    return KeyringBackend(tmp_path / "data", environ=environ, argv=py(code), **kw)


def test_round_trip_through_a_real_probe_process(tmp_path: Path, bus: str) -> None:
    kb = backend(tmp_path, bus)
    kb.set(KEY, Secret(SECRET))
    assert kb.get(KEY).reveal() == SECRET
    kb.delete(KEY)
    with pytest.raises(CredentialNotFound):
        kb.get(KEY)
    with pytest.raises(CredentialNotFound):
        kb.delete(KEY)


def test_changed_host_or_login_finds_no_secret(tmp_path: Path, bus: str) -> None:
    kb = backend(tmp_path, bus)
    kb.set(KEY, Secret(SECRET))
    for other in (
        EntryKey("work", "user", "evil.example.com"),
        EntryKey("work", "other", "imap.example.com"),
        EntryKey("other", "user", "imap.example.com"),
    ):
        with pytest.raises(CredentialNotFound):
            kb.get(other)


def test_describe_reports_backend_and_wsl(tmp_path: Path, bus: str) -> None:
    desc = backend(tmp_path, bus).describe()
    assert (desc.kind, desc.secure, desc.status) == ("keyring", True, "ok")
    assert desc.backend is not None
    assert isinstance(desc.wsl, bool)


def test_set_refuses_bad_secret_before_any_spawn(
    tmp_path: Path, bus: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_spawn(*_a: object, **_k: object) -> None:
        raise AssertionError("spawned")

    monkeypatch.setattr(probe_module, "run_bounded", no_spawn)
    kb = backend(tmp_path, bus)
    for bad in ("", "a\nb", "a\rb", "a\0b", "x" * CEILINGS["credential_command_output_bytes"]):
        with pytest.raises(CredentialRejected):
            kb.set(KEY, Secret(bad))


def test_describe_set_and_get_share_one_bound(
    tmp_path: Path, bus: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[dict[str, Any]] = []
    real = probe_module.run_bounded

    def spy(argv: Any, **kwargs: Any) -> Any:
        seen.append({k: v for k, v in kwargs.items() if k != "env"})
        return real(argv, **kwargs)

    monkeypatch.setattr(probe_module, "run_bounded", spy)
    limits = Limits(keyring_probe_seconds=7, credential_command_output_bytes=1024)
    kb = backend(tmp_path, bus, limits=limits)
    kb.describe()
    kb.set(KEY, Secret("pw"))
    kb.get(KEY)
    assert len(seen) == 3
    assert {s["deadline"] for s in seen} == {7}
    assert {s["stdout_cap"] for s in seen} == {1024}
    assert {s["stderr_cap"] for s in seen} == {CEILINGS["credential_stderr_bytes"]}


def test_lowered_probe_limit_is_honoured(tmp_path: Path, bus: str) -> None:
    kb = backend(
        tmp_path, bus, "import time; time.sleep(60)", limits=Limits(keyring_probe_seconds=1)
    )
    start = time.monotonic()
    with pytest.raises(CredentialTimeout):
        kb.get(KEY)
    assert time.monotonic() - start < 3


@pytest.mark.parametrize(
    ("code", "error"),
    [
        ("import sys; sys.exit(10)", CredentialNotFound),
        ("import sys; sys.exit(11)", CredentialBackendUnavailable),
        ("import sys; sys.exit(12)", CredentialLocked),
        ("import sys; sys.exit(13)", CredentialBackendError),
        ("import sys; sys.exit(1)", CredentialBackendError),
        ("import sys; sys.stdout.write('x' * 100000)", CredentialLimitExceeded),
        ("import sys; sys.stdout.write('line1\\nlogin: u\\n')", CredentialRejected),
        ("pass", CredentialRejected),
        ("import sys; sys.stdout.write('\\n')", CredentialRejected),
    ],
)
def test_probe_results_map_to_typed_errors(
    tmp_path: Path, bus: str, code: str, error: type[CredentialError]
) -> None:
    with pytest.raises(error):
        backend(tmp_path, bus, code).get(KEY)


def test_probe_output_is_accepted_only_after_exit_zero(tmp_path: Path, bus: str) -> None:
    code = "import sys; sys.stdout.write('pw\\n'); sys.exit(1)"
    with pytest.raises(CredentialBackendError):
        backend(tmp_path, bus, code).get(KEY)


def test_secret_on_probe_stderr_never_reaches_errors_logs_or_repr(
    tmp_path: Path, bus: str, caplog: pytest.LogCaptureFixture
) -> None:
    code = (
        "import sys; sys.stderr.write('"
        + SECRET.replace("\\", "\\\\").replace("'", "")
        + "'); sys.exit(13)"
    )
    plain = SECRET.replace("'", "")
    with caplog.at_level(logging.DEBUG), pytest.raises(CredentialBackendError) as info:
        backend(tmp_path, bus, code).get(KEY)
    err = info.value
    assert plain not in str(err) + repr(err) + repr(err.args)
    assert err.__cause__ is None and err.__context__ is None
    assert plain not in caplog.text


def test_stderr_flood_from_the_probe_is_bounded(tmp_path: Path, bus: str) -> None:
    code = (
        "import sys\n"
        "chunk = b'e' * 65536\n"
        "for _ in range(1024): sys.stderr.buffer.write(chunk)\n"
        "sys.exit(11)"
    )
    start = time.monotonic()
    with pytest.raises(CredentialBackendUnavailable):
        backend(tmp_path, bus, code).get(KEY)
    assert time.monotonic() - start < CEILINGS["keyring_probe_seconds"]


def test_keyring_variables_go_to_the_probe_only(tmp_path: Path) -> None:
    environ = {
        "PATH": "/bin",
        "PYTHON_KEYRING_BACKEND": "some.Backend",
        "XDG_CONFIG_HOME": "/cfg",
        "DBUS_SESSION_BUS_ADDRESS": "tcp:host=x",
        "UNRELATED": "v",
    }
    env = probe_env(environ, "unix:path=/run/bus")
    assert env["PYTHON_KEYRING_BACKEND"] == "some.Backend"
    assert env["XDG_CONFIG_HOME"] == "/cfg"
    assert env["DBUS_SESSION_BUS_ADDRESS"] == "unix:path=/run/bus"
    assert "UNRELATED" not in env
    assert "DBUS_SESSION_BUS_ADDRESS" not in probe_env(environ, None)
    from mailferret.credentials.process import minimal_env

    assert "PYTHON_KEYRING_BACKEND" not in minimal_env(environ)
    assert "XDG_CONFIG_HOME" not in minimal_env(environ)


def test_probe_receives_the_keyring_variables(tmp_path: Path, bus: str) -> None:
    code = (
        "import os, sys; sys.stdout.write(os.environ['PYTHON_KEYRING_BACKEND'] + '|' "
        "+ os.environ['XDG_CONFIG_HOME'] + '|' + str('UNRELATED' in os.environ))"
    )
    environ = env_for(tmp_path, bus, PYTHON_KEYRING_BACKEND="some.Backend", UNRELATED="v")
    outcome = run_probe(
        "get", KEY, data_dir=tmp_path / "d", limits=Limits(), environ=environ, argv=py(code)
    )
    assert outcome.status == "ok"
    assert outcome.stdout.decode() == f"some.Backend|{tmp_path}|False"


@linux_only
def test_unset_or_refused_bus_never_spawns(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def no_spawn(*_a: object, **_k: object) -> None:
        raise AssertionError("spawned")

    monkeypatch.setattr(probe_module, "run_bounded", no_spawn)
    for address in (
        None,
        "unixexec:path=/bin/sh",
        "autolaunch:",
        "tcp:host=x,port=1",
        "unix:path=/missing",
    ):
        environ = {"PATH": "/bin"}
        if address:
            environ["DBUS_SESSION_BUS_ADDRESS"] = address
        with pytest.raises(CredentialBackendUnavailable):
            KeyringBackend(tmp_path, environ=environ).get(KEY)
        assert KeyringBackend(tmp_path, environ=environ).describe().status == "unavailable"


@linux_only
def test_only_accepted_bus_entries_reach_the_probe(tmp_path: Path, bus: str) -> None:
    mixed = f"unixexec:path=/bin/sh;{bus};tcp:host=x,port=1"
    code = "import os, sys; sys.stdout.write(os.environ['DBUS_SESSION_BUS_ADDRESS'])"
    outcome = run_probe(
        "get",
        KEY,
        data_dir=tmp_path / "d",
        limits=Limits(),
        environ={"PATH": "/bin", "DBUS_SESSION_BUS_ADDRESS": mixed},
        argv=py(code),
    )
    assert outcome.stdout.decode() == bus


def test_planted_keyring_module_in_the_data_dir_is_never_imported(tmp_path: Path, bus: str) -> None:
    data = tmp_path / "data"
    data.mkdir()
    marker = tmp_path / "imported"
    (data / "keyring.py").write_text(f"open({str(marker)!r}, 'w').write('x')\n")
    (data / "mailferret.py").write_text(f"open({str(marker)!r}, 'w').write('x')\n")
    kb = KeyringBackend(data, environ=env_for(tmp_path, bus))
    desc = kb.describe()
    assert not marker.exists()
    assert desc.status in {"ok", "unavailable", "error", "timeout", "locked"}


@pytest.fixture
def mute_bus(tmp_path: Path) -> Iterator[str]:
    """A session bus that completes the SASL handshake and then never answers (V3 E6)."""
    if not hasattr(socket, "AF_UNIX"):
        pytest.skip("no AF_UNIX")
    path = tmp_path / "mute.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(8)
    held: list[socket.socket] = []
    stop = threading.Event()

    def serve(conn: socket.socket) -> None:
        buf = b""
        while not stop.is_set():
            try:
                data = conn.recv(4096)
            except OSError:
                return
            if not data:
                return
            buf += data
            while b"\r\n" in buf:
                line, buf = buf.split(b"\r\n", 1)
                line = line.lstrip(b"\0")
                if line.startswith(b"AUTH"):
                    conn.sendall(b"OK 0123456789abcdef0123456789abcdef\r\n")
                elif line.startswith(b"NEGOTIATE_UNIX_FD"):
                    conn.sendall(b"AGREE_UNIX_FD\r\n")
                elif line.startswith(b"BEGIN"):
                    buf = b""

    def accept() -> None:
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn = server.accept()[0]
            except OSError:
                continue
            held.append(conn)
            threading.Thread(target=serve, args=(conn,), daemon=True).start()

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    try:
        yield f"unix:path={path}"
    finally:
        stop.set()
        thread.join(2)
        for conn in held:
            conn.close()
        server.close()


@linux_only
def test_mute_bus_blocking_probe_is_bounded(tmp_path: Path, mute_bus: str) -> None:
    code = (
        "import os, socket\n"
        "s = socket.socket(socket.AF_UNIX)\n"
        "s.connect(os.environ['DBUS_SESSION_BUS_ADDRESS'].split('=', 1)[1])\n"
        "s.recv(1)"
    )
    kb = KeyringBackend(
        tmp_path / "d",
        Limits(keyring_probe_seconds=2),
        environ=env_for(tmp_path, mute_bus),
        argv=py(code),
    )
    start = time.monotonic()
    with pytest.raises(CredentialTimeout):
        kb.get(KEY)
    assert time.monotonic() - start < 2 + 2


@linux_only
@pytest.mark.parametrize("forced", [True, False])
def test_mute_bus_repro_with_the_real_keyring(tmp_path: Path, mute_bus: str, forced: bool) -> None:
    """Retained V3 E6 repro: the real keyring against a bus that authenticates and goes silent."""
    pytest.importorskip("keyring")
    pytest.importorskip("secretstorage")
    extra = {"PYTHON_KEYRING_BACKEND": "keyring.backends.SecretService.Keyring"} if forced else {}
    bound = 3
    kb = KeyringBackend(
        tmp_path / "d",
        Limits(keyring_probe_seconds=bound),
        environ=env_for(tmp_path, mute_bus, **extra),
    )
    start = time.monotonic()
    with pytest.raises(CredentialTimeout):
        kb.get(KEY)
    elapsed = time.monotonic() - start
    assert bound <= elapsed < bound + 2


@pytest.fixture
def clean_redaction() -> Iterator[None]:
    from mailferret.logging import clear_secrets

    clear_secrets()
    yield
    clear_secrets()


def _forms(secret: str, login: str) -> list[str]:
    import base64

    quoted = secret.replace("\\", "\\\\").replace('"', '\\"')
    blob = base64.b64encode(f"\0{login}\0{secret}".encode()).decode("ascii")
    return [secret, quoted, blob]


@pytest.mark.usefixtures("clean_redaction")
@pytest.mark.parametrize("via", ["get", "set"])
def test_secret_forms_are_registered_for_redaction(tmp_path: Path, bus: str, via: str) -> None:
    from mailferret.logging import redact

    kb = backend(tmp_path, bus)
    if via == "get":
        kb.set(KEY, Secret(SECRET))
        from mailferret.logging import clear_secrets

        clear_secrets()
        assert redact(SECRET) == SECRET
        kb.get(KEY)
    else:
        kb.set(KEY, Secret(SECRET))
    for form in _forms(SECRET, KEY.login):
        assert redact(f"line {form} end") == "line *** end"


def test_unusable_data_dir_is_a_fixed_text_error(tmp_path: Path, bus: str) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x")
    kb = KeyringBackend(blocker / "data", environ=env_for(tmp_path, bus))
    with pytest.raises(CredentialBackendError) as info:
        kb.get(KEY)
    assert str(tmp_path) not in str(info.value) + repr(info.value.args)
    assert info.value.__cause__ is None
    assert info.value.__suppress_context__


def test_rejected_maps_to_the_documented_error_code() -> None:
    assert CredentialRejected.code == "error"


@pytest.mark.skipif(sys.platform not in {"darwin", "win32"}, reason="Keychain / Credential Locker")
def test_real_probe_through_the_platform_keyring(tmp_path: Path) -> None:
    """A§10 item 23: real set/get/delete under a throwaway service name, within L-27."""
    import uuid

    limits = Limits()
    kb = KeyringBackend(tmp_path / "data", limits)
    desc = kb.describe()
    if desc.status != "ok" or not desc.secure:
        pytest.skip(f"no usable platform keyring on this runner ({desc.status})")
    expected = {"darwin": "macOS", "win32": "Windows"}[sys.platform]
    assert expected in (desc.backend or "")
    key = EntryKey(f"mailferret-test-{uuid.uuid4().hex}", "user", "imap.example.com")
    start = time.monotonic()
    try:
        kb.set(key, Secret(SECRET))
        assert kb.get(key).reveal() == SECRET
    finally:
        with contextlib.suppress(CredentialError):
            kb.delete(key)
    assert time.monotonic() - start < 3 * limits.keyring_probe_seconds
    with pytest.raises(CredentialNotFound):
        kb.get(key)
