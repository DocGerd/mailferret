"""``command`` backend with fake commands (A§2.1; T-02, T-03, T-11, T-17; L-14, L-22, L-29)."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import signal
import stat
import sys
import time
import tracemalloc
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from mailferret.config.schema import CREDENTIAL_ENV_ALLOWLIST
from mailferret.credentials import (
    CommandBackend,
    CredentialBackendError,
    CredentialBackendUnavailable,
    CredentialLimitExceeded,
    CredentialLocked,
    CredentialNotFound,
    CredentialRejected,
    CredentialTimeout,
    EntryKey,
    Secret,
)
from mailferret.credentials import command_backend as cb
from mailferret.credentials.bindings import binding_path, write_binding
from mailferret.limits import CEILINGS, Limits
from tests.unit.credentials.helpers import pid_dead, py, read_pid

KEY = EntryKey("work", "user", "imap.example.com")
SECRET = "pa-ss_w0rd"  # noqa: S105  # pii-check: ignore
SECONDS = 1
MARGIN = 2.0
LIMITS = Limits(credential_command_seconds=SECONDS)
SLOW_LIMITS = Limits(credential_command_seconds=10)
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX sessions and pipes")
windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows job object")


def backend(
    tmp_path: Path,
    get: list[str],
    set_: list[str] | None = None,
    *,
    env: dict[str, str] | None = None,
    environ: dict[str, str] | None = None,
    limits: Limits = LIMITS,
) -> CommandBackend:
    return CommandBackend(
        tmp_path / "data",
        get,
        set_,
        env=env,
        limits=limits,
        environ=os.environ if environ is None else environ,
    )


def bind(tmp_path: Path, key: EntryKey = KEY) -> None:
    (tmp_path / "data").mkdir(exist_ok=True)
    write_binding(tmp_path / "data", key)


def store_commands(store: Path) -> tuple[list[str], list[str]]:
    get = py(f"import sys; sys.stdout.write(open({str(store)!r}).read())")
    set_ = py(f"import sys; open({str(store)!r}, 'w').write(sys.stdin.read())")
    return get, set_


def timed(call: object) -> float:
    start = time.monotonic()
    with contextlib.suppress(Exception):
        call()  # type: ignore[operator]
    return time.monotonic() - start


def test_allowlist_matches_the_config_schema() -> None:
    assert cb.ENV_ALLOWLIST == CREDENTIAL_ENV_ALLOWLIST


def test_set_then_get_round_trip_and_binding_record(tmp_path: Path) -> None:
    store = tmp_path / "store"
    get, set_ = store_commands(store)
    b = backend(tmp_path, get, set_)
    b.set(KEY, Secret(SECRET))
    assert b.get(KEY).reveal() == SECRET
    record = binding_path(tmp_path / "data", KEY)
    assert json.loads(record.read_text()) == {
        "service": KEY.service,
        "username": KEY.username,
    }
    assert SECRET not in record.read_text()
    if sys.platform != "win32":
        assert stat.S_IMODE(record.stat().st_mode) == 0o600


def test_get_without_binding_does_not_spawn(tmp_path: Path) -> None:
    marker = tmp_path / "spawned"
    b = backend(tmp_path, py(f"open({str(marker)!r}, 'w'); print('x')"))
    with pytest.raises(CredentialNotFound):
        b.get(KEY)
    assert not marker.exists()


@pytest.mark.parametrize(
    "other",
    [
        EntryKey("work", "user", "evil.example.net"),
        EntryKey("work", "other", "imap.example.com"),
    ],
)
def test_tampered_login_or_host_finds_no_secret_and_does_not_spawn(
    tmp_path: Path, other: EntryKey
) -> None:
    marker = tmp_path / "spawned"
    bind(tmp_path)
    b = backend(tmp_path, py(f"open({str(marker)!r}, 'w'); print('x')"))
    with pytest.raises(CredentialNotFound):
        b.get(other)
    assert not marker.exists()


@pytest.mark.parametrize("content", ["", "not json", "[]", '{"service": "mailferret/work"}'])
def test_unreadable_or_partial_binding_is_not_found(tmp_path: Path, content: str) -> None:
    bind(tmp_path)
    binding_path(tmp_path / "data", KEY).write_text(content)
    b = backend(tmp_path, py("print('x')"))
    with pytest.raises(CredentialNotFound):
        b.get(KEY)


def test_failed_set_leaves_no_binding(tmp_path: Path) -> None:
    bind(tmp_path)
    b = backend(tmp_path, py("print('x')"), py("import sys; sys.exit(3)"))
    with pytest.raises(CredentialBackendError):
        b.set(KEY, Secret(SECRET))
    assert not binding_path(tmp_path / "data", KEY).exists()


def test_delete_removes_the_binding(tmp_path: Path) -> None:
    bind(tmp_path)
    b = backend(tmp_path, py("print('x')"))
    b.delete(KEY)
    b.delete(KEY)
    assert not binding_path(tmp_path / "data", KEY).exists()


def test_set_without_set_command_is_unavailable(tmp_path: Path) -> None:
    with pytest.raises(CredentialBackendUnavailable):
        backend(tmp_path, py("print('x')")).set(KEY, Secret(SECRET))


@pytest.mark.parametrize(
    "value", ["a\nb", "a\rb", "a\0b", "", "x" * CEILINGS["credential_command_output_bytes"]]
)
def test_set_refuses_what_get_would_refuse_before_any_spawn(tmp_path: Path, value: str) -> None:
    marker = tmp_path / "spawned"
    b = backend(tmp_path, py("print('x')"), py(f"open({str(marker)!r}, 'w')"))
    with pytest.raises(CredentialRejected):
        b.set(KEY, Secret(value))
    assert not marker.exists()


@pytest.mark.parametrize(
    "output",
    [b"", b"\n", b"line1\nline2\n", b"a\rb", b"a\x00b", b"caf\xe9", b"two\r\n\r\n"],
)
def test_get_refuses_output_the_secret_rule_refuses(tmp_path: Path, output: bytes) -> None:
    bind(tmp_path)
    code = f"import sys; sys.stdout.buffer.write({output!r})"
    with pytest.raises(CredentialRejected):
        backend(tmp_path, py(code)).get(KEY)


def test_get_strips_one_line_ending(tmp_path: Path) -> None:
    bind(tmp_path)
    assert backend(tmp_path, py(f"print({SECRET!r})")).get(KEY).reveal() == SECRET


def test_nonzero_exit_is_a_fixed_error_without_stderr(tmp_path: Path) -> None:
    bind(tmp_path)
    code = (
        "import sys; sys.stderr.write('hunter2-leak'); sys.stdout.write('hunter2-leak'); "
        "sys.exit(4)"
    )
    with pytest.raises(CredentialBackendError) as info:
        backend(tmp_path, py(code)).get(KEY)
    assert "hunter2" not in str(info.value) + repr(info.value.args)
    assert info.value.__cause__ is None
    assert info.value.__suppress_context__


def test_sleeping_command_times_out_within_bound(tmp_path: Path) -> None:
    bind(tmp_path)
    b = backend(tmp_path, py("import time; time.sleep(60)"))
    start = time.monotonic()
    with pytest.raises(CredentialTimeout):
        b.get(KEY)
    assert time.monotonic() - start < SECONDS + MARGIN


def test_stdout_flood_is_limit_exceeded(tmp_path: Path) -> None:
    bind(tmp_path)
    b = backend(
        tmp_path,
        py("import sys\nwhile True: sys.stdout.buffer.write(b'x' * 65536)"),
        limits=SLOW_LIMITS,
    )
    start = time.monotonic()
    with pytest.raises(CredentialLimitExceeded):
        b.get(KEY)
    assert time.monotonic() - start < SLOW_LIMITS.credential_command_seconds


def test_stderr_megabytes_are_bounded_and_do_not_fail_the_call(tmp_path: Path) -> None:
    bind(tmp_path)
    code = (
        "import sys\nfor _ in range(64): sys.stderr.buffer.write(b'e' * 65536)\nprint('ok-secret')"
    )
    tracemalloc.start()
    try:
        assert backend(tmp_path, py(code), limits=SLOW_LIMITS).get(KEY).reveal() == "ok-secret"
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 4 * 1024 * 1024


def test_partial_output_before_a_timeout_is_discarded(tmp_path: Path) -> None:
    bind(tmp_path)
    b = backend(tmp_path, py("import time; print('half', flush=True); time.sleep(60)"))
    with pytest.raises(CredentialTimeout) as info:
        b.get(KEY)
    assert "half" not in str(info.value)


def test_same_session_grandchild_holding_stdout(tmp_path: Path) -> None:
    bind(tmp_path)
    pid_file = tmp_path / "grandchild.pid"
    code = (
        "import subprocess, sys\n"
        "p = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(60)'])\n"
        f"open({str(pid_file)!r}, 'w').write(str(p.pid))\n"
        "print('secret-looking')"
    )
    start = time.monotonic()
    with pytest.raises(CredentialTimeout):
        backend(tmp_path, py(code)).get(KEY)
    assert time.monotonic() - start < SECONDS + MARGIN
    assert pid_dead(read_pid(pid_file)), "grandchild left behind"


@posix_only
def test_setsid_descendant_holding_stdout(tmp_path: Path) -> None:
    bind(tmp_path)
    pid_file = tmp_path / "escaped.pid"
    code = (
        "import os, time\n"
        "if os.fork() == 0:\n"
        "    os.setsid()\n"
        f"    open({str(pid_file)!r}, 'w').write(str(os.getpid()))\n"
        "    time.sleep(60)\n"
        "    os._exit(0)\n"
        "print('x', flush=True)\n"
        "os._exit(0)"
    )
    try:
        start = time.monotonic()
        with pytest.raises(CredentialTimeout):
            backend(tmp_path, py(code)).get(KEY)
        assert time.monotonic() - start < SECONDS + MARGIN
    finally:
        if pid_file.exists() and pid_file.read_text():
            with contextlib.suppress(ProcessLookupError):
                os.kill(int(pid_file.read_text()), signal.SIGKILL)


def test_set_child_that_neither_reads_stdin_nor_exits(tmp_path: Path) -> None:
    b = backend(tmp_path, py("print('x')"), py("import time; time.sleep(60)"))
    start = time.monotonic()
    with pytest.raises(CredentialTimeout):
        b.set(KEY, Secret(SECRET))
    assert time.monotonic() - start < SECONDS + MARGIN
    assert not binding_path(tmp_path / "data", KEY).exists()


@posix_only
def test_environment_is_minimal_and_carries_the_allowlisted_names(tmp_path: Path) -> None:
    bind(tmp_path)
    code = "import json, os; print(json.dumps(sorted(os.environ)))"
    environ = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": "/h",
        "GNUPGHOME": "/g",
        "PASSWORD_STORE_DIR": "/s",
        "GPG_AGENT_INFO": "x",
        "SECRET_THING": "x",
        "PYTHON_KEYRING_BACKEND": "k",
    }
    names = json.loads(backend(tmp_path, py(code), environ=environ).get(KEY).reveal())
    assert {"GNUPGHOME", "PASSWORD_STORE_DIR", "HOME"} <= set(names)
    assert not {"SECRET_THING", "GPG_AGENT_INFO", "PYTHON_KEYRING_BACKEND"} & set(names)


def test_cwd_is_the_data_dir(tmp_path: Path) -> None:
    bind(tmp_path)
    got = backend(tmp_path, py("import os; print(os.getcwd())")).get(KEY).reveal()
    assert Path(got).resolve() == (tmp_path / "data").resolve()


def test_non_absolute_executable_is_refused_before_spawn(tmp_path: Path) -> None:
    bind(tmp_path)
    with pytest.raises(CredentialBackendError):
        backend(tmp_path, ["pass", "show", "x"]).get(KEY)


def test_env_name_outside_the_allowlist_is_refused(tmp_path: Path) -> None:
    bind(tmp_path)
    with pytest.raises(CredentialBackendError):
        backend(tmp_path, py("print('x')"), env={"LD_PRELOAD": "/x.so"}).get(KEY)


@pytest.mark.parametrize(
    "opts",
    [
        "--passphrase hunter2",
        "--passphrase=hunter2",
        "--passph=hunter2",
        "--pinentry-mode=loopback",
        "--pinentry-mode error",
        "--pinentry-mode",
        "--status-fd=1",
        "--output /x",
        "-o /x",
        "--multifile",
        "--log-file /x",
        "--agent-program /x",
        "--keyserver x",
        "--auto-key-retrieve",
        "--auto-key-locate x",
        "--options /x",
        "--homedir /x",
        "-q",
        "--",
        "--quiet --passphrase x",
        "--pinentry-mode=error --output=/x",
    ],
)
def test_gpg_opts_outside_the_allowlist_are_refused_before_spawn(tmp_path: Path, opts: str) -> None:
    bind(tmp_path)
    marker = tmp_path / "spawned"
    code = f"open({str(marker)!r}, 'w'); print('x')"
    env = {"PASSWORD_STORE_GPG_OPTS": opts}
    with pytest.raises(CredentialBackendError):
        backend(tmp_path, py(code), env=env).get(KEY)
    with pytest.raises(CredentialBackendError):
        backend(tmp_path, py("print('x')"), py(code), env=env).set(KEY, Secret(SECRET))
    assert not marker.exists()


@pytest.mark.parametrize("opts", ["--pinentry-mode=error", "--quiet --no-tty", ""])
def test_allowlisted_gpg_opts_are_accepted(tmp_path: Path, opts: str) -> None:
    bind(tmp_path)
    store = tmp_path / "store"
    get, set_ = store_commands(store)
    b = backend(tmp_path, get, set_, env={"PASSWORD_STORE_GPG_OPTS": opts})
    b.set(KEY, Secret(SECRET))
    assert b.get(KEY).reveal() == SECRET


@pytest.mark.parametrize("name", ["PASSWORD_STORE_GPG_OPTS", "PASSWORD_STORE_DIR", "GNUPGHOME"])
@pytest.mark.parametrize("value", ["a\nb", "a\rb", "a\0b"])
def test_control_characters_in_env_values_are_refused_before_spawn(
    tmp_path: Path, name: str, value: str
) -> None:
    bind(tmp_path)
    marker = tmp_path / "spawned"
    with pytest.raises(CredentialBackendError):
        backend(tmp_path, py(f"open({str(marker)!r}, 'w')"), env={name: value}).get(KEY)
    assert not marker.exists()


def test_refused_set_keeps_a_valid_binding(tmp_path: Path) -> None:
    bind(tmp_path)
    for set_argv, env in (
        (["relative-tool"], None),
        (py("print('x')"), {"LD_PRELOAD": "/x.so"}),
        (py("print('x')"), {"PASSWORD_STORE_GPG_OPTS": "--passphrase x"}),
    ):
        b = backend(tmp_path, py("print('x')"), set_argv, env=env)
        with pytest.raises(CredentialBackendError):
            b.set(KEY, Secret(SECRET))
        assert binding_path(tmp_path / "data", KEY).exists()


def test_describe_is_secure_only_for_the_pass_recipe(tmp_path: Path) -> None:
    assert not backend(tmp_path, py("print('x')")).describe().secure
    if sys.platform != "win32":
        assert backend(tmp_path, ["/usr/bin/pass", "show", "x"]).describe().secure


SPECIAL = 'pa"ss\\w0rd'  # pii-check: ignore


def _forms(login: str) -> list[str]:
    import base64

    quoted = SPECIAL.replace("\\", "\\\\").replace('"', '\\"')
    blob = base64.b64encode(f"\0{login}\0{SPECIAL}".encode()).decode("ascii")
    return [SPECIAL, quoted, blob]


@pytest.fixture
def clean_redaction() -> Iterator[None]:
    from mailferret.logging import clear_secrets

    clear_secrets()
    yield
    clear_secrets()


@pytest.mark.usefixtures("clean_redaction")
@pytest.mark.parametrize("via", ["get", "set"])
def test_secret_forms_are_registered_for_redaction(tmp_path: Path, via: str) -> None:
    from mailferret.logging import redact

    bind(tmp_path)
    store = tmp_path / "store"
    get, set_ = store_commands(store)
    b = backend(tmp_path, get, set_)
    if via == "get":
        store.write_text(SPECIAL)
        assert redact(SPECIAL) == SPECIAL
        b.get(KEY)
    else:
        b.set(KEY, Secret(SPECIAL))
    for form in _forms(KEY.login):
        assert redact(f"line {form} end") == "line *** end"


@pytest.mark.usefixtures("clean_redaction")
@pytest.mark.parametrize("code", [0, 7])
def test_secret_on_stderr_never_reaches_logs_or_output(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    capfd: pytest.CaptureFixture[str],
    code: int,
) -> None:
    bind(tmp_path)
    script = f"import sys; sys.stderr.write({SECRET!r}); print({SECRET!r}); sys.exit({code})"
    with caplog.at_level(logging.DEBUG):
        try:
            backend(tmp_path, py(script)).get(KEY)
        except CredentialBackendError as exc:
            assert SECRET not in str(exc) + repr(exc.args)
    out = capfd.readouterr()
    assert SECRET not in caplog.text + out.out + out.err


def test_describe_names_only_the_executable(tmp_path: Path) -> None:
    d = backend(tmp_path, [sys.executable, "-c", "x"]).describe()
    assert (d.kind, d.backend) == ("command", Path(sys.executable).name)


FAKE_SCRIPT = """#!{python}
import os, re, sys, time
opts = os.environ.get("PASSWORD_STORE_GPG_OPTS", "")
fd = int(re.findall(r"--status-fd=(\\d+)", opts)[-1])
{body}
"""


@pytest.fixture
def fake_pass(tmp_path: Path) -> Callable[[str], list[str]]:
    def make(body: str) -> list[str]:
        path = tmp_path / "bin" / "pass"
        path.parent.mkdir(exist_ok=True)
        path.write_text(FAKE_SCRIPT.format(python=sys.executable, body=body))
        path.chmod(0o755)
        return [str(path), "show", "mailferret/work"]

    return make


LOCKED_LINE = "[GNUPG:] ERROR pkdecrypt_failed 67108949\\n"


@posix_only
def test_recipe_environment(
    tmp_path: Path, fake_pass: Callable[[str], list[str]], request: pytest.FixtureRequest
) -> None:
    bind(tmp_path)
    held = [os.open(os.devnull, os.O_RDONLY) for _ in range(12)]
    request.addfinalizer(lambda: [os.close(fd) for fd in held])
    body = "print(opts + '|' + os.environ['LC_ALL'])"
    argv = fake_pass(body)
    out = backend(tmp_path, argv, env={"PASSWORD_STORE_GPG_OPTS": "--quiet"}).get(KEY)
    opts, lc_all = out.reveal().split("|")
    fd = opts.rsplit("=", 1)[1]
    assert opts.startswith("--quiet --pinentry-mode=error --status-fd=")
    assert opts.endswith(f"--status-fd={fd}")
    assert lc_all == "C"
    assert int(fd) >= 12


@posix_only
@pytest.mark.parametrize("fds_open", [0, 12])
def test_locked_from_status_code(
    tmp_path: Path, fake_pass: Callable[[str], list[str]], fds_open: int
) -> None:
    bind(tmp_path)
    held = [os.open(os.devnull, os.O_RDONLY) for _ in range(fds_open)]
    try:
        body = (
            f"os.write(fd, b'{LOCKED_LINE}')\n"
            "sys.stderr.write('gpg: public key decryption failed: No pinentry')\n"
            "sys.exit(2)"
        )
        with pytest.raises(CredentialLocked):
            backend(tmp_path, fake_pass(body)).get(KEY)  # type: ignore[operator]
    finally:
        for fd in held:
            os.close(fd)


@posix_only
@pytest.mark.parametrize(
    "line",
    [
        "[GNUPG:] ERROR pkdecrypt_failed 83918929\\n",
        "[GNUPG:] ERROR pkdecrypt_failed 67108949 extra\\n",
        "[GNUPG:] NO_SECKEY ABCDEF\\n",
        "[GNUPG:] DECRYPTION_FAILED\\n",
        "[GNUPG:] ERROR pkdecrypt_failed 67108949",
        "",
    ],
)
def test_other_failures_are_errors_not_locked(
    tmp_path: Path, fake_pass: Callable[[str], list[str]], line: str
) -> None:
    bind(tmp_path)
    body = f"os.write(fd, b'{line}')\nsys.stderr.write('No pinentry')\nsys.exit(2)"
    with pytest.raises(CredentialBackendError) as info:
        backend(tmp_path, fake_pass(body)).get(KEY)  # type: ignore[operator]
    assert not isinstance(info.value, CredentialLocked)


@posix_only
def test_locked_status_is_ignored_on_exit_zero(
    tmp_path: Path, fake_pass: Callable[[str], list[str]]
) -> None:
    bind(tmp_path)
    body = f"os.write(fd, b'{LOCKED_LINE}')\nprint('fine')"
    assert backend(tmp_path, fake_pass(body)).get(KEY).reveal() == "fine"  # type: ignore[operator]


@posix_only
def test_status_text_alone_on_stderr_does_not_make_locked(
    tmp_path: Path, fake_pass: Callable[[str], list[str]]
) -> None:
    bind(tmp_path)
    body = f"sys.stderr.write('{LOCKED_LINE}')\nsys.exit(2)"
    with pytest.raises(CredentialBackendError) as info:
        backend(tmp_path, fake_pass(body)).get(KEY)  # type: ignore[operator]
    assert not isinstance(info.value, CredentialLocked)


@posix_only
def test_not_found_from_pass_message(tmp_path: Path, fake_pass: Callable[[str], list[str]]) -> None:
    bind(tmp_path)
    body = (
        "sys.stderr.write('Error: mailferret/work is not in the password store.\\n')\nsys.exit(1)"
    )
    with pytest.raises(CredentialNotFound):
        backend(tmp_path, fake_pass(body)).get(KEY)  # type: ignore[operator]


@posix_only
def test_status_flood_after_the_locked_line_keeps_locked_and_bounds_memory(
    tmp_path: Path, fake_pass: Callable[[str], list[str]]
) -> None:
    bind(tmp_path)
    body = (
        f"os.write(fd, b'{LOCKED_LINE}')\n"
        "for _ in range(64): os.write(fd, b'[GNUPG:] USERID_HINT ' + b'k' * 65000 + b'\\n')\n"
        "sys.exit(2)"
    )
    argv = fake_pass(body)
    tracemalloc.start()
    try:
        start = time.monotonic()
        with pytest.raises(CredentialLocked):
            backend(tmp_path, argv).get(KEY)
        elapsed = time.monotonic() - start
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 4 * 1024 * 1024
    assert elapsed < SECONDS + MARGIN


@posix_only
def test_locked_line_past_the_status_cap_is_not_seen(
    tmp_path: Path, fake_pass: Callable[[str], list[str]]
) -> None:
    bind(tmp_path)
    cap = CEILINGS["credential_status_bytes"]
    body = (
        f"os.write(fd, b'[GNUPG:] USERID_HINT ' + b'k' * {cap} + b'\\n')\n"
        f"os.write(fd, b'{LOCKED_LINE}')\n"
        "sys.exit(2)"
    )
    with pytest.raises(CredentialBackendError) as info:
        backend(tmp_path, fake_pass(body)).get(KEY)  # type: ignore[operator]
    assert not isinstance(info.value, CredentialLocked)


@posix_only
def test_status_pipe_held_by_setsid_descendant_is_a_timeout_not_locked(
    tmp_path: Path, fake_pass: Callable[[str], list[str]]
) -> None:
    bind(tmp_path)
    pid_file = tmp_path / "holder.pid"
    body = (
        "if os.fork() == 0:\n"
        "    os.setsid()\n"
        f"    open({str(pid_file)!r}, 'w').write(str(os.getpid()))\n"
        "    time.sleep(60)\n"
        "    os._exit(0)\n"
        f"os.write(fd, b'{LOCKED_LINE}')\n"
        "sys.exit(2)"
    )
    argv = fake_pass(body)
    try:
        start = time.monotonic()
        with pytest.raises(CredentialTimeout):
            backend(tmp_path, argv).get(KEY)
        assert time.monotonic() - start < SECONDS + MARGIN
    finally:
        if pid_file.exists() and pid_file.read_text():
            with contextlib.suppress(ProcessLookupError):
                os.kill(int(pid_file.read_text()), signal.SIGKILL)


@posix_only
def test_a_command_not_named_pass_gets_no_recipe(tmp_path: Path) -> None:
    bind(tmp_path)
    code = "import os; print(os.environ.get('PASSWORD_STORE_GPG_OPTS', 'unset'))"
    assert backend(tmp_path, py(code)).get(KEY).reveal() == "unset"


@windows_only
def test_job_object_kills_a_grandchild_holding_stdout(tmp_path: Path) -> None:
    bind(tmp_path)
    pid_file = tmp_path / "grandchild.pid"
    code = (
        "import subprocess, sys\n"
        "p = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(60)'])\n"
        f"open({str(pid_file)!r}, 'w').write(str(p.pid))\n"
        "print('x', flush=True)"
    )
    start = time.monotonic()
    with pytest.raises(CredentialTimeout):
        backend(tmp_path, py(code)).get(KEY)
    assert time.monotonic() - start < SECONDS + MARGIN
    assert pid_dead(read_pid(pid_file)), "grandchild left behind"


@windows_only
def test_job_object_kills_a_descendant_that_tries_to_break_away(tmp_path: Path) -> None:
    bind(tmp_path)
    pid_file = tmp_path / "breakaway.pid"
    sleeper = "[sys.executable, '-I', '-c', 'import time; time.sleep(60)']"
    code = (
        "import subprocess, sys\n"
        "try:\n"
        f"    p = subprocess.Popen({sleeper}, creationflags=subprocess.CREATE_BREAKAWAY_FROM_JOB)\n"
        "except OSError:\n"
        f"    p = subprocess.Popen({sleeper})\n"
        f"open({str(pid_file)!r}, 'w').write(str(p.pid))\n"
        "print('x', flush=True)"
    )
    start = time.monotonic()
    with pytest.raises(CredentialTimeout):
        backend(tmp_path, py(code)).get(KEY)
    assert time.monotonic() - start < SECONDS + MARGIN
    assert pid_dead(read_pid(pid_file)), "descendant escaped the job object"


@windows_only
def test_set_child_that_neither_reads_stdin_nor_exits_on_windows(tmp_path: Path) -> None:
    b = backend(tmp_path, py("print('x')"), py("import time; time.sleep(60)"))
    start = time.monotonic()
    with pytest.raises(CredentialTimeout):
        b.set(KEY, Secret(SECRET))
    assert time.monotonic() - start < SECONDS + MARGIN
