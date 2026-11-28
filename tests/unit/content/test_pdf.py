"""T-06: PDF worker caps, hardened pypdf configuration, bombs, host fail-closed behaviour."""

from __future__ import annotations

import base64
import dataclasses
import inspect
import json
import os
import stat
import sys
import threading
import time
import typing
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pypdf import Configuration, PdfReader, apply_configuration, get_configuration

from mailferret.content import pdf_host
from mailferret.content.extractors import DEFAULT_EXTRACTORS, extract_text
from mailferret.content.mime import PartInfo
from mailferret.content.pdf_host import extract_pdf, parse_result, run_bounded, worker_argv
from mailferret.content.pdf_worker import (
    PAGE_ENTRY_FACTOR,
    PAGE_TREE_DEPTH,
    PAGE_TREE_FACTOR,
    WorkerLimits,
    extract,
    hardened_overrides,
    hardening_gaps,
)
from mailferret.limits import CEILINGS, MIB, Limits
from tests.fixtures import generators

LIMITS = Limits()
STREAM = LIMITS.pdf_stream_bytes
PY = sys.executable


def kinds(result: pdf_host.PdfText) -> list[tuple[str, str | None]]:
    """Notes, without the platform-dependent memory-cap note (asserted on its own)."""
    return [(n.kind, n.limit) for n in result.notes if n.kind != "memory_cap_unavailable"]


def python(code: str) -> list[str]:
    return [PY, "-I", "-c", code]


# --- pypdf configuration ---------------------------------------------------------------------


def applied(limits: Limits = LIMITS) -> dict[str, object]:
    return hardened_overrides(Configuration(), stream_bytes=limits.pdf_stream_bytes)


def test_no_integer_field_exceeds_the_stream_cap() -> None:
    assert hardening_gaps(Configuration(), stream_bytes=STREAM), "pypdf defaults are above the cap"
    with apply_configuration(**applied()):
        config = get_configuration()
        assert hardening_gaps(config, stream_bytes=STREAM) == []
        for field in dataclasses.fields(config):
            value = getattr(config, field.name)
            if type(value) is int:
                assert value <= STREAM, field.name


def program_fields() -> list[str]:
    hints = typing.get_type_hints(Configuration)
    return [
        f.name
        for f in dataclasses.fields(Configuration)
        if str in typing.get_args(hints[f.name]) and type(None) in typing.get_args(hints[f.name])
    ]


def test_every_program_field_is_overridden_to_none() -> None:
    names = program_fields()
    assert "jbig2dec_binary" in names
    for name in names:
        configured = dataclasses.replace(Configuration(), **{name: "/x/prog"})
        overrides = hardened_overrides(configured, stream_bytes=STREAM)
        with apply_configuration(configured, **overrides):
            assert getattr(get_configuration(), name) is None, name


def test_page_tree_fields_derive_from_the_l09_ceiling_and_a_fixed_depth() -> None:
    overrides = applied(Limits(max_pdf_pages=1))
    tree = PAGE_TREE_FACTOR * CEILINGS["max_pdf_pages"]
    assert overrides["page_tree_maximum_entries"] == tree
    assert overrides["page_tree_maximum_page_entries"] == tree * PAGE_ENTRY_FACTOR
    assert overrides["page_tree_maximum_depth"] == PAGE_TREE_DEPTH


@pytest.mark.parametrize("pages", [1, 2])
def test_a_lowered_page_limit_still_reads_ordinary_documents(pages: int) -> None:
    small = Limits(max_pdf_pages=pages)
    flat = extract_pdf(generators.plain_pdf(pages=25), small)
    assert flat.text is not None and flat.text.count("Hello PDF") == pages
    assert kinds(flat) == [("limit_exceeded", "L-09")]
    nested = extract_pdf(generators.nested_page_tree_pdf(pages=5, depth=3), small)
    assert nested.text is not None and nested.text.count("Hello PDF") == pages
    assert kinds(nested) == [("limit_exceeded", "L-09")]


def test_reader_constructor_limits_stay_at_pypdf_defaults() -> None:
    params = inspect.signature(PdfReader.__init__).parameters
    assert params["root_object_recovery_limit"].default == 10_000
    assert params["xref_stream_maximum_entries"].default == 2_000_000
    assert params["xref_rebuild_maximum_entries"].default == 2_000_000
    seen: list[dict[str, object]] = []

    class Spy(PdfReader):
        def __init__(self, *args: object, **kwargs: object) -> None:
            seen.append(dict(kwargs))
            super().__init__(*args, **kwargs)  # type: ignore[arg-type]

    import pypdf

    original = pypdf.PdfReader
    pypdf.PdfReader = Spy  # type: ignore[misc]
    try:
        extract(generators.plain_pdf(), worker_limits())
    finally:
        pypdf.PdfReader = original  # type: ignore[misc]
    assert seen == [{}]


def worker_limits(**changes: int) -> WorkerLimits:
    base = WorkerLimits(
        pages=LIMITS.max_pdf_pages,
        chars=LIMITS.max_body_chars,
        stream_bytes=STREAM,
        memory=LIMITS.pdf_worker_memory_bytes,
        input_bytes=LIMITS.max_attachment_bytes,
    )
    return dataclasses.replace(base, **changes)


def test_configuration_is_applied_in_the_parsing_thread() -> None:
    import pypdf

    seen: list[list[str]] = []

    class Spy(PdfReader):
        def __init__(self, *args: object, **kwargs: object) -> None:
            super().__init__(*args, **kwargs)  # type: ignore[arg-type]
            seen.append(hardening_gaps(get_configuration(), stream_bytes=STREAM))

    original = pypdf.PdfReader
    pypdf.PdfReader = Spy  # type: ignore[misc]
    out: list[bytes] = []
    try:
        thread = threading.Thread(
            target=lambda: out.append(extract(generators.plain_pdf(), worker_limits()))
        )
        thread.start()
        thread.join()
    finally:
        pypdf.PdfReader = original  # type: ignore[misc]
    assert seen == [[]]
    assert json.loads(out[0])["text"] == "Hello PDF"


# --- the worker end to end -------------------------------------------------------------------


def test_plain_pdf_text() -> None:
    result = extract_pdf(generators.plain_pdf())
    assert result.text == "Hello PDF"
    assert kinds(result) == []
    assert not result.truncated


def test_injection_text_is_returned_as_data() -> None:
    result = extract_pdf(generators.injection_pdf())
    assert result.text is not None and "CANARY" in result.text


def test_deflate_bomb_between_the_cap_and_the_pypdf_default_is_limited() -> None:
    inflated = STREAM + 8 * MIB  # below pypdf's own 75 MB default
    started = time.monotonic()
    result = extract_pdf(generators.deflate_bomb_pdf(inflated))
    assert result.text is None
    assert ("limit_exceeded", "L-10") in kinds(result)
    assert time.monotonic() - started < LIMITS.pdf_worker_seconds


def test_page_bomb_of_100000_pages_is_limited() -> None:
    started = time.monotonic()
    result = extract_pdf(generators.page_bomb_pdf(100_000))
    assert result.text is None
    assert ("limit_exceeded", "L-09") in kinds(result)
    assert time.monotonic() - started < LIMITS.pdf_worker_seconds


def test_cyclic_page_tree_ends_without_text_inside_the_timeout() -> None:
    started = time.monotonic()
    result = extract_pdf(generators.cyclic_page_tree_pdf())
    assert result.text is None
    assert kinds(result) == [("malformed", None)]
    assert time.monotonic() - started < LIMITS.pdf_worker_seconds


def test_more_pages_than_the_limit_keeps_the_first_pages_and_says_so() -> None:
    result = extract_pdf(generators.plain_pdf(pages=LIMITS.max_pdf_pages + 1))
    assert result.text is not None
    assert result.text.count("Hello PDF") == LIMITS.max_pdf_pages
    assert result.truncated
    assert kinds(result) == [("limit_exceeded", "L-09")]


def test_page_tree_beyond_the_derived_bound_is_limited() -> None:
    pages = PAGE_TREE_FACTOR * LIMITS.max_pdf_pages  # the root node counts as an entry
    within = extract_pdf(generators.plain_pdf(pages=pages - 1))
    assert within.text is not None and within.truncated
    beyond = extract_pdf(generators.plain_pdf(pages=pages + 1))
    assert beyond.text is None
    assert ("limit_exceeded", "L-09") in kinds(beyond)


def test_text_is_capped_at_the_char_limit() -> None:
    small = Limits(max_body_chars=50)
    result = extract_pdf(generators.plain_pdf(text="x" * 200), small)
    assert result.text == "x" * 50
    assert result.truncated
    assert ("limit_exceeded", "L-03") in kinds(result)


def test_malformed_and_truncated_inputs_cost_a_note_only() -> None:
    for data in (b"", b"not a pdf", generators.truncated_pdf(), b"%PDF-1.4\n" + b"\0" * 1000):
        result = extract_pdf(data)
        assert result.text is None
        assert kinds(result)


def test_input_over_the_attachment_limit_never_spawns(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise AssertionError("worker spawned")

    monkeypatch.setattr(pdf_host, "run_bounded", boom)
    result = extract_pdf(b"%PDF-" + b"0" * LIMITS.max_attachment_bytes)
    assert kinds(result) == [("limit_exceeded", "L-08")]


def test_worker_itself_refuses_input_over_its_cap() -> None:
    argv = [PY, "-I", "-m", pdf_host.WORKER_MODULE]
    for name, value in (
        ("pages", 5),
        ("chars", 100),
        ("stream-bytes", STREAM),
        ("memory", 512 * MIB),
        ("input-bytes", 10),
    ):
        argv += [f"--{name}", str(value)]
    result = run_bounded(argv, b"x" * 11, deadline=20, memory_bytes=512 * MIB, stdout_cap=65536)
    assert result.returncode == 0
    assert json.loads(result.stdout)["notes"] == [["limit_exceeded", "L-08"]]


@pytest.mark.parametrize("args", [[], ["--pages", "0"], ["--pages", "x"] * 5, ["a"] * 10])
def test_worker_rejects_bad_arguments(args: list[str]) -> None:
    result = run_bounded(
        [PY, "-I", "-m", pdf_host.WORKER_MODULE, *args],
        b"",
        deadline=20,
        memory_bytes=512 * MIB,
        stdout_cap=1024,
    )
    assert result.returncode == 2
    assert result.stdout == b""


# --- jbig2dec -------------------------------------------------------------------------------


def fake_jbig2dec(directory: Path) -> Path:
    log = directory / "runs.log"
    if sys.platform == "win32":
        script = directory / "jbig2dec.bat"
        script.write_text(f'@echo run>>"{log}"\r\n@exit /b 1\r\n')
    else:
        script = directory / "jbig2dec"
        script.write_text(f'#!/bin/sh\necho run >> "{log}"\nexit 1\n')
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return log


def test_jbig2_stream_spawns_no_process_and_yields_a_note(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = fake_jbig2dec(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
    result = extract_pdf(generators.jbig2_content_pdf())
    assert not log.exists(), "jbig2dec was run"
    assert result.text is None or result.text == ""
    assert kinds(result)


def test_the_fake_jbig2dec_is_run_when_the_override_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Control: without the ``None`` override pypdf finds and runs the program on ``PATH``."""
    log = fake_jbig2dec(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
    pdf = tmp_path / "in.pdf"
    pdf.write_bytes(generators.jbig2_content_pdf())
    script = tmp_path / "control.py"
    script.write_text(
        "import sys\n"
        "from mailferret.content import pdf_worker as w\n"
        "w.hardened_overrides = lambda *a, **k: {}\n"
        "w.hardening_gaps = lambda *a, **k: []\n"
        "limits = w.WorkerLimits(50, 100000, 1 << 25, 1 << 29, 1 << 24)\n"
        "w.extract(open(sys.argv[1], 'rb').read(), limits)\n"
    )
    run_bounded(
        [PY, "-I", str(script), str(pdf)],
        b"",
        deadline=30,
        memory_bytes=LIMITS.pdf_worker_memory_bytes,
        stdout_cap=65536,
    )
    assert log.exists()


# --- the host --------------------------------------------------------------------------------


def test_timeout_returns_within_the_deadline_and_kills_the_worker() -> None:
    started = time.monotonic()
    result = run_bounded(
        python("import time; time.sleep(60)"),
        b"",
        deadline=1,
        memory_bytes=LIMITS.pdf_worker_memory_bytes,
        stdout_cap=1024,
    )
    assert result.status == "timeout"
    assert result.returncode is not None
    assert time.monotonic() - started < 10


def test_hanging_worker_maps_to_limit_exceeded(monkeypatch: pytest.MonkeyPatch) -> None:
    started = time.monotonic()
    result = extract_pdf(
        generators.plain_pdf(),
        Limits(pdf_worker_seconds=1),
        argv=python("import time; time.sleep(60)"),
    )
    assert kinds(result) == [("limit_exceeded", "L-10")]
    assert time.monotonic() - started < 10


def test_output_flood_is_cut_and_limited() -> None:
    started = time.monotonic()
    result = extract_pdf(
        generators.plain_pdf(),
        argv=python("import sys; sys.stdout.buffer.write(b'a' * (64 * 1024 * 1024))"),
    )
    assert result.text is None
    assert kinds(result) == [("limit_exceeded", "L-03")]
    assert time.monotonic() - started < 20


def test_stderr_flood_does_not_block_the_worker() -> None:
    result = extract_pdf(
        generators.plain_pdf(),
        argv=python(
            "import sys; sys.stderr.write('e' * (4 * 1024 * 1024)); "
            'sys.stdout.write(\'{"v":1,"text":"ok","truncated":false,"notes":[]}\')'
        ),
    )
    assert result.text == "ok"


def test_failed_worker_and_garbage_output_fail_closed() -> None:
    for code in ("import sys; sys.exit(3)", "print('not json')", "print('[1]')", "print('')"):
        assert kinds(extract_pdf(b"%PDF-", argv=python(code))) == [("part_failed", None)]


def test_missing_interpreter_fails_closed() -> None:
    result = extract_pdf(b"%PDF-", argv=["/nonexistent/python-for-mailferret"])
    assert kinds(result) == [("part_failed", None)]


@pytest.mark.parametrize(
    "body",
    [
        {"v": 2, "text": "", "truncated": False, "notes": []},
        {"v": 1, "text": 1, "truncated": False, "notes": []},
        {"v": 1, "text": "", "truncated": "no", "notes": []},
        {"v": 1, "text": "", "truncated": False, "notes": [["nope", None]]},
        {"v": 1, "text": "", "truncated": False, "notes": [["malformed", "evil text"]]},
        {"v": 1, "text": "", "truncated": False, "notes": [["malformed", None, 1]]},
        {"v": 1, "text": "", "truncated": False, "notes": [["malformed", None]] * 17},
        {"v": 1, "text": "", "truncated": False, "notes": "x"},
    ],
)
def test_result_validation(body: object) -> None:
    result = parse_result(json.dumps(body).encode(), LIMITS)
    assert kinds(result) == [("part_failed", None)]


def test_result_text_is_recapped_and_scrubbed() -> None:
    small = Limits(max_body_chars=10)
    raw = json.dumps({"v": 1, "text": "a" * 50, "truncated": False, "notes": []}).encode()
    result = parse_result(raw, small)
    assert result.text == "a" * 10 and result.truncated
    assert ("limit_exceeded", "L-03") in kinds(result)
    lone = b'{"v":1,"text":"a\\ud800b","truncated":false,"notes":[]}'
    kept = parse_result(lone, LIMITS).text
    assert kept is not None
    kept.encode("utf-8")


def test_worker_environment_is_minimal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MAILFERRET_TEST_CANARY", "secret")
    result = run_bounded(
        python("import os; print(os.environ.get('MAILFERRET_TEST_CANARY', 'absent'))"),
        b"",
        deadline=20,
        memory_bytes=LIMITS.pdf_worker_memory_bytes,
        stdout_cap=1024,
    )
    assert result.stdout.strip() == b"absent"


def test_argv_carries_the_limits_and_isolated_mode() -> None:
    small = Limits(max_pdf_pages=7, max_body_chars=99)
    argv = worker_argv(small)
    assert argv[1:4] == ["-I", "-m", pdf_host.WORKER_MODULE]
    assert argv[argv.index("--pages") + 1] == "7"
    assert argv[argv.index("--chars") + 1] == "99"
    assert argv[argv.index("--memory") + 1] == str(small.pdf_worker_memory_bytes)
    assert argv[argv.index("--stream-bytes") + 1] == str(small.pdf_stream_bytes)


# --- memory cap ------------------------------------------------------------------------------

CAP = 256 * MIB
HOG = 768 * MIB


def hog(cap_for_worker: int, job_cap: int) -> pdf_host.RunResult:
    """The production cap function and spawn function around an allocation over the cap."""
    code = (
        "from mailferret.content.pdf_worker import apply_memory_limit; "
        f"apply_memory_limit({cap_for_worker}); "
        f"data = bytearray({HOG}); data[::4096] = b'x' * len(data[::4096]); print('survived')"
    )
    return run_bounded(python(code), b"", deadline=60, memory_bytes=job_cap, stdout_cap=1024)


def test_memory_hog_survives_without_a_cap() -> None:
    result = hog(4096 * MIB, 4096 * MIB)
    assert result.stdout.strip() == b"survived", "control: the hog must fit without a cap"


@pytest.mark.skipif(sys.platform == "darwin", reason="macOS enforcement is pinned from CI")
def test_memory_cap_stops_the_hog() -> None:
    result = hog(CAP, CAP)
    assert result.status == "exited"
    assert result.stdout.strip() != b"survived"
    assert result.returncode != 0


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS behaviour")
def test_macos_rlimit_as_is_not_enforced_so_the_fallback_bound_applies() -> None:
    """Observed on the macOS runners: ``setrlimit`` is refused and the allocation succeeds."""
    result = hog(CAP, CAP)
    assert result.stdout.strip() == b"survived", f"enforced now? rc={result.returncode}"


def test_apply_memory_limit_reports_what_the_os_did() -> None:
    code = (
        "from mailferret.content.pdf_worker import apply_memory_limit; "
        f"print(apply_memory_limit({4096 * MIB}))"
    )
    result = run_bounded(python(code), b"", deadline=20, memory_bytes=4096 * MIB, stdout_cap=1024)
    assert result.stdout.strip() in (b"True", b"False")
    if sys.platform.startswith("linux"):
        assert result.stdout.strip() == b"True"
    if sys.platform == "win32":
        assert result.stdout.strip() == b"False"
    if sys.platform == "darwin":
        assert result.stdout.strip() == b"False"


# --- the registry ----------------------------------------------------------------------------


def part(content_type: str, encoding: str = "7bit", section: str = "2") -> PartInfo:
    return PartInfo(
        section=section,
        content_type=content_type,
        encoding=encoding,
        size=None,
        depth=1,
        disposition="attachment",
    )


def test_registry_extracts_a_base64_pdf() -> None:
    data = base64.encodebytes(generators.plain_pdf())
    result = extract_text(part("application/pdf", "base64"), data)
    assert result.text == "Hello PDF"
    assert result.section == "2"


def test_registry_notes_carry_the_section() -> None:
    result = extract_text(part("application/pdf"), generators.cyclic_page_tree_pdf())
    assert result.text is None
    assert [(n.kind, n.part) for n in result.notes if n.kind != "memory_cap_unavailable"] == [
        ("malformed", "2")
    ]


def test_registry_plain_text_and_unsupported_types() -> None:
    assert extract_text(part("text/plain"), b"hello").text == "hello"
    assert extract_text(part("text/html"), b"<p>x</p>").notes[0].kind == "unsupported"
    assert extract_text(part("image/png"), b"\x89PNG").notes[0].kind == "unsupported"
    assert extract_text(part("application/pdf", "uuencode"), b"x").notes[0].kind == "unsupported"
    assert set(DEFAULT_EXTRACTORS) == {"application/pdf", "text/plain", "text/html"}


def test_registry_isolates_a_failing_extractor() -> None:
    def broken(*args: object) -> None:
        raise ValueError("secret mail text")

    result = extract_text(part("text/plain"), b"x", extractors={"text/plain": broken})  # type: ignore[dict-item]
    assert result.text is None
    assert [n.kind for n in result.notes] == ["part_failed"]
    assert "secret" not in repr(result)


def test_registry_refuses_oversized_input() -> None:
    small = Limits(max_attachment_bytes=1024)
    result = extract_text(part("text/plain"), b"a" * 2000, small)
    assert [(n.kind, n.limit) for n in result.notes] == [("limit_exceeded", "L-08")]


# --- fuzz ------------------------------------------------------------------------------------

BASE = generators.plain_pdf(pages=2)


@settings(
    max_examples=60,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)
@given(
    st.lists(st.tuples(st.integers(0, len(BASE) - 1), st.integers(0, 255)), max_size=12),
    st.integers(0, len(BASE)),
)
def test_mutated_pdfs_never_raise_in_the_worker(edits: list[tuple[int, int]], cut: int) -> None:
    data = bytearray(BASE)
    for pos, value in edits:
        data[pos] = value
    body = json.loads(extract(bytes(data[: cut or len(data)]), worker_limits()))
    assert body["v"] == 1 and isinstance(body["text"], str)


@settings(max_examples=100, deadline=None)
@given(st.binary(max_size=2048))
def test_arbitrary_worker_output_never_raises_in_the_host(raw: bytes) -> None:
    result = parse_result(raw, LIMITS)
    assert isinstance(result, pdf_host.PdfText)


# --- review follow-ups -----------------------------------------------------------------------


def test_memory_error_in_a_page_maps_to_the_l10_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    from pypdf import PageObject

    def hog_page(self: object, *args: object, **kwargs: object) -> str:
        raise MemoryError

    monkeypatch.setattr(PageObject, "extract_text", hog_page)
    body = json.loads(extract(generators.plain_pdf(pages=3), worker_limits()))
    assert body["notes"] == [["limit_exceeded", "L-10"]]
    assert body["text"] == ""


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads RLIMIT_AS back")
def test_the_real_worker_applies_the_memory_limit_to_itself() -> None:
    memory = 400 * MIB
    argv = worker_argv(Limits(pdf_worker_memory_bytes=memory))[4:]
    code = (
        "import resource, sys\n"
        "from mailferret.content import pdf_worker\n"
        f"pdf_worker.main({argv!r})\n"
        "sys.stdout.write('\\n%d' % resource.getrlimit(resource.RLIMIT_AS)[0])\n"
    )
    result = run_bounded(
        python(code),
        generators.plain_pdf(),
        deadline=30,
        memory_bytes=4096 * MIB,
        stdout_cap=65536,
    )
    payload, _, limit = result.stdout.rpartition(b"\n")
    assert int(limit) == memory
    assert json.loads(payload)["notes"] == []


def test_missing_memory_cap_is_visible_as_a_note() -> None:
    body = json.loads(extract(generators.plain_pdf(), worker_limits(), memory_capped=False))
    assert body["notes"] == [["memory_cap_unavailable", None]]
    assert body["text"] == "Hello PDF"
    result = extract_pdf(generators.plain_pdf())
    present = any(n.kind == "memory_cap_unavailable" for n in result.notes)
    assert present == (sys.platform == "darwin")


def test_a_failed_job_object_is_noted_by_the_host(monkeypatch: pytest.MonkeyPatch) -> None:
    body = b'{"v":1,"text":"ok","truncated":false,"notes":[]}'
    fake = pdf_host.RunResult("exited", 0, body, job_failed=True)
    monkeypatch.setattr(pdf_host, "run_bounded", lambda *a, **k: fake)
    result = extract_pdf(b"%PDF-")
    assert result.text == "ok"
    assert [n.kind for n in result.notes] == ["memory_cap_unavailable"]


class _FakeProc:
    def __init__(self) -> None:
        self.killed = False
        self.stdin = self.stdout = self.stderr = None
        self.pid = 0

    def kill(self) -> None:
        self.killed = True


def test_job_object_failures_are_reported_and_never_leave_the_worker_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proc = _FakeProc()
    monkeypatch.setattr(pdf_host.MemoryJob, "create", classmethod(lambda cls, n: None))
    assert pdf_host._attach_job(proc, 1) == (None, True)  # type: ignore[arg-type]

    def explode(cls: object, memory: int) -> None:
        raise OSError("job")

    monkeypatch.setattr(pdf_host.MemoryJob, "create", classmethod(explode))
    monkeypatch.setattr(pdf_host.os, "killpg", lambda *a: None, raising=False)
    with pytest.raises(OSError, match="job"):
        pdf_host._attach_job(proc, 1)  # type: ignore[arg-type]
    assert proc.killed


@pytest.mark.skipif(not hasattr(os, "waitid"), reason="needs waitid")
def test_exit_is_detected_without_reaping_the_leader() -> None:
    import subprocess

    proc = subprocess.Popen([PY, "-I", "-c", "pass"])  # noqa: S603
    try:
        deadline = time.monotonic() + 20
        while not pdf_host._has_exited(proc):
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert proc.returncode is None  # still unreaped: its process group id is still ours
    finally:
        proc.wait()


def _alive(pid: int) -> bool:
    import subprocess

    if sys.platform == "win32":
        out = subprocess.run(  # noqa: S603
            ["tasklist", "/FI", f"PID eq {pid}", "/NH"],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        ).stdout
        return str(pid) in out
    out = subprocess.run(  # noqa: S603
        ["ps", "-o", "stat=", "-p", str(pid)],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    return bool(out) and not out.startswith("Z")


def _wait_dead(pid: int) -> bool:
    end = time.monotonic() + 10
    while time.monotonic() < end:
        if not _alive(pid):
            return True
        time.sleep(0.1)
    return False


@pytest.mark.parametrize("worker_exits", [False, True], ids=["hangs", "exits_leaving_child"])
def test_descendants_of_the_worker_are_killed(tmp_path: Path, worker_exits: bool) -> None:
    pidfile = tmp_path / "child.pid"
    code = (
        "import subprocess, sys, time\n"
        "child = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(120)'],"
        " stdout=sys.stdout)\n"
        f"open({str(pidfile)!r}, 'w').write(str(child.pid))\n"
        + ("" if worker_exits else "time.sleep(120)\n")
    )
    started = time.monotonic()
    result = run_bounded(python(code), b"", deadline=4, memory_bytes=4096 * MIB, stdout_cap=1024)
    assert time.monotonic() - started < 15
    assert pidfile.exists(), "the worker never started its child"
    pid = int(pidfile.read_text())
    try:
        assert result.status == "timeout"
        assert _wait_dead(pid), "grandchild survived the deadline"
    finally:
        if _alive(pid) and sys.platform != "win32":
            os.kill(pid, 9)


def test_cf_controls_are_stripped_from_every_extractor_and_noted() -> None:
    raw = generators.format_control_pdf()
    assert "‮" in (extract_pdf(raw).text or ""), "control: the PDF yields Cf characters"
    result = extract_text(part("application/pdf"), raw)
    assert result.text == "x"
    assert [(n.kind, n.part) for n in result.notes if n.kind != "memory_cap_unavailable"] == [
        ("format_stripped", "2")
    ]
    plain = extract_text(part("text/plain"), "a‮b​c".encode())
    assert plain.text == "abc"
    assert [n.kind for n in plain.notes] == ["format_stripped"]
    clean = extract_text(part("text/plain"), b"abc")
    assert clean.notes == ()
