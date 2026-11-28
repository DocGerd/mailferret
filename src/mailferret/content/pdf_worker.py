"""PDF text extraction worker: ``python -I -m mailferret.content.pdf_worker`` (T-06, A§10 item 10).

Reads one PDF from stdin and writes one JSON result to stdout. It runs under the host's wall
time and, per OS, a memory limit; on POSIX it applies ``RLIMIT_AS`` to itself before ``pypdf``
is imported. Notes carry fixed kinds and L-table IDs only, never pypdf or PDF text.
"""

from __future__ import annotations

import dataclasses
import io
import json
import sys
import typing
from collections.abc import Iterator, Mapping, Sequence
from typing import TYPE_CHECKING, Any, Final

from mailferret.content.truncate import truncate_chars

if TYPE_CHECKING:
    from pypdf import Configuration

PAGE_TREE_FACTOR: Final = 20
PAGE_ENTRY_FACTOR: Final = 16
RESULT_VERSION: Final = 1
_OPTIONS: Final = ("pages", "chars", "stream-bytes", "memory", "input-bytes")


def apply_memory_limit(memory_bytes: int) -> bool:
    """Cap the address space of this process; ``False`` if the OS did not take the limit."""
    if sys.platform == "win32":
        return False
    import resource

    try:
        _, hard = resource.getrlimit(resource.RLIMIT_AS)
        soft = memory_bytes if hard == resource.RLIM_INFINITY else min(memory_bytes, hard)
        resource.setrlimit(resource.RLIMIT_AS, (soft, hard))
    except (ValueError, OSError):
        return False
    return True


def _hints() -> Mapping[str, Any]:
    from pypdf import Configuration

    return typing.get_type_hints(Configuration)


def _is_program(hint: Any) -> bool:
    args = typing.get_args(hint)
    return str in args and type(None) in args


def hardened_overrides(
    configuration: Configuration, *, stream_bytes: int, pages: int
) -> dict[str, Any]:
    """The ``Configuration`` fields to change, found at runtime so a new field is covered."""
    hints = _hints()
    out: dict[str, Any] = {}
    for field in dataclasses.fields(configuration):
        hint = hints[field.name]
        value = getattr(configuration, field.name)
        if hint is int and value > stream_bytes:
            out[field.name] = stream_bytes
        elif _is_program(hint):
            out[field.name] = None
    tree = PAGE_TREE_FACTOR * pages
    out["page_tree_maximum_entries"] = min(configuration.page_tree_maximum_entries, tree)
    out["page_tree_maximum_page_entries"] = min(
        configuration.page_tree_maximum_page_entries, tree * PAGE_ENTRY_FACTOR
    )
    out["page_tree_maximum_depth"] = min(configuration.page_tree_maximum_depth, pages)
    return out


def hardening_gaps(configuration: Configuration, *, stream_bytes: int) -> list[str]:
    """Names of fields still above ``stream_bytes`` (integers) or naming a program."""
    hints = _hints()
    gaps: list[str] = []
    for field in dataclasses.fields(configuration):
        hint = hints[field.name]
        value = getattr(configuration, field.name)
        if (hint is int and value > stream_bytes) or (_is_program(hint) and value is not None):
            gaps.append(field.name)
    return gaps


@dataclasses.dataclass(frozen=True, slots=True)
class WorkerLimits:
    pages: int
    chars: int
    stream_bytes: int
    memory: int
    input_bytes: int


class _Result:
    def __init__(self) -> None:
        self.text = ""
        self.truncated = False
        self.notes: list[tuple[str, str | None]] = []

    def note(self, kind: str, limit: str | None = None) -> None:
        if (kind, limit) not in self.notes:
            self.notes.append((kind, limit))

    def failed(self, kind: str, limit: str | None = None) -> None:
        self.text = ""
        self.truncated = False
        self.note(kind, limit)

    def encode(self) -> bytes:
        text = self.text.encode("utf-8", "replace").decode("utf-8")
        body = {
            "v": RESULT_VERSION,
            "text": text,
            "truncated": self.truncated,
            "notes": [list(n) for n in self.notes],
        }
        return json.dumps(body, ensure_ascii=False).encode("utf-8", "replace")


def _pages(reader: Any, limits: WorkerLimits, out: _Result) -> Iterator[str]:
    from pypdf.errors import LimitReachedError

    pages = reader.pages
    try:
        count = len(pages)
    except LimitReachedError:
        out.note("limit_exceeded", "L-09")
        return
    except Exception:  # structural fault
        out.note("malformed")
        return
    for index in range(min(count, limits.pages)):
        try:
            page = pages[index]
        except LimitReachedError:
            out.note("limit_exceeded", "L-09")
            return
        except Exception:  # structural fault: the rest of the tree is not trustworthy
            out.note("malformed")
            return
        try:
            yield page.extract_text()
        except LimitReachedError:
            out.note("limit_exceeded", "L-10")
        except Exception:  # per-page fault isolation
            out.note("part_failed")
    if count > limits.pages:
        out.truncated = True
        out.note("limit_exceeded", "L-09")


def _collect(data: bytes, limits: WorkerLimits, out: _Result) -> None:
    from pypdf import PdfReader, get_configuration

    reader = PdfReader(io.BytesIO(data))
    if hardening_gaps(get_configuration(), stream_bytes=limits.stream_bytes):
        raise RuntimeError("configuration not applied")
    if reader.is_encrypted and not reader.decrypt(""):
        out.failed("unsupported")
        return
    chunks: list[str] = []
    size = 0
    for text in _pages(reader, limits, out):
        chunks.append(text)
        size += len(text)
        if size > limits.chars:
            break
    capped = truncate_chars("\n\n".join(chunks), limits.chars)
    out.text = capped.text
    if capped.truncated:
        out.truncated = True
        out.note("limit_exceeded", "L-03")


def extract(data: bytes, limits: WorkerLimits) -> bytes:
    """Parse ``data`` with the hardened configuration applied in this thread; return the JSON."""
    from pypdf import Configuration, apply_configuration
    from pypdf.errors import LimitReachedError, PyPdfError

    out = _Result()
    overrides = hardened_overrides(
        Configuration(), stream_bytes=limits.stream_bytes, pages=limits.pages
    )
    try:
        with apply_configuration(**overrides):
            _collect(data, limits, out)
    except (MemoryError, LimitReachedError):
        out.failed("limit_exceeded", "L-10")
    except (RecursionError, PyPdfError):
        out.failed("malformed")
    except Exception:  # anything else costs this attachment a note
        out.failed("part_failed")
    return out.encode()


def parse_arguments(argv: Sequence[str]) -> WorkerLimits | None:
    if len(argv) != 2 * len(_OPTIONS):
        return None
    values: dict[str, int] = {}
    for name, flag, raw in zip(_OPTIONS, argv[0::2], argv[1::2], strict=True):
        if flag != f"--{name}" or not raw.isdecimal() or len(raw) > 12 or int(raw) < 1:
            return None
        values[name] = int(raw)
    return WorkerLimits(
        values["pages"],
        values["chars"],
        values["stream-bytes"],
        values["memory"],
        values["input-bytes"],
    )


def main(argv: Sequence[str]) -> int:
    limits = parse_arguments(argv)
    if limits is None:
        return 2
    apply_memory_limit(limits.memory)
    try:
        data = sys.stdin.buffer.read(limits.input_bytes + 1)
    except OSError:
        return 3
    if len(data) > limits.input_bytes:
        result = _Result()
        result.failed("limit_exceeded", "L-08")
        payload = result.encode()
    else:
        payload = extract(data, limits)
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
