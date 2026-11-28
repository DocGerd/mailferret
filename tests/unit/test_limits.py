import ast
import inspect

import pytest
from pydantic import ValidationError

from mailferret import limits
from mailferret.config import Limits as ConfigLimits
from mailferret.config import parse
from mailferret.limits import CEILINGS, Limits, merge

MIB = 1024**2
SECURITY_TABLE = {
    "L-01": {"max_message_bytes": 25 * MIB},
    "L-02": {"max_part_bytes": 2 * MIB},
    "L-03": {"max_body_chars": 100_000},
    "L-04": {"max_header_value_chars": 8_192},
    "L-05": {"max_header_bytes": 256 * 1024},
    "L-06": {"max_mime_depth": 16},
    "L-07": {"max_mime_parts": 256},
    "L-08": {"max_attachment_bytes": 10 * MIB},
    "L-09": {"max_pdf_pages": 50},
    "L-10": {
        "pdf_worker_seconds": 20,
        "pdf_worker_memory_bytes": 512 * MIB,
        "pdf_stream_bytes": 32 * MIB,
    },
    "L-11": {"imap_connect_seconds": 15},
    "L-12": {"imap_read_seconds": 30},
    "L-13": {"tool_deadline_seconds": 90},
    "L-14": {"credential_command_seconds": 10},
    "L-15": {"max_page_size": 200, "max_candidates": 10_000},
    "L-16": {"max_thread_messages": 100},
    "L-17": {"max_alias_period_days": 365, "max_alias_scan": 5_000},
    "L-18": {"max_attachments_listed": 100},
    "L-19": {"max_response_bytes": MIB},
    "L-20": {"max_line_bytes": MIB},
    "L-21": {"max_folders": 1_000},
    "L-22": {"credential_command_output_bytes": 4096},
    "L-23": {"max_query_chars": 256},
    "L-24": {"max_criteria": 16},
    "L-25": {"fetch_batch_size": 200},
    "L-26": {"max_command_response_bytes": 27 * MIB},
    "L-27": {"keyring_probe_seconds": 10},
    "L-28": {"credential_stderr_bytes": 16 * 1024},
    "L-29": {"credential_status_bytes": 16 * 1024},
    "L-30": {"max_header_values": 16},
    "L-31": {"max_header_addresses": 64},
    "L-32": {"max_response_line_bytes": 5 * MIB // 2},
}
EXPECTED = {k: v for row in SECURITY_TABLE.values() for k, v in row.items()}


@pytest.mark.parametrize("lid", sorted(SECURITY_TABLE))
def test_every_l_row_has_its_ceiling_as_default(lid: str) -> None:
    defaults = Limits()
    for key, ceiling in SECURITY_TABLE[lid].items():
        assert CEILINGS[key] == ceiling
        assert getattr(defaults, key) == ceiling


def test_ceilings_are_read_only() -> None:
    with pytest.raises(TypeError):
        CEILINGS["max_folders"] = 10**9  # type: ignore[index]


def test_table_and_models_cover_the_same_keys() -> None:
    assert dict(CEILINGS) == EXPECTED
    assert set(Limits.model_fields) == set(CEILINGS)
    assert set(ConfigLimits.model_fields) == set(CEILINGS)


def test_response_ceiling_covers_a_full_fallback_fetch() -> None:
    assert CEILINGS["max_command_response_bytes"] == (
        CEILINGS["max_message_bytes"] + 2 * CEILINGS["max_line_bytes"]
    )


def test_line_ceiling_exceeds_one_line_and_stays_under_the_response_total() -> None:
    assert CEILINGS["max_line_bytes"] < CEILINGS["max_response_line_bytes"]
    assert CEILINGS["max_response_line_bytes"] < CEILINGS["max_command_response_bytes"]


def test_model_is_frozen() -> None:
    value = Limits()
    with pytest.raises(ValidationError):
        value.max_page_size = 1  # type: ignore[misc]


@pytest.mark.parametrize(("key", "ceiling"), sorted(CEILINGS.items()))
def test_merge_lowers_but_never_raises(key: str, ceiling: int) -> None:
    floor = limits.LINE_OVERHEAD_BYTES + Limits().max_line_bytes + 1
    lowest = floor if key == "max_response_line_bytes" else 1
    assert getattr(merge({key: lowest}), key) == lowest
    assert getattr(merge({key: ceiling}), key) == ceiling
    for bad in (ceiling + 1, 0, -1):
        with pytest.raises(ValidationError):
            merge({key: bad})
        with pytest.raises(ValidationError):
            Limits(**{key: bad})


def test_a_line_total_that_cannot_hold_one_line_is_rejected() -> None:
    line = Limits().max_line_bytes
    floor = line + limits.LINE_OVERHEAD_BYTES
    with pytest.raises(ValidationError, match="max_response_line_bytes"):
        merge({"max_response_line_bytes": floor})
    assert merge({"max_response_line_bytes": floor + 1}).max_response_line_bytes == floor + 1
    with pytest.raises(ValidationError, match="max_response_line_bytes"):
        merge({"max_response_line_bytes": floor - 1, "max_line_bytes": line})
    assert merge({"max_line_bytes": 1024, "max_response_line_bytes": 2048})


def test_merge_ignores_none_and_rejects_unknown_and_non_int() -> None:
    assert merge({"max_page_size": None}) == Limits()
    with pytest.raises(ValidationError):
        merge({"max_everything": 1})
    for bad in (True, 1.0, "5"):
        with pytest.raises(ValidationError):
            merge({"max_page_size": bad})  # type: ignore[dict-item]


def test_config_limits_resolve() -> None:
    config = parse(
        '[accounts.a]\nhost = "imap.example.com"\ntls = "implicit"\n'
        'login = "user@example.com"\n[limits]\nmax_page_size = 10\n'
    )
    effective = config.limits.resolve()
    assert effective.max_page_size == 10
    assert effective.max_folders == CEILINGS["max_folders"]


def test_tool_argument_defaults_stay_under_lowered_ceilings() -> None:
    assert Limits().default_page_size == limits.DEFAULT_PAGE_SIZE == 25
    assert merge({"max_page_size": 5}).default_page_size == 5
    assert Limits().default_alias_period_days == 30
    assert merge({"max_alias_period_days": 7}).default_alias_period_days == 7


def test_limits_imports_no_mailferret_module() -> None:
    tree = ast.parse(inspect.getsource(limits))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert node.module is None or not node.module.startswith("mailferret")
        elif isinstance(node, ast.Import):
            assert all(not a.name.startswith("mailferret") for a in node.names)
