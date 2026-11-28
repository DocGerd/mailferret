"""The L-table of SECURITY §5: ceilings, defaults and the merge with ``[limits]`` (A§1)."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final, Self

from pydantic import BaseModel, ConfigDict, model_validator

KIB: Final = 1024
MIB: Final = 1024 * KIB

# Bytes charged per response line on top of its length (L-26): what imaplib keeps for one untagged
# line of a new type. Not a [limits] key: lowering it would weaken the bound. The measurement and
# its margin are in tests/unit/imap/test_overhead.py.
LINE_OVERHEAD_BYTES: Final = 424

# Line bytes (with their overhead) one fetched message is allowed in a FETCH response (L-32).
# Proposed; to be re-measured on real mail in D5. Not a [limits] key.
FETCH_LINE_ALLOWANCE_BYTES: Final = 32 * KIB

CEILINGS: Final[Mapping[str, int]] = MappingProxyType(
    {
        "max_message_bytes": 25 * MIB,
        "max_part_bytes": 2 * MIB,
        "max_body_chars": 100_000,
        "max_header_value_chars": 8_192,
        "max_header_bytes": 256 * KIB,
        "max_mime_depth": 16,
        "max_mime_parts": 256,
        "max_attachment_bytes": 10 * MIB,
        "max_pdf_pages": 50,
        "pdf_worker_seconds": 20,
        "pdf_worker_memory_bytes": 512 * MIB,
        "pdf_stream_bytes": 32 * MIB,
        "imap_connect_seconds": 15,
        "imap_read_seconds": 30,
        "tool_deadline_seconds": 90,
        "credential_command_seconds": 10,
        "max_page_size": 200,
        "max_candidates": 10_000,
        "max_thread_messages": 100,
        "max_alias_period_days": 365,
        "max_alias_scan": 5_000,
        "max_attachments_listed": 100,
        "max_response_bytes": MIB,
        "max_line_bytes": MIB,
        "max_folders": 1_000,
        "credential_command_output_bytes": 4 * KIB,
        "max_query_chars": 256,
        "max_criteria": 16,
        "fetch_batch_size": 200,
        "max_command_response_bytes": 27 * MIB,
        "max_response_line_bytes": 5 * MIB // 2,
        "keyring_probe_seconds": 10,
        "credential_stderr_bytes": 16 * KIB,
        "credential_status_bytes": 16 * KIB,
        "max_header_values": 16,
        "max_header_addresses": 64,
    }
)

DEFAULT_PAGE_SIZE: Final = 25
DEFAULT_ALIAS_PERIOD_DAYS: Final = 30


def violation(key: str, value: int) -> str | None:
    """Return why ``value`` is not allowed for ``key``, or ``None``."""
    ceiling = CEILINGS[key]
    if not 1 <= value <= ceiling:
        return f"{key} must be between 1 and {ceiling}"
    return None


class Limits(BaseModel):
    """Effective limits: every field defaults to its ceiling and may only be lowered."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    max_message_bytes: int = CEILINGS["max_message_bytes"]
    max_part_bytes: int = CEILINGS["max_part_bytes"]
    max_body_chars: int = CEILINGS["max_body_chars"]
    max_header_value_chars: int = CEILINGS["max_header_value_chars"]
    max_header_bytes: int = CEILINGS["max_header_bytes"]
    max_mime_depth: int = CEILINGS["max_mime_depth"]
    max_mime_parts: int = CEILINGS["max_mime_parts"]
    max_attachment_bytes: int = CEILINGS["max_attachment_bytes"]
    max_pdf_pages: int = CEILINGS["max_pdf_pages"]
    pdf_worker_seconds: int = CEILINGS["pdf_worker_seconds"]
    pdf_worker_memory_bytes: int = CEILINGS["pdf_worker_memory_bytes"]
    pdf_stream_bytes: int = CEILINGS["pdf_stream_bytes"]
    imap_connect_seconds: int = CEILINGS["imap_connect_seconds"]
    imap_read_seconds: int = CEILINGS["imap_read_seconds"]
    tool_deadline_seconds: int = CEILINGS["tool_deadline_seconds"]
    credential_command_seconds: int = CEILINGS["credential_command_seconds"]
    max_page_size: int = CEILINGS["max_page_size"]
    max_candidates: int = CEILINGS["max_candidates"]
    max_thread_messages: int = CEILINGS["max_thread_messages"]
    max_alias_period_days: int = CEILINGS["max_alias_period_days"]
    max_alias_scan: int = CEILINGS["max_alias_scan"]
    max_attachments_listed: int = CEILINGS["max_attachments_listed"]
    max_response_bytes: int = CEILINGS["max_response_bytes"]
    max_line_bytes: int = CEILINGS["max_line_bytes"]
    max_folders: int = CEILINGS["max_folders"]
    credential_command_output_bytes: int = CEILINGS["credential_command_output_bytes"]
    max_query_chars: int = CEILINGS["max_query_chars"]
    max_criteria: int = CEILINGS["max_criteria"]
    fetch_batch_size: int = CEILINGS["fetch_batch_size"]
    max_command_response_bytes: int = CEILINGS["max_command_response_bytes"]
    max_response_line_bytes: int = CEILINGS["max_response_line_bytes"]
    keyring_probe_seconds: int = CEILINGS["keyring_probe_seconds"]
    credential_stderr_bytes: int = CEILINGS["credential_stderr_bytes"]
    credential_status_bytes: int = CEILINGS["credential_status_bytes"]
    max_header_values: int = CEILINGS["max_header_values"]
    max_header_addresses: int = CEILINGS["max_header_addresses"]

    @model_validator(mode="after")
    def _within_ceilings(self) -> Self:
        for key in CEILINGS:
            problem = violation(key, getattr(self, key))
            if problem:
                raise ValueError(problem)
        return self

    @property
    def default_page_size(self) -> int:
        return min(DEFAULT_PAGE_SIZE, self.max_page_size)

    @property
    def default_alias_period_days(self) -> int:
        return min(DEFAULT_ALIAS_PERIOD_DAYS, self.max_alias_period_days)


def merge(overrides: Mapping[str, int | None]) -> Limits:
    """Apply ``[limits]`` overrides (``None`` is unset); a value above its ceiling is an error."""
    return Limits.model_validate({k: v for k, v in overrides.items() if v is not None})
