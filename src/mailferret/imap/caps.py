"""Per-command read caps: a literal cap and a response total (T-08, A§2.2, L-26)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from mailferret.limits import Limits


class LiteralItem(Enum):
    """The fetched item whose literal sets the per-command literal cap."""

    HEADER = ("L-05", "max_header_bytes")
    PART = ("L-02", "max_part_bytes")
    ATTACHMENT = ("L-08", "max_attachment_bytes")
    MESSAGE = ("L-01", "max_message_bytes")

    @property
    def limit_id(self) -> str:
        return str(self.value[0])

    def cap(self, limits: Limits) -> int:
        return int(getattr(limits, str(self.value[1])))


@dataclass(frozen=True)
class CommandCaps:
    literal_cap: int
    total: int
    limit: str


def default_caps(limits: Limits) -> CommandCaps:
    """For commands that fetch no message items (SEARCH, LIST, STATUS, ...): the whole `L-26`."""
    return CommandCaps(
        LiteralItem.HEADER.cap(limits),
        limits.max_command_response_bytes,
        LiteralItem.HEADER.limit_id,
    )


def unclamped_total(limits: Limits, item: LiteralItem | None, messages: int) -> int:
    """``n x (c + L-20) + L-20``: ``c`` is the literal cap of the item, 0 for items without one."""
    c = item.cap(limits) if item is not None else 0
    return messages * (c + limits.max_line_bytes) + limits.max_line_bytes


def fetch_caps(limits: Limits, item: LiteralItem | None, messages: int) -> CommandCaps:
    """Caps for a FETCH of ``messages`` messages, the total clamped to `L-26`.

    A lowered `L-01` or `L-20` lowers ``c`` and the allowance with it; `L-26` is its own key
    and only clamps.
    """
    if messages < 1:
        raise ValueError("a FETCH covers at least one message")
    literal = item or LiteralItem.HEADER
    return CommandCaps(
        literal.cap(limits),
        min(limits.max_command_response_bytes, unclamped_total(limits, item, messages)),
        literal.limit_id,
    )


def max_messages(limits: Limits, item: LiteralItem | None) -> int:
    """The most messages one FETCH may cover with an unclamped total under `L-26`; 0 if none."""
    c = item.cap(limits) if item is not None else 0
    room = limits.max_command_response_bytes - limits.max_line_bytes
    return max(0, room // (c + limits.max_line_bytes))
