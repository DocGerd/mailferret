"""Draft-first sending interface. Types only; no implementation exists."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal, Protocol


class DraftSender(Protocol):
    def create_draft(
        self, to: Sequence[str], subject: str, body: str, *, confirm: Literal[True]
    ) -> str: ...

    def send_draft(self, draft_id: str, *, confirm: Literal[True]) -> None: ...
