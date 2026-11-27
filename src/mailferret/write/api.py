"""Write operations interface. Types only; no implementation exists."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal, Protocol


class WriteOps(Protocol):
    def move(
        self, folder: str, uids: Sequence[int], destination: str, *, confirm: Literal[True]
    ) -> None: ...

    def set_flags(
        self, folder: str, uids: Sequence[int], flags: Sequence[str], *, confirm: Literal[True]
    ) -> None: ...

    def mark_read(self, folder: str, uids: Sequence[int], *, confirm: Literal[True]) -> None: ...

    def create_folder(self, name: str, *, confirm: Literal[True]) -> None: ...
