"""Operations and exit codes shared by the keyring probe and its parent."""

from __future__ import annotations

from typing import Final

OK: Final = 0
NOT_FOUND: Final = 10
UNAVAILABLE: Final = 11
LOCKED: Final = 12
ERROR: Final = 13

OPS: Final = ("describe", "get", "set", "delete")
