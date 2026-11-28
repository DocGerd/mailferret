"""``DBUS_SESSION_BUS_ADDRESS`` pre-check, run in the parent before the probe (A§2.1, V3-4)."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import unquote_to_bytes

_LOCATION_KEYS = frozenset({"path", "abstract"})
_ALLOWED_KEYS = _LOCATION_KEYS | {"guid"}


@dataclass(frozen=True)
class BusCheck:
    status: str
    accepted: tuple[str, ...] = ()

    @property
    def usable(self) -> bool:
        return bool(self.accepted)

    @property
    def address(self) -> str:
        return ";".join(self.accepted)


def _parse_entry(entry: str) -> dict[str, str] | None:
    transport, sep, rest = entry.partition(":")
    if transport != "unix" or not sep:
        return None
    params: dict[str, str] = {}
    for item in rest.split(","):
        key, eq, value = item.partition("=")
        if not eq or key in params or key not in _ALLOWED_KEYS:
            return None
        params[key] = value
    if len(_LOCATION_KEYS.intersection(params)) != 1:
        return None
    return params


def check_bus_address(
    value: str | None, *, exists: Callable[[str], bool] = os.path.exists
) -> BusCheck:
    if not value:
        return BusCheck("unset")
    accepted: list[str] = []
    refused = False
    missing = False
    for entry in value.split(";"):
        if not entry:
            continue
        params = _parse_entry(entry)
        if params is None:
            refused = True
            continue
        if "path" in params:
            path = unquote_to_bytes(params["path"]).decode("utf-8", errors="surrogateescape")
            if not path or "\0" in path or not exists(path):
                missing = True
                continue
        accepted.append(entry)
    if accepted:
        return BusCheck("ok", tuple(accepted))
    return BusCheck("missing_path" if missing and not refused else "refused")
