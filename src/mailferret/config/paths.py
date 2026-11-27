"""Config location: flag, then MAILFERRET_CONFIG, then the platform default (R§6)."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from platformdirs import user_config_dir

ENV_VAR = "MAILFERRET_CONFIG"
FILE_NAME = "config.toml"


@dataclass(frozen=True)
class ConfigLocation:
    path: Path
    overridden: bool


def default_config_path() -> Path:
    return Path(user_config_dir("mailferret", appauthor=False, roaming=True)) / FILE_NAME


def resolve_location(
    flag: str | os.PathLike[str] | None = None, env: Mapping[str, str] | None = None
) -> ConfigLocation:
    environ = os.environ if env is None else env
    if flag is not None and str(flag) != "":
        return ConfigLocation(Path(flag).expanduser(), True)
    value = environ.get(ENV_VAR, "")
    if value:
        return ConfigLocation(Path(value).expanduser(), True)
    return ConfigLocation(default_config_path(), False)
