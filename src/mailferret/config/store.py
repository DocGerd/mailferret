"""Load and write the config file."""

from __future__ import annotations

import os
import tempfile
import tomllib
from collections.abc import Mapping, MutableMapping
from pathlib import Path
from typing import Any

import tomlkit
from pydantic import ValidationError

from mailferret.config.paths import resolve_location
from mailferret.config.schema import Config


class ConfigError(Exception):
    """Invalid config. The message never contains values from the file (T-01)."""


def _describe(error: ValidationError) -> str:
    lines = [
        f"{'.'.join(str(part) for part in item['loc']) or '<root>'}: {item['msg']}"
        for item in error.errors(include_input=False, include_url=False)
    ]
    return "invalid config:\n" + "\n".join(lines)


def parse(text: str) -> Config:
    try:
        return Config.model_validate(tomllib.loads(text))
    except tomllib.TOMLDecodeError as exc:
        message = f"config is not valid TOML: {exc}"
    except ValidationError as exc:
        message = _describe(exc)
    # Raised outside the handlers so __context__ holds neither the file text nor its values.
    raise ConfigError(message)


def load(
    flag: str | os.PathLike[str] | None = None, env: Mapping[str, str] | None = None
) -> Config:
    """A missing file, including one named by an override, means no accounts (A§7)."""
    path = resolve_location(flag, env).path
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return Config()
    except (OSError, UnicodeDecodeError) as exc:
        message = f"cannot read config: {type(exc).__name__}"
    else:
        return parse(text)
    raise ConfigError(message)


def _merge(target: Any, data: Mapping[str, Any], full: Mapping[str, Any]) -> None:
    """Make `target` match `data`, leaving values that already equal a default untouched.

    `full` is the same section with defaults included.
    """
    for key in [k for k in target if k not in full]:
        del target[key]
    for key, default in full.items():
        if key in data:
            value = data[key]
            if isinstance(value, Mapping):
                if not isinstance(target.get(key), MutableMapping):
                    target[key] = tomlkit.table()
                _merge(target[key], value, default)
            elif target.get(key) != value:
                target[key] = value
        elif key in target:
            if isinstance(default, Mapping) and isinstance(target[key], MutableMapping):
                _merge(target[key], {}, default)
            elif target[key] != default:
                del target[key]


def write(
    config: Config,
    flag: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
) -> Path:
    """Atomic write with mode 0600, keeping the comments of an existing file."""
    path = resolve_location(flag, env).path
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    doc = tomlkit.document()
    if path.exists():
        try:
            doc = tomlkit.parse(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            doc = tomlkit.document()
    data = {
        "schema_version": config.schema_version,
        **config.model_dump(mode="json", exclude_defaults=True),
    }
    _merge(doc, data, config.model_dump(mode="json", exclude_none=True))
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(tomlkit.dumps(doc))
            handle.flush()
            os.fsync(handle.fileno())
        Path(tmp).chmod(0o600)
        Path(tmp).replace(path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return path
