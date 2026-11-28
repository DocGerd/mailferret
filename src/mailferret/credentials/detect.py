"""Keyring backend classification: refuse fail, null, plaintext and empty chainers (T-01).

Works on class names, so it needs no ``keyring`` import and runs inside the probe.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class Verdict:
    usable: bool
    reason: str | None = None


def qualified_name(backend: object) -> str:
    cls = type(backend)
    return f"{cls.__module__}.{cls.__qualname__}"


def _refusal(backend: object) -> str | None:
    for cls in type(backend).__mro__:
        module, name = cls.__module__, cls.__name__
        if module == "keyring.backends.fail":
            return "fail"
        if module == "keyring.backends.null":
            return "null"
        if module.split(".")[0] == "keyrings" or "plaintext" in name.lower():
            return "plaintext"
    return None


def classify(backend: object) -> Verdict:
    reason = _refusal(backend)
    if reason is not None:
        return Verdict(False, reason)
    if type(backend).__name__ == "ChainerBackend":
        members = getattr(backend, "backends", None)
        children: list[object] = list(members) if isinstance(members, Iterable) else []
        if not children:
            return Verdict(False, "chainer_empty")
        for child in children:
            verdict = classify(child)
            if not verdict.usable:
                return verdict
    return Verdict(True)
