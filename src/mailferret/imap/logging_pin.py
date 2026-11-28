"""imapclient logging pinned off (T-03, T-21).

imapclient logs commands, the username and raw server lines, and ``imapclient.util`` warns with
raw 8-bit bytes. ``debug`` is pinned to 0 by the guard mixin; here the logger is set to
``CRITICAL + 1`` with ``propagate = False`` and a ``NullHandler``. A WARNING pin still reaches
stderr through ``logging.lastResort``, so both parts are required.
"""

from __future__ import annotations

import logging
from typing import Final

LOGGER_NAME: Final = "imapclient"
_CHILDREN: Final = ("imapclient.imaplib", "imapclient.imapclient", "imapclient.util")


def pin_imapclient_logging() -> None:
    """Idempotent; also run at import of ``mailferret.imap`` and before every connection."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.CRITICAL + 1)
    logger.propagate = False
    logger.handlers[:] = [logging.NullHandler()]
    for name in _CHILDREN:
        child = logging.getLogger(name)
        child.setLevel(logging.NOTSET)
        child.disabled = False
        child.propagate = True
        child.handlers[:] = []


def logging_is_pinned() -> bool:
    """Whether every imapclient logger is disabled and cannot reach a handler outside."""
    parent = logging.getLogger(LOGGER_NAME)
    if parent.propagate or parent.level <= logging.CRITICAL:
        return False
    if len(parent.handlers) != 1 or type(parent.handlers[0]) is not logging.NullHandler:
        return False
    for name in _CHILDREN:
        child = logging.getLogger(name)
        if not child.propagate or child.isEnabledFor(logging.CRITICAL) or child.handlers:
            return False
    return True
