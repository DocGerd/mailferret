"""Authentication (A§2): the ``Authenticator`` protocol, ``PasswordAuth`` and the markers (T-16)."""

from mailferret.auth.errors import AuthError, AuthFailed, AuthFailedReason, LoginPaused
from mailferret.auth.markers import PAUSE_SECONDS, AuthMarkers, marker_path
from mailferret.auth.password import PasswordAuth
from mailferret.auth.protocol import Authenticator, guard_connect

__all__ = [
    "PAUSE_SECONDS",
    "AuthError",
    "AuthFailed",
    "AuthFailedReason",
    "AuthMarkers",
    "Authenticator",
    "LoginPaused",
    "PasswordAuth",
    "guard_connect",
    "marker_path",
]
