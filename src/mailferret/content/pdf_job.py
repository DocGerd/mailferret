"""Windows job object with a per-process memory limit and kill-on-close, via ``ctypes`` (T-06).

Own copy: ``content/`` never imports ``credentials/``. Every method is inert off Windows.
"""

from __future__ import annotations

import sys
from typing import Any

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _LIMIT_PROCESS_MEMORY = 0x100
    _KILL_ON_JOB_CLOSE = 0x2000
    _EXTENDED_LIMIT_INFORMATION = 9

    class _BasicLimits(ctypes.Structure):
        _fields_ = (
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        )

    class _IoCounters(ctypes.Structure):
        _fields_ = tuple((name, ctypes.c_uint64) for name in ("r0", "r1", "r2", "w0", "w1", "o"))

    class _ExtendedLimits(ctypes.Structure):
        _fields_ = (
            ("BasicLimitInformation", _BasicLimits),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        )

    def _kernel32() -> Any:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateJobObjectW.restype = wintypes.HANDLE
        k32.CreateJobObjectW.argtypes = (wintypes.LPVOID, wintypes.LPCWSTR)
        k32.SetInformationJobObject.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
        )
        k32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        k32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
        k32.CloseHandle.argtypes = (wintypes.HANDLE,)
        return k32


class MemoryJob:
    """Create with :meth:`create`; ``None`` means no job object could be made."""

    def __init__(self, handle: Any) -> None:
        self._handle = handle

    @classmethod
    def create(cls, memory_bytes: int) -> MemoryJob | None:
        if sys.platform == "win32":
            k32 = _kernel32()
            handle = k32.CreateJobObjectW(None, None)
            if not handle:
                return None
            info = _ExtendedLimits()
            info.BasicLimitInformation.LimitFlags = _LIMIT_PROCESS_MEMORY | _KILL_ON_JOB_CLOSE
            info.ProcessMemoryLimit = memory_bytes
            ok = k32.SetInformationJobObject(
                handle, _EXTENDED_LIMIT_INFORMATION, ctypes.byref(info), ctypes.sizeof(info)
            )
            if ok:
                return cls(handle)
            k32.CloseHandle(handle)
        return None

    def assign(self, process_handle: int) -> bool:
        if sys.platform == "win32":
            return bool(_kernel32().AssignProcessToJobObject(self._handle, process_handle))
        return False

    def terminate(self) -> None:
        if sys.platform == "win32" and self._handle:
            _kernel32().TerminateJobObject(self._handle, 1)

    def close(self) -> None:
        if sys.platform == "win32" and self._handle:
            _kernel32().CloseHandle(self._handle)
            self._handle = None
