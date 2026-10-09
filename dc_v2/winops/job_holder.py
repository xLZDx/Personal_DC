"""Tiny stand-alone process that keeps a NAMED Windows Job Object alive (stdlib + ctypes only).

A named job's name disappears from the object namespace once its last handle is closed, even while member processes
still run. When the server dies, every handle it owned dies with it, so a detached process tree could no longer be
re-opened by name. This holder owns one extra handle, outlives the server, and exits itself when the job has had
members and is now empty (or when nothing ever joined within the grace period).

Usage: ``python job_holder.py <job-name>``; prints ``ready`` once the job exists.
"""
from __future__ import annotations

import ctypes
import sys
import time
from ctypes import wintypes

GRACE_SECONDS = 120
JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1


class _Accounting(ctypes.Structure):
    _fields_ = [("TotalUserTime", ctypes.c_longlong), ("TotalKernelTime", ctypes.c_longlong),
                ("ThisPeriodTotalUserTime", ctypes.c_longlong), ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                ("TotalPageFaultCount", wintypes.DWORD), ("TotalProcesses", wintypes.DWORD),
                ("ActiveProcesses", wintypes.DWORD), ("TotalTerminatedProcesses", wintypes.DWORD)]


def main(name: str) -> int:
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateJobObjectW.restype = wintypes.HANDLE
    k.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    k.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                            ctypes.c_void_p]
    handle = k.CreateJobObjectW(None, name)
    if not handle:
        return 2
    print("ready", flush=True)
    started, seen = time.time(), False
    while True:
        info = _Accounting()
        if not k.QueryInformationJobObject(handle, JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION, ctypes.byref(info),
                                           ctypes.sizeof(info), None):
            return 3
        if info.ActiveProcesses > 0:
            seen = True
        elif seen or time.time() - started > GRACE_SECONDS:
            return 0
        time.sleep(1)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]) if len(sys.argv) == 2 else 64)
