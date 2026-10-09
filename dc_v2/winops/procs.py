"""Low-level Windows process primitives (ctypes, stdlib only).

Identity is ``(pid, creation FILETIME)``: a recycled PID has a different
creation time, so stale records can never be applied to an unrelated process.
"""
from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from typing import Any

from personal_dc.policy import PolicyError

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_TERMINATE = 0x0001
PROCESS_SET_QUOTA = 0x0100
SYNCHRONIZE = 0x00100000
STILL_ACTIVE = 259
TH32CS_SNAPPROCESS = 0x2
INVALID_HANDLE = ctypes.c_void_p(-1).value
JobObjectBasicProcessIdList = 3
JobObjectExtendedLimitInformation = 9
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x100
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x8
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
CREATE_SUSPENDED = 0x4


class _FILETIME(ctypes.Structure):
    _fields_ = [("lo", wintypes.DWORD), ("hi", wintypes.DWORD)]

    def value(self) -> int:
        return (self.hi << 32) | self.lo


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_void_p),
                ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
                ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)]


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint64) for n in
                ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                 "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _BASIC_LIMIT(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD)]


class _EXT_LIMIT(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", _BASIC_LIMIT), ("IoInfo", _IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]


def _k32() -> Any:
    if os.name != "nt":
        raise PolicyError("WINDOWS_ONLY")
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.OpenProcess.restype = wintypes.HANDLE
    k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k.CreateJobObjectW.restype = wintypes.HANDLE
    k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    k.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    k.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    k.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    k.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    k.GetProcessTimes.argtypes = [wintypes.HANDLE, ctypes.POINTER(_FILETIME), ctypes.POINTER(_FILETIME),
                                  ctypes.POINTER(_FILETIME), ctypes.POINTER(_FILETIME)]
    k.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                             ctypes.POINTER(wintypes.DWORD)]
    k.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    k.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    k.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                            ctypes.c_void_p]
    k.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
    k.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
    return k


_K = None


def k32() -> Any:
    global _K
    if _K is None:
        _K = _k32()
    return _K


def _open(pid: int, access: int) -> int | None:
    handle = k32().OpenProcess(access, False, int(pid))
    return handle or None


def creation_time(pid: int) -> int | None:
    """Process creation time as a FILETIME integer, or ``None`` if not openable."""
    handle = _open(pid, PROCESS_QUERY_LIMITED_INFORMATION)
    if not handle:
        return None
    try:
        c, e, kt, ut = _FILETIME(), _FILETIME(), _FILETIME(), _FILETIME()
        if not k32().GetProcessTimes(handle, c, e, kt, ut):
            return None
        return c.value()
    finally:
        k32().CloseHandle(handle)


def image_path(pid: int) -> str | None:
    handle = _open(pid, PROCESS_QUERY_LIMITED_INFORMATION)
    if not handle:
        return None
    try:
        size = wintypes.DWORD(32768)
        buf = ctypes.create_unicode_buffer(size.value)
        if k32().QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return buf.value
        return None
    finally:
        k32().CloseHandle(handle)


def is_alive(pid: int, created: int | None = None) -> bool:
    """True when the process exists, is still running and (if given) has the same identity."""
    handle = _open(pid, PROCESS_QUERY_LIMITED_INFORMATION)
    if not handle:
        return False
    try:
        code = wintypes.DWORD()
        if not k32().GetExitCodeProcess(handle, ctypes.byref(code)) or code.value != STILL_ACTIVE:
            return False
        if created is not None:
            c, e, kt, ut = _FILETIME(), _FILETIME(), _FILETIME(), _FILETIME()
            if not k32().GetProcessTimes(handle, c, e, kt, ut) or c.value() != created:
                return False
        return True
    finally:
        k32().CloseHandle(handle)


def snapshot() -> list[dict[str, Any]]:
    """All processes: pid, ppid, exe name, thread count (Toolhelp32; no command lines)."""
    k = k32()
    snap = k.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == INVALID_HANDLE:
        raise PolicyError("PROCESS_SNAPSHOT_FAILED")
    rows: list[dict[str, Any]] = []
    try:
        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
        ok = k.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            rows.append({"pid": int(entry.th32ProcessID), "ppid": int(entry.th32ParentProcessID),
                         "name": entry.szExeFile, "threads": int(entry.cntThreads)})
            ok = k.Process32NextW(snap, ctypes.byref(entry))
    finally:
        k.CloseHandle(snap)
    return rows


def descendants(root_pid: int, root_created: int) -> list[tuple[int, int]]:
    """Live descendants (pid, created) of a verified root.

    A child must have been created *after* its recorded parent (guards against
    ppid reuse). Parent identity of the root itself is verified by the caller.
    """
    if not is_alive(root_pid, root_created):
        return []
    rows = snapshot()
    children: dict[int, list[int]] = {}
    for row in rows:
        children.setdefault(row["ppid"], []).append(row["pid"])
    result: list[tuple[int, int]] = []
    queue: list[tuple[int, int]] = [(root_pid, root_created)]
    seen = {root_pid}
    while queue:
        parent, parent_created = queue.pop()
        for child in children.get(parent, []):
            if child in seen:
                continue
            created = creation_time(child)
            if created is None or created < parent_created:
                continue
            seen.add(child)
            result.append((child, created))
            queue.append((child, created))
    return result


def terminate_exact(pid: int, created: int, exit_code: int = 1) -> bool:
    """Terminate only if (pid, creation time) still match. Returns True if killed."""
    handle = _open(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE)
    if not handle:
        return False
    try:
        c, e, kt, ut = _FILETIME(), _FILETIME(), _FILETIME(), _FILETIME()
        if not k32().GetProcessTimes(handle, c, e, kt, ut) or c.value() != created:
            return False
        return bool(k32().TerminateProcess(handle, exit_code))
    finally:
        k32().CloseHandle(handle)


def terminate_tree(root_pid: int, root_created: int) -> list[int]:
    """Kill leaves first, then the root, each verified by creation time."""
    killed: list[int] = []
    tree = descendants(root_pid, root_created)
    for pid, created in reversed(tree):
        if terminate_exact(pid, created):
            killed.append(pid)
    if terminate_exact(root_pid, root_created):
        killed.append(root_pid)
    return killed


class Job:
    """A Windows Job Object used to track and terminate a launched process tree.

    ``kill_on_close`` ties the whole tree to the server's lifetime (commands); long-running
    managed processes are created without it so they can survive a server restart.
    """

    def __init__(self, memory_limit_bytes: int | None = None, max_active: int | None = None,
                 kill_on_close: bool = False) -> None:
        k = k32()
        self.handle = k.CreateJobObjectW(None, None)
        if not self.handle:
            raise PolicyError("JOB_CREATE_FAILED")
        flags, info = 0, _EXT_LIMIT()
        if memory_limit_bytes:
            flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY
            info.ProcessMemoryLimit = int(memory_limit_bytes)
        if max_active:
            flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            info.BasicLimitInformation.ActiveProcessLimit = int(max_active)
        if kill_on_close:
            flags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if flags:
            info.BasicLimitInformation.LimitFlags = flags
            if not k.SetInformationJobObject(self.handle, JobObjectExtendedLimitInformation,
                                             ctypes.byref(info), ctypes.sizeof(info)):
                k.CloseHandle(self.handle)
                self.handle = None
                raise PolicyError("JOB_LIMITS_NOT_APPLIED")

    def assign(self, process_handle: int) -> bool:
        return bool(k32().AssignProcessToJobObject(self.handle, process_handle))

    def terminate(self, exit_code: int = 1) -> bool:
        handle = self.handle
        return bool(handle) and bool(k32().TerminateJobObject(handle, exit_code))

    def pids(self) -> list[int]:
        if not self.handle:
            return []
        class _LIST(ctypes.Structure):
            _fields_ = [("NumberOfAssignedProcesses", wintypes.DWORD),
                        ("NumberOfProcessIdsInList", wintypes.DWORD),
                        ("ProcessIdList", ctypes.c_size_t * 256)]
        info = _LIST()
        if not k32().QueryInformationJobObject(self.handle, JobObjectBasicProcessIdList,
                                               ctypes.byref(info), ctypes.sizeof(info), None):
            return []
        return [int(info.ProcessIdList[i]) for i in range(info.NumberOfProcessIdsInList)]

    def close(self) -> None:
        handle, self.handle = self.handle, None
        if handle:
            k32().CloseHandle(handle)


def resume_process(process_handle: int) -> None:
    """Resume a process created with CREATE_SUSPENDED (ntdll!NtResumeProcess)."""
    resume = ctypes.windll.ntdll.NtResumeProcess
    resume.argtypes = [wintypes.HANDLE]
    status = resume(process_handle)
    if status != 0:
        raise PolicyError("RESUME_FAILED")


def current_user() -> str:
    return os.environ.get("USERDOMAIN", "") + "\\" + os.environ.get("USERNAME", "")
