"""Windows service inspection and allow-listed control through the Service Control Manager.

* Status/start/stop use the SCM API directly (ctypes) so results are
  locale-independent and subject to the caller's real SCM permissions; nothing
  here can bypass Service Control Manager access checks.
* Mutation requires: exact service name (no wildcards), an explicit per-service
  allowlist entry that lists the action, not on the hard-coded security-critical
  denylist, and an operator approval bound to (service, action) unless the entry
  explicitly lists the action as ``approval_free``.
* Every mutation records rollback information and confirms the resulting state.
"""
from __future__ import annotations

import ctypes
import os
import re
import time
from ctypes import wintypes
from typing import Any

from mcp.types import ToolAnnotations
from personal_dc.policy import PolicyError

from .common import (ELEVATED, approval_or_response, atomic_write_json, audit, iso, native_config, new_id,
                     redact_text, state_subdir, threaded)
from .sysrun import ps_json

_RO = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
_MUT = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False)

_NAME = re.compile(r"^[A-Za-z0-9_.$-]{1,100}$")
STATES = {1: "stopped", 2: "start_pending", 3: "stop_pending", 4: "running", 5: "continue_pending",
          6: "pause_pending", 7: "paused"}
SC_MANAGER_CONNECT = 0x0001
SERVICE_QUERY_STATUS = 0x0004
SERVICE_ENUMERATE_DEPENDENTS = 0x0008
SERVICE_START = 0x0010
SERVICE_STOP = 0x0020
SERVICE_CONTROL_STOP = 1
SC_STATUS_PROCESS_INFO = 0
SERVICE_STATE_ALL = 3

# Hard denylist: security-critical or system-fundamental services are never controllable here.
PROTECTED = {n.casefold() for n in (
    "RpcSs", "RpcEptMapper", "DcomLaunch", "SamSs", "LSM", "BFE", "mpssvc", "WinDefend", "WdNisSvc", "Sense",
    "SecurityHealthService", "wscsvc", "EventLog", "CryptSvc", "TrustedInstaller", "LanmanServer",
    "LanmanWorkstation", "TermService", "Schedule", "winmgmt", "PlugPlay", "Power", "ProfSvc", "Netlogon", "KDC",
    "NTDS", "Dnscache", "Dhcp", "nsi", "gpsvc", "SystemEventsBroker", "TimeBrokerSvc", "UserManager", "Winmgmt",
    "wuauserv", "BITS", "UsoSvc", "WaaSMedicSvc", "AppIDSvc", "VaultSvc", "KeyIso", "CertPropSvc", "sshd",
    "RemoteRegistry", "SNMP", "NlaSvc", "netprofm", "Appinfo", "seclogon", "LmHosts", "SharedAccess", "ShellHWDetection",
    "WdFilter", "WdBoot", "WdNisDrv", "MsSecFlt", "mpsdrv", "bam", "PcaSvc", "wlidsvc", "Wcmsvc")}


class _SSP(ctypes.Structure):
    _fields_ = [("dwServiceType", wintypes.DWORD), ("dwCurrentState", wintypes.DWORD),
                ("dwControlsAccepted", wintypes.DWORD), ("dwWin32ExitCode", wintypes.DWORD),
                ("dwServiceSpecificExitCode", wintypes.DWORD), ("dwCheckPoint", wintypes.DWORD),
                ("dwWaitHint", wintypes.DWORD), ("dwProcessId", wintypes.DWORD),
                ("dwServiceFlags", wintypes.DWORD)]


class _ENUM_STATUS(ctypes.Structure):
    _fields_ = [("lpServiceName", wintypes.LPWSTR), ("lpDisplayName", wintypes.LPWSTR),
                ("ServiceStatus", ctypes.c_byte * 28)]


def _adv() -> Any:
    if os.name != "nt":
        raise PolicyError("WINDOWS_ONLY")
    a = ctypes.WinDLL("advapi32", use_last_error=True)
    a.OpenSCManagerW.restype = ctypes.c_void_p
    a.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    a.OpenServiceW.restype = ctypes.c_void_p
    a.OpenServiceW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR, wintypes.DWORD]
    a.CloseServiceHandle.argtypes = [ctypes.c_void_p]
    a.QueryServiceStatusEx.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                       ctypes.POINTER(wintypes.DWORD)]
    a.StartServiceW.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
    a.ControlService.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
    a.EnumDependentServicesW.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                         ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
    return a


def _check_name(name: Any) -> str:
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise PolicyError("INVALID_SERVICE_NAME")
    if any(ch in name for ch in "*?[]%"):
        raise PolicyError("SERVICE_WILDCARDS_NOT_ALLOWED")
    return name


class _Svc:
    """Open service handle context."""

    def __init__(self, name: str, access: int) -> None:
        self.adv = _adv()
        self.name, self.access = name, access
        self.scm = self.handle = None

    def __enter__(self) -> "_Svc":
        self.scm = self.adv.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
        if not self.scm:
            raise PolicyError(f"SCM_OPEN_FAILED:{ctypes.get_last_error()}")
        self.handle = self.adv.OpenServiceW(self.scm, self.name, self.access)
        if not self.handle:
            err = ctypes.get_last_error()
            self.adv.CloseServiceHandle(self.scm)
            raise PolicyError({1060: "SERVICE_NOT_FOUND", 5: "SCM_ACCESS_DENIED"}.get(err, f"SCM_ERROR:{err}"))
        return self

    def __exit__(self, *exc: Any) -> None:
        if self.handle:
            self.adv.CloseServiceHandle(self.handle)
        if self.scm:
            self.adv.CloseServiceHandle(self.scm)

    def status(self) -> dict[str, Any]:
        info, needed = _SSP(), wintypes.DWORD()
        if not self.adv.QueryServiceStatusEx(self.handle, SC_STATUS_PROCESS_INFO, ctypes.byref(info),
                                             ctypes.sizeof(info), ctypes.byref(needed)):
            raise PolicyError(f"SCM_QUERY_FAILED:{ctypes.get_last_error()}")
        return {"state": STATES.get(info.dwCurrentState, str(info.dwCurrentState)), "pid": int(info.dwProcessId),
                "win32_exit_code": int(info.dwWin32ExitCode), "controls_accepted": int(info.dwControlsAccepted),
                "accepts_stop": bool(info.dwControlsAccepted & 1)}

    def dependents(self) -> list[dict[str, str]]:
        needed, count = wintypes.DWORD(), wintypes.DWORD()
        self.adv.EnumDependentServicesW(self.handle, SERVICE_STATE_ALL, None, 0, ctypes.byref(needed),
                                        ctypes.byref(count))
        if not needed.value:
            return []
        for _ in range(3):   # the set can grow between the size query and the read (ERROR_MORE_DATA = 234)
            buf = ctypes.create_string_buffer(needed.value)
            if self.adv.EnumDependentServicesW(self.handle, SERVICE_STATE_ALL, buf, needed.value,
                                               ctypes.byref(needed), ctypes.byref(count)):
                break
            if ctypes.get_last_error() != 234:
                raise PolicyError(f"SCM_ENUM_DEPENDENTS_FAILED:{ctypes.get_last_error()}")
        else:
            raise PolicyError("SCM_ENUM_DEPENDENTS_UNSTABLE")
        entries = ctypes.cast(buf, ctypes.POINTER(_ENUM_STATUS))
        out = []
        for i in range(count.value):
            raw = bytes(entries[i].ServiceStatus)
            state = int.from_bytes(raw[4:8], "little")
            out.append({"name": entries[i].lpServiceName, "state": STATES.get(state, str(state))})
        return out


def _try_access(name: str, access: int) -> bool:
    try:
        with _Svc(name, access):
            return True
    except PolicyError:
        return False


def _wait_state(name: str, target: str, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    current = ""
    while True:
        with _Svc(name, SERVICE_QUERY_STATUS) as svc:
            current = svc.status()["state"]
        if current == target or time.monotonic() >= deadline:
            return current
        time.sleep(0.5)


def _allow_entry(name: str) -> dict[str, Any] | None:
    cfg = native_config()
    for entry in cfg["service_allowlist"]:
        if isinstance(entry, dict) and str(entry.get("name", "")).casefold() == name.casefold():
            return entry
    return None


def _protected(name: str) -> bool:
    extra = {str(n).casefold() for n in native_config()["service_denylist_extra"]}
    return name.casefold() in PROTECTED or name.casefold() in extra


_INSPECT_PS = r"""
$n = [string]$env:PDC_ARG_NAME
$w = Get-CimInstance Win32_Service -Filter ("Name='" + $n + "'")
if (-not $w) { '{"found":false}'; exit 0 }
$s = Get-Service -Name $n
[pscustomobject]@{
  found=$true; name=$w.Name; display_name=$w.DisplayName; start_mode=$w.StartMode; start_name=$w.StartName;
  path_name=$w.PathName; process_id=$w.ProcessId; description=$w.Description; delayed_auto=$w.DelayedAutoStart;
  depends_on=@($s.ServicesDependedOn | ForEach-Object { $_.Name });
} | ConvertTo-Json -Compress -Depth 3
"""

_LIST_PS = r"""
$f = [string]$env:PDC_ARG_FILTER; $st = [string]$env:PDC_ARG_STATE
Get-CimInstance Win32_Service | Where-Object {
  ($f -eq '' -or $_.Name -like ('*' + $f + '*') -or $_.DisplayName -like ('*' + $f + '*')) -and
  ($st -eq '' -or $_.State -eq $st)
} | Sort-Object Name | Select-Object -First 400 Name, DisplayName, State, StartMode |
  ConvertTo-Json -Compress -Depth 2
"""


def service_list(name_contains: str = "", state: str = "", limit_rows: int = 200) -> dict[str, Any]:
    """List services (name, display name, state, start mode) with allowlist/protection flags."""
    if state not in ("", "Running", "Stopped", "Paused"):
        raise PolicyError("INVALID_STATE_FILTER")
    needle = name_contains.strip()[:60]
    if needle and not re.fullmatch(r"[A-Za-z0-9_. $-]*", needle):
        raise PolicyError("INVALID_FILTER")
    rows = ps_json(_LIST_PS, {"filter": needle, "state": state}, timeout=45) or []
    if isinstance(rows, dict):
        rows = [rows]
    out = []
    for row in rows[:max(1, min(int(limit_rows), 400))]:
        name = str(row["Name"])
        out.append({"name": name, "display_name": row["DisplayName"], "state": row["State"],
                    "start_mode": row["StartMode"], "protected": _protected(name),
                    "allowlisted": _allow_entry(name) is not None})
    audit("service.list", "OK", count=len(out))
    return {"count": len(out), "services": out}


def service_inspect(name: str) -> dict[str, Any]:
    """Resolve a real service by exact name: config, dependencies, live status and SCM permissions."""
    _check_name(name)
    info = ps_json(_INSPECT_PS, {"name": name}) or {"found": False}
    if not info.get("found"):
        return {"name": name, "found": False}
    with _Svc(name, SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS) as svc:
        status = svc.status()
        dependents = svc.dependents()
    entry = _allow_entry(name)
    info["path_name"] = redact_text(str(info.get("path_name") or ""))
    return {"name": name, "found": True, **info, **status, "dependents": dependents,
            "can_start": _try_access(name, SERVICE_START), "can_stop": _try_access(name, SERVICE_STOP),
            "protected": _protected(name),
            "allowlist": ({"actions": entry.get("actions", []), "approval_free": entry.get("approval_free", [])}
                          if entry else None)}


def _policy(name: str, action: str) -> dict[str, Any]:
    """Name/denylist/allowlist policy (no approval consumed). Returns the allowlist entry."""
    _check_name(name)
    if _protected(name):
        audit("service." + action, "DENIED", service=name, reason="PROTECTED")
        raise PolicyError("SERVICE_PROTECTED_SECURITY_CRITICAL")
    entry = _allow_entry(name)
    if not entry or action not in entry.get("actions", []):
        audit("service." + action, "DENIED", service=name, reason="NOT_ALLOWLISTED")
        raise PolicyError("SERVICE_ACTION_NOT_ALLOWLISTED")
    return entry


def _gate(name: str, action: str, approval_id: str | None, pre_approved: bool = False) -> dict[str, Any] | None:
    """Policy + existence check, THEN approval. Returns an approval response dict, or None when allowed."""
    entry = _policy(name, action)
    with _Svc(name, SERVICE_QUERY_STATUS):   # fails with SERVICE_NOT_FOUND before an approval is consumed
        pass
    if pre_approved or action in entry.get("approval_free", []):
        return None
    return approval_or_response("service." + action, {"service": name, "action": action}, approval_id, ELEVATED)


def _rollback(name: str, action: str, prior: str) -> str:
    rid = new_id("svr")
    atomic_write_json(state_subdir("rollback") / (rid + ".json"),
                      {"id": rid, "service": name, "action": action, "prior_state": prior, "at": iso(),
                       "restore": ("start" if prior == "running" else "stop" if prior == "stopped" else "manual"),
                       "note": "advisory record; restore only through the allow-listed service tools"})
    return rid


def _do_start(name: str, timeout_s: float) -> str:
    with _Svc(name, SERVICE_START | SERVICE_QUERY_STATUS) as svc:
        if svc.status()["state"] != "running":
            if not svc.adv.StartServiceW(svc.handle, 0, None):
                err = ctypes.get_last_error()
                if err != 1056:  # already running
                    raise PolicyError(f"SERVICE_START_FAILED:{err}")
    return _wait_state(name, "running", timeout_s)


def _do_stop(name: str, timeout_s: float) -> str:
    with _Svc(name, SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS) as svc:
        status = svc.status()
        if status["state"] not in ("stopped", "stop_pending"):
            running = [d for d in svc.dependents() if d["state"] != "stopped"]
            if running:
                raise PolicyError("SERVICE_HAS_RUNNING_DEPENDENTS:" + ",".join(d["name"] for d in running)[:200])
            if not status["accepts_stop"]:
                raise PolicyError("SERVICE_DOES_NOT_ACCEPT_STOP")
            ss = (ctypes.c_byte * 28)()
            if not svc.adv.ControlService(svc.handle, SERVICE_CONTROL_STOP, ss):
                err = ctypes.get_last_error()
                if err != 1062:  # not started
                    raise PolicyError(f"SERVICE_STOP_FAILED:{err}")
    return _wait_state(name, "stopped", timeout_s)


def _mutate(name: str, action: str, timeout_s: int, approval_id: str | None,
            pre_approved: bool = False) -> dict[str, Any]:
    """``pre_approved`` is for callers that already consumed an approval bound to a plan containing this step."""
    pending = _gate(name, action, approval_id, pre_approved)
    if pending:
        return pending
    timeout = max(5, min(int(timeout_s), 300))
    with _Svc(name, SERVICE_QUERY_STATUS) as svc:
        prior = svc.status()["state"]
    rollback_id = _rollback(name, action, prior)
    audit("service." + action, "START", service=name, prior_state=prior, rollback_id=rollback_id)
    try:
        if action == "start":
            final = _do_start(name, timeout)
            expected = "running"
        elif action == "stop":
            final = _do_stop(name, timeout)
            expected = "stopped"
        else:
            stopped = _do_stop(name, timeout)
            if stopped != "stopped":
                raise PolicyError(f"SERVICE_RESTART_STOP_NOT_CONFIRMED:{stopped}")
            final = _do_start(name, timeout)
            expected = "running"
    except PolicyError as exc:
        try:
            with _Svc(name, SERVICE_QUERY_STATUS) as svc:
                now = svc.status()["state"]
        except PolicyError:
            now = "unknown"
        audit("service." + action, "ERROR", service=name, reason=str(exc), state_now=now)
        raise
    ok = final == expected
    audit("service." + action, "OK" if ok else "UNCONFIRMED", service=name, final_state=final)
    return {"service": name, "action": action, "prior_state": prior, "final_state": final, "confirmed": ok,
            "rollback": {"id": rollback_id, "restore_by": {"running": "service_start", "stopped": "service_stop"}.get(prior, "manual")}}


def service_start(name: str, timeout_s: int = 60, approval_id: str | None = None) -> dict[str, Any]:
    """Start an allow-listed service and confirm it reached `running`."""
    return _mutate(name, "start", timeout_s, approval_id)


def service_stop(name: str, timeout_s: int = 60, approval_id: str | None = None) -> dict[str, Any]:
    """Stop an allow-listed service (refuses if dependents run) and confirm `stopped`."""
    return _mutate(name, "stop", timeout_s, approval_id)


def service_restart(name: str, timeout_s: int = 60, approval_id: str | None = None) -> dict[str, Any]:
    """Stop then start an allow-listed service; confirm `running`."""
    return _mutate(name, "restart", timeout_s, approval_id)


def service_wait(name: str, state: str = "running", timeout_s: int = 60) -> dict[str, Any]:
    """Wait (read-only) until a service reaches a state or the timeout passes."""
    _check_name(name)
    if state not in ("running", "stopped", "paused"):
        raise PolicyError("INVALID_TARGET_STATE")
    final = _wait_state(name, state, max(1, min(int(timeout_s), 300)))
    return {"service": name, "target": state, "current": final, "reached": final == state}


def service_current_state(name: str) -> str:
    """Helper for other modules (apache control)."""
    with _Svc(_check_name(name), SERVICE_QUERY_STATUS) as svc:
        return svc.status()["state"]


def register_service_tools(server: Any) -> None:
    server.tool(annotations=_RO)(threaded(service_list))
    server.tool(annotations=_RO)(threaded(service_inspect))
    server.tool(annotations=_MUT)(threaded(service_start))
    server.tool(annotations=_MUT)(threaded(service_stop))
    server.tool(annotations=_MUT)(threaded(service_restart))
    server.tool(annotations=_RO)(threaded(service_wait))
