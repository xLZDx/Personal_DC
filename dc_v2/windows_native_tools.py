"""Read-only and narrowly scoped native Windows tools for personal DC v2.

No shell=True, arbitrary PowerShell scripts, privilege elevation, service
mutation, installation, credential access or unbounded process execution.
The caller chooses from enumerated, audited commands only.
"""
from __future__ import annotations

import csv
import io
import os
import re
import subprocess
import time
from typing import Any

from mcp.types import ToolAnnotations
from personal_dc.audit import record
from personal_dc.policy import PolicyError

_READ_ONLY = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_MAX_BYTES = 30000

# Fixed argument vectors (not command fragments). Do not add a shell here.
_COMMANDS: dict[str, tuple[str, ...]] = {
    "python_version": ("C:\\Python314\\python.exe", "--version"),
    "whoami": ("whoami.exe",),
    "ipconfig": ("ipconfig.exe", "/all"),
    "network_ports": ("netstat.exe", "-ano", "-p", "tcp"),
    "processes": ("tasklist.exe", "/fo", "csv", "/nh"),
    "services": ("sc.exe", "query", "state=", "all"),
}


def _native_run(argv: tuple[str, ...], timeout: int = 15) -> dict[str, Any]:
    if os.name != "nt":
        raise PolicyError("WINDOWS_ONLY_NATIVE_TOOL")
    if not argv or any(not arg or "\x00" in arg for arg in argv):
        raise PolicyError("INVALID_NATIVE_COMMAND")
    started = time.monotonic()
    record("native.command", "START", operation=argv[0], args=list(argv[1:]))
    try:
        cp = subprocess.run(
            list(argv), shell=False, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=max(1, min(timeout, 20)),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            env={"SystemRoot": os.environ.get("SystemRoot", r"C:\\Windows"),
                 "WINDIR": os.environ.get("WINDIR", r"C:\\Windows"),
                 "PATH": os.path.join(os.environ.get("SystemRoot", r"C:\\Windows"), "System32")},
        )
        result = {
            "exit_code": cp.returncode,
            "stdout": cp.stdout[:_MAX_BYTES],
            "stderr": cp.stderr[:3000],
            "truncated": len(cp.stdout) > _MAX_BYTES,
            "duration_s": round(time.monotonic() - started, 3),
        }
        record("native.command", "OK" if cp.returncode == 0 else "ERROR",
               operation=argv[0], exit_code=cp.returncode)
        return result
    except (OSError, subprocess.TimeoutExpired) as exc:
        record("native.command", "ERROR", operation=argv[0],
               reason=type(exc).__name__)
        return {"exit_code": None, "error": type(exc).__name__,
                "duration_s": round(time.monotonic() - started, 3)}


def system_diagnostics(kind: str = "processes") -> dict[str, Any]:
    """Inspect Windows processes, services, TCP ports, or network adapters.

    Allowed kinds: processes, services, network_ports, ipconfig.
    This is read-only and does not run a user-supplied command.
    """
    allowed = {"processes", "services", "network_ports", "ipconfig"}
    if kind not in allowed:
        raise PolicyError("UNKNOWN_DIAGNOSTIC_KIND")
    return {"kind": kind, **_native_run(_COMMANDS[kind])}


def service_status(service_name: str) -> dict[str, Any]:
    """Read Windows service status by literal service name; cannot start/stop."""
    if not isinstance(service_name, str) or not _NAME.fullmatch(service_name):
        raise PolicyError("INVALID_SERVICE_NAME")
    return {"service": service_name,
            **_native_run(("sc.exe", "query", service_name))}


def command_execute(command: str) -> dict[str, Any]:
    """Execute ONLY a fixed, no-argument read-only Windows command.

    Allowlisted: python_version, whoami, ipconfig, network_ports,
    processes, services. No shell, PowerShell, pipes or custom args.
    """
    if command not in _COMMANDS:
        raise PolicyError("COMMAND_NOT_IN_SAFE_ALLOWLIST")
    return {"command": command, **_native_run(_COMMANDS[command])}


def register_native_tools(server: Any) -> None:
    """Register native tools exclusively in the v2 entrypoint process."""
    server.tool(annotations=_READ_ONLY)(system_diagnostics)
    server.tool(annotations=_READ_ONLY)(service_status)
    server.tool(annotations=_READ_ONLY)(command_execute)
