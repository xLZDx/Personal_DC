"""Native PowerShell / CMD / executable command execution on top of managed processes.

Security model (structure, not keyword blacklists):

* ``read_only``      - a *structural allowlist*: fixed catalog aliases, allow-listed
                       system executables with validated arguments, or a PowerShell
                       pipeline made only of allow-listed Get-* cmdlets with literal
                       parameters. Everything else is rejected before launch.
* ``workspace_write``- cwd inside approved roots. Trusted dev tools (git, python,
                       npm, node...) run without approval; shells and any other
                       executable need an operator approval bound to the exact
                       command digest.
* ``elevated``       - always needs an operator approval. The server never raises
                       its own token or bypasses UAC.
"""
from __future__ import annotations

import base64
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from mcp.types import ToolAnnotations
from personal_dc.policy import PolicyError

from .common import (ELEVATED, READ_ONLY, WORKSPACE_WRITE, audit, bounded, limit, safe_path, state_subdir)
from .process_tools import (TERMINAL, Managed, authorize_launch, build_env, get_managed, guard_git_args, launch,
                            public_meta, read_output, resolve_exe, stop_managed, wait_done)

_RO = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
_WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False)
_STOP = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=False)

SYS32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")

# Legacy fixed aliases kept for backward compatibility with the first native release.
CATALOG: dict[str, tuple[str, ...]] = {
    "python_version": ("C:\\Python314\\python.exe", "--version"),
    "whoami": ("whoami.exe",),
    "hostname": ("hostname.exe",),
    "ipconfig": ("ipconfig.exe", "/all"),
    "network_ports": ("netstat.exe", "-ano", "-p", "tcp"),
    "processes": ("tasklist.exe", "/fo", "csv", "/nh"),
    "services": ("sc.exe", "query", "state=", "all"),
    "systeminfo": ("systeminfo.exe",),
    "disk_free": ("fsutil.exe", "volume", "diskfree", "C:"),
}

# System executables permitted in read_only mode: first-arg allowlist and forbidden args.
_RO_EXES: dict[str, dict[str, Any]] = {
    "whoami.exe": {"first": None, "deny": set()},
    "hostname.exe": {"first": None, "deny": set()},
    "ipconfig.exe": {"first": None, "deny": {"/release", "/renew", "/flushdns", "/registerdns", "/release6", "/renew6"}},
    "netstat.exe": {"first": None, "deny": set()},
    "tasklist.exe": {"first": None, "deny": {"/s", "/u", "/p"}},
    "systeminfo.exe": {"first": None, "deny": {"/s", "/u", "/p"}},
    "sc.exe": {"first": {"query", "queryex", "qc", "qdescription", "qfailure", "enumdepend"}, "deny": set()},
    "where.exe": {"first": None, "deny": {"/r"}},
    "fsutil.exe": {"first": {"volume", "fsinfo"}, "deny": {"setzeroeable", "dirty"}},
}
_RO_ARG = re.compile(r"^[A-Za-z0-9_./:=\\*,\- ]{1,120}$")

_PS_PRODUCERS = {"get-process", "get-service", "get-netipaddress", "get-nettcpconnection", "get-netadapter",
                 "get-ciminstance", "get-computerinfo", "get-date", "get-hotfix", "get-volume", "get-disk",
                 "get-psdrive", "get-timezone", "get-culture"}
_PS_FILTERS = {"select-object", "sort-object", "measure-object", "format-list", "format-table",
               "convertto-json", "out-string", "where-object-simple"}
_PS_FORBIDDEN_PARAMS = {"-computername", "-cimsession", "-credential", "-session", "-asjob", "-computer",
                        "-includeusername", "-module", "-fileversioninfo"}
_CIM_CLASSES = {"win32_operatingsystem", "win32_computersystem", "win32_processor", "win32_logicaldisk",
                "win32_service", "win32_networkadapterconfiguration", "win32_bios", "win32_physicalmemory",
                "win32_timezone", "win32_quickfixengineering"}
_PS_TOKEN = re.compile(r"\s*(?:(?P<pipe>\|)|(?P<str>'[A-Za-z0-9_ .:\\/*,=%-]{0,200}')|"
                       r"(?P<param>-[A-Za-z]{1,40})|(?P<word>[A-Za-z0-9_.:\\*,/%=-]{1,200}))")
_PS_PRELUDE = ("$ProgressPreference='SilentlyContinue';"
               "[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);"
               "$OutputEncoding=[Console]::OutputEncoding;")
_PS_EPILOGUE = "\r\nif ($LASTEXITCODE) { exit $LASTEXITCODE } elseif (-not $?) { exit 1 }"
MAX_SCRIPT_CHARS = 6000


def validate_readonly_powershell(command: str) -> str:
    """Structural validation of a read-only PowerShell pipeline; returns the normalized script."""
    if not isinstance(command, str) or not command.strip() or len(command) > 1000 or "\x00" in command:
        raise PolicyError("INVALID_READONLY_POWERSHELL")
    pos, segments, current = 0, [], []
    while pos < len(command):
        if command[pos:].strip() == "":
            break
        match = _PS_TOKEN.match(command, pos)
        if not match or match.end() == pos:
            raise PolicyError("READONLY_POWERSHELL_SYNTAX_NOT_ALLOWED")
        pos = match.end()
        if match.group("pipe"):
            segments.append(current)
            current = []
        else:
            kind = match.lastgroup
            current.append((kind, match.group(kind)))
    segments.append(current)
    if len(segments) > 5 or any(not seg for seg in segments):
        raise PolicyError("READONLY_POWERSHELL_PIPELINE_INVALID")
    for index, seg in enumerate(segments):
        head_kind, head = seg[0]
        name = head.casefold()
        allowed = _PS_PRODUCERS if index == 0 else _PS_FILTERS
        if head_kind != "word" or name not in allowed:
            raise PolicyError("READONLY_POWERSHELL_CMDLET_NOT_ALLOWED:" + head[:40])
        params = [v.casefold() for k, v in seg[1:] if k == "param"]
        if any(p in _PS_FORBIDDEN_PARAMS for p in params):
            raise PolicyError("READONLY_POWERSHELL_PARAMETER_NOT_ALLOWED")
        if name == "get-ciminstance":
            values = [v.strip("'").casefold() for k, v in seg[1:] if k in ("word", "str")]
            if not values or values[0] not in _CIM_CLASSES:
                raise PolicyError("READONLY_CIM_CLASS_NOT_ALLOWED")
    return command.strip()


def encode_powershell(script: str) -> str:
    return base64.b64encode((_PS_PRELUDE + script + _PS_EPILOGUE).encode("utf-16-le")).decode("ascii")


def _validate_readonly_exec(name: str, args: list[str]) -> None:
    spec = _RO_EXES.get(name.casefold())
    if not spec:
        raise PolicyError("READONLY_EXECUTABLE_NOT_ALLOWED:" + name[:40])
    for arg in args:
        if not isinstance(arg, str) or not _RO_ARG.fullmatch(arg):
            raise PolicyError("READONLY_ARGUMENT_NOT_ALLOWED")
        if arg.casefold() in spec["deny"]:
            raise PolicyError("READONLY_ARGUMENT_DENIED")
    if spec["first"] is not None and (not args or args[0].casefold() not in spec["first"]):
        raise PolicyError("READONLY_SUBCOMMAND_NOT_ALLOWED")


def _quote(arg: str) -> str:
    return subprocess.list2cmdline([arg])


def _prepare(shell: str, command: str, argv: list[str] | None, mode: str, env: dict[str, str]) -> dict[str, Any]:
    """Return launch spec: exe_path, argv|cmdline, summary, force_approval."""
    if shell == "catalog":
        if command not in CATALOG:
            raise PolicyError("COMMAND_NOT_IN_SAFE_ALLOWLIST")
        vector = list(CATALOG[command])
        exe = resolve_exe(vector[0], env)
        return {"exe": exe, "argv": vector[1:], "cmdline": None, "summary": {"catalog": command}, "force": False}
    if shell == "exec":
        vector = list(argv or [])
        if not vector or len(vector) > 100:
            raise PolicyError("ARGV_REQUIRED")
        if any(not isinstance(a, str) or "\x00" in a or len(a) > 8192 for a in vector):
            raise PolicyError("INVALID_ARGUMENTS")
        exe = resolve_exe(vector[0], env)
        args = vector[1:]
        if mode == READ_ONLY:
            _validate_readonly_exec(exe.name, args)
        if exe.name.casefold() == "git.exe":
            args = guard_git_args(args)
        if exe.name.casefold() in {"powershell.exe", "pwsh.exe", "cmd.exe"}:
            return {"exe": exe, "argv": args, "cmdline": None, "summary": {"argv": [exe.name, *args]},
                    "force": True}
        return {"exe": exe, "argv": args, "cmdline": None, "summary": {"argv": [exe.name, *args]}, "force": False}
    if shell == "powershell":
        if not isinstance(command, str) or not command.strip() or len(command) > MAX_SCRIPT_CHARS:
            raise PolicyError("INVALID_SCRIPT")
        if mode == READ_ONLY:
            script = validate_readonly_powershell(command)
        else:
            script = command
        exe = resolve_exe("powershell.exe", env)
        base = ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encode_powershell(script)]
        return {"exe": exe, "argv": base, "cmdline": None, "summary": {"powershell": script}, "force": mode != READ_ONLY}
    if shell == "cmd":
        if mode == READ_ONLY:
            raise PolicyError("CMD_NOT_AVAILABLE_IN_READ_ONLY_MODE")
        if not isinstance(command, str) or not command.strip() or len(command) > 4000 or "\x00" in command \
                or "\n" in command or "\r" in command:
            raise PolicyError("INVALID_CMD_COMMAND")
        exe = resolve_exe("cmd.exe", env)
        line = f'{_quote(str(exe))} /d /s /c "chcp 65001>nul & {command}"'
        return {"exe": exe, "argv": None, "cmdline": line, "summary": {"cmd": command}, "force": True}
    raise PolicyError("UNKNOWN_SHELL")


def _start(shell: str, command: str, argv: list[str] | None, cwd: str, timeout_s: int, mode: str,
           env: dict[str, str] | None, approval_id: str | None, kind_label: str) -> dict[str, Any] | Managed:
    if mode not in (READ_ONLY, WORKSPACE_WRITE, ELEVATED):
        raise PolicyError("UNKNOWN_TRUST_MODE")
    environment = build_env(env)
    spec = _prepare(shell, command, argv, mode, environment)
    if mode == READ_ONLY:
        workdir = Path(SYS32)
    else:
        workdir = safe_path(cwd or "D:\\Temp")
        if not workdir.is_dir():
            raise PolicyError("CWD_NOT_A_DIRECTORY")
    timeout = max(1, min(int(timeout_s), limit("max_timeout_s")))
    params = {"shell": shell, "summary": spec["summary"], "cwd": str(workdir), "timeout_s": timeout,
              "env": sorted((env or {}).keys())}
    pending = authorize_launch(mode, spec["exe"], environment, params, approval_id, force_approval=spec["force"])
    if pending:
        return pending
    return launch(kind="command", label=kind_label, argv=spec["argv"], cmdline=spec["cmdline"],
                  exe_path=spec["exe"], cwd=workdir, env=environment, timeout_s=timeout, mode=mode,
                  approval_id=approval_id, summary=params, kill_orphans=True)


def command_execute(command: str = "", shell: str = "catalog", argv: list[str] | None = None, cwd: str = "",
                    timeout_s: int = 30, mode: str = READ_ONLY, env: dict[str, str] | None = None,
                    approval_id: str | None = None, max_chars: int = 30000) -> dict[str, Any]:
    """Run a command to completion and return bounded output.

    shell: catalog (legacy fixed aliases: whoami, ipconfig, processes, services...),
    powershell, cmd, or exec (argument vector in `argv`, no shell).
    mode: read_only (structural allowlist) | workspace_write | elevated.
    Non-trivial commands return APPROVAL_REQUIRED until the operator grants approval_id.
    On timeout the whole process tree is killed (state timed_out).
    """
    result = _start(shell, command, argv, cwd, timeout_s, mode, env, approval_id, shell)
    if isinstance(result, dict):
        return result
    managed: Managed = result
    wait_done(managed, max(1, min(int(timeout_s), limit("max_timeout_s"))) + 15)
    out = _result(managed, max_chars)
    if shell == "catalog":
        out["command"] = command  # legacy response field
    return out


def _result(managed: Managed, max_chars: int) -> dict[str, Any]:
    cap = max(100, min(int(max_chars), 100000))
    pages = {}
    for stream in ("stdout", "stderr"):
        page = read_output(managed, stream, 0, min(cap, limit("max_page_bytes")))
        text, cut = bounded(page["text"], cap)
        pages[stream] = (text, cut or page["next_offset"] < page["size"], page["next_offset"], page["size"])
    meta = managed.meta
    return {"id": meta["id"], "state": meta["state"], "exit_code": meta["exit_code"],
            "timed_out": meta["state"] == "timed_out", "stdout": pages["stdout"][0], "stderr": pages["stderr"][0],
            "stdout_truncated": pages["stdout"][1], "stderr_truncated": pages["stderr"][1],
            "stdout_next_offset": pages["stdout"][2], "stderr_next_offset": pages["stderr"][2],
            "output_bytes": {"stdout": pages["stdout"][3], "stderr": pages["stderr"][3]},
            "started_at": meta["started_at"], "ended_at": meta["ended_at"]}


def command_start(command: str = "", shell: str = "powershell", argv: list[str] | None = None, cwd: str = "",
                  timeout_s: int = 600, mode: str = WORKSPACE_WRITE, env: dict[str, str] | None = None,
                  approval_id: str | None = None) -> dict[str, Any]:
    """Start a command in the background; poll with command_status / command_output."""
    result = _start(shell, command, argv, cwd, timeout_s, mode, env, approval_id, shell)
    if isinstance(result, dict):
        return result
    return {"status": "STARTED", **public_meta(result.meta)}


def _command(process_id: str) -> Managed:
    managed = get_managed(process_id)
    if managed.meta["kind"] != "command":
        raise PolicyError("NOT_A_COMMAND_USE_PROCESS_TOOLS")
    return managed


def command_status(command_id: str) -> dict[str, Any]:
    """State, exit code and timing of a command started with command_start."""
    managed = _command(command_id)
    return {**public_meta(managed.meta), "terminal": managed.meta["state"] in TERMINAL}


def command_output(command_id: str, stream: str = "stdout", offset: int = 0, max_bytes: int = 16384) -> dict[str, Any]:
    """Paginated UTF-8 output (byte-offset cursors) of a command."""
    return read_output(_command(command_id), stream, offset, max_bytes)


def command_cancel(command_id: str) -> dict[str, Any]:
    """Cancel a command and terminate its process tree."""
    return stop_managed(_command(command_id), "stopped")


def command_history(limit_rows: int = 30, state: str = "") -> dict[str, Any]:
    """Recent managed commands (newest first) with redacted summaries."""
    base = state_subdir("procs")
    rows = []
    for directory in sorted(base.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        meta_path = directory / "meta.json"
        if not meta_path.is_file():
            continue
        try:
            import json
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            continue
        if meta.get("kind") != "command" or (state and meta.get("state") != state):
            continue
        rows.append(public_meta(meta))
        if len(rows) >= max(1, min(int(limit_rows), 200)):
            break
    audit("command.history", "OK", count=len(rows))
    return {"commands": rows}


def register_command_tools(server: Any) -> None:
    server.tool(annotations=_WRITE)(command_execute)
    server.tool(annotations=_WRITE)(command_start)
    server.tool(annotations=_RO)(command_status)
    server.tool(annotations=_RO)(command_output)
    server.tool(annotations=_STOP)(command_cancel)
    server.tool(annotations=_RO)(command_history)
