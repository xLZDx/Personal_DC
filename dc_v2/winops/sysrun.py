"""Internal bounded runner for FIXED, server-authored scripts/executables.

Never used for caller-supplied commands (those go through managed processes).
Caller data reaches PowerShell only through environment variables
(``PDC_ARG_*``), never by string interpolation, so it cannot alter the script.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from personal_dc.policy import PolicyError

from . import procs
from .common import atomic_write_bytes, state_subdir

MAX_BYTES = 400000
_PRELUDE = ("$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';"
            "[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);")


def _sys_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    root = os.environ.get("SystemRoot", r"C:\Windows")
    env = {"SystemRoot": root, "WINDIR": root,
           "PATH": ";".join([os.path.join(root, "System32"), root,
                             os.path.join(root, "System32", "Wbem")]),
           "TEMP": os.environ.get("TEMP", os.path.join(root, "Temp")),
           "TMP": os.environ.get("TMP", os.path.join(root, "Temp")),
           "USERPROFILE": os.environ.get("USERPROFILE", ""),
           "LOCALAPPDATA": os.environ.get("LOCALAPPDATA", ""),
           "PSModulePath": os.environ.get("PSModulePath", "")}
    for key, value in (extra or {}).items():
        if not key.startswith("PDC_ARG_"):
            raise PolicyError("INVALID_ENV_NAME")
        env[key] = str(value)[:4096]
    return env


def run_capture(argv: list[str], timeout: int = 30, env: dict[str, str] | None = None,
                cwd: str | None = None) -> dict[str, Any]:
    """Run argv (no shell) and capture bounded output; kill the tree on timeout."""
    if os.name != "nt":
        raise PolicyError("WINDOWS_ONLY")
    started = time.monotonic()
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                shell=False, env=_sys_env(env), cwd=cwd or os.path.join(
                                    os.environ.get("SystemRoot", r"C:\Windows"), "System32"),
                                creationflags=subprocess.CREATE_NO_WINDOW)
    except OSError as exc:
        return {"exit_code": None, "error": type(exc).__name__, "launch_error": True, "stdout": "",
                "stderr": "", "timed_out": False}
    created = procs.creation_time(proc.pid)
    timed_out = False
    try:
        out, err = proc.communicate(timeout=max(1, timeout))
    except subprocess.TimeoutExpired:
        timed_out = True
        if created:
            procs.terminate_tree(proc.pid, created)
        proc.kill()
        try:
            out, err = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:   # a surviving grandchild still holds the pipes
            out, err = b"", b""
    return {"exit_code": proc.returncode, "timed_out": timed_out,
            "stdout": out[:MAX_BYTES].decode("utf-8", errors="replace"),
            "stderr": err[:20000].decode("utf-8", errors="replace"),
            "duration_s": round(time.monotonic() - started, 3)}


SCRIPT_KEEP_DAYS = 7


def script_file(text: str) -> Path:
    """Persist a PowerShell script as a content-addressed ``.ps1`` (UTF-8 with BOM) and return its path.

    Running a file avoids ``-EncodedCommand`` blobs, which behavioural antivirus engines treat as a malware
    signature. The name is the SHA-256 of the content, so identical text maps to the same read-only file and the
    approval digest (which binds the script text) also binds the file that runs.
    """
    folder = state_subdir("scripts")
    body = b"\xef\xbb\xbf" + text.encode("utf-8")
    path = folder / (hashlib.sha256(body).hexdigest()[:40] + ".ps1")
    if not path.exists() or path.read_bytes() != body:
        atomic_write_bytes(path, body)
    _prune_scripts(folder, keep=path)
    return path


SCRIPT_MAX_FILES = 200
SCRIPT_MAX_BYTES = 8 * 1024 * 1024
_PRUNE_STATE = {"last": 0.0}


def _prune_scripts(folder: Path, keep: Path) -> None:
    """Bounded housekeeping of server-owned staging scripts: age, file count and total bytes; at most once a minute
    and at most 100 removals per pass, so a flood of requests can neither fill the disk nor stall the backend."""
    now = time.time()
    if now - _PRUNE_STATE["last"] < 60:
        return
    _PRUNE_STATE["last"] = now
    entries = []
    with contextlib.suppress(OSError):
        for item in folder.glob("*.ps1"):
            st = item.stat()
            entries.append((st.st_mtime, st.st_size, item))
    entries.sort(key=lambda e: e[0])                       # oldest first
    total = sum(e[1] for e in entries)
    cutoff = now - SCRIPT_KEEP_DAYS * 86400
    removed = 0
    for mtime, size, item in entries:
        if removed >= 100 or item == keep:
            continue
        if mtime < cutoff or len(entries) - removed > SCRIPT_MAX_FILES or total > SCRIPT_MAX_BYTES:
            with contextlib.suppress(OSError):
                item.unlink()
                total -= size
                removed += 1


def verify_script_file(path: Path, text: str) -> None:
    """Re-read the file immediately before launch: the bytes that run must be exactly the approved text."""
    expected = b"\xef\xbb\xbf" + text.encode("utf-8")
    try:
        actual = path.read_bytes()
    except OSError as exc:
        raise PolicyError("SCRIPT_FILE_UNREADABLE") from exc
    if actual != expected:
        raise PolicyError("SCRIPT_FILE_CHANGED_BEFORE_LAUNCH")


def ps_file_args(path: Path) -> list[str]:
    """Argument vector that runs a script file: RemoteSigned (local files) instead of Bypass."""
    return ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-File", str(path)]


def run_ps(script: str, args: dict[str, str] | None = None, timeout: int = 30) -> dict[str, Any]:
    """Run a fixed PowerShell script. ``args`` become ``$env:PDC_ARG_<NAME>``."""
    env = {"PDC_ARG_" + k.upper(): v for k, v in (args or {}).items()}
    ps = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0",
                      "powershell.exe")
    return run_capture([ps, *ps_file_args(script_file(_PRELUDE + script))], timeout=timeout, env=env)


def ps_json(script: str, args: dict[str, str] | None = None, timeout: int = 30) -> Any:
    """Run a fixed script that ends in ``ConvertTo-Json``; raise on failure."""
    result = run_ps(script, args, timeout)
    if result.get("timed_out"):
        raise PolicyError("POWERSHELL_TIMEOUT")
    if result["exit_code"] != 0:
        raise PolicyError("POWERSHELL_FAILED:" + result["stderr"].strip().splitlines()[0][:160]
                          if result["stderr"].strip() else "POWERSHELL_FAILED")
    text = result["stdout"].strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError as exc:
        raise PolicyError("POWERSHELL_OUTPUT_NOT_JSON") from exc
