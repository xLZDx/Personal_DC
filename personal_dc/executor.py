from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import Any

from .audit import record
from .policy import Policy

MAX_CAPTURE = 40000


_SECRET_ENV_MARKERS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")


def _child_env() -> dict[str, str]:
    """Environment for policy-run children: no gateway/tunnel/API secrets are inherited."""
    return {k: v for k, v in os.environ.items()
            if not k.upper().startswith(("PDC_", "CONTROL_PLANE_", "OPENAI_"))
            and not any(m in k.upper() for m in _SECRET_ENV_MARKERS)}


def run(executable: str, args: list[str], cwd: str | Path, timeout: int = 120) -> dict[str, Any]:
    policy = Policy()
    safe_cwd = policy.resolve_path(cwd)
    exe, safe_args = policy.validate_command(executable, args)
    if Path(exe).name.casefold() in {"git", "git.exe"}:
        safe_args = ["-c", "core.fsmonitor=false", *safe_args]
    timeout = max(1, min(int(timeout), 1800))
    started = time.monotonic()
    record("command", "START", executable=exe, args=safe_args, cwd=str(safe_cwd), timeout=timeout)
    try:
        proc = subprocess.run(
            [exe, *safe_args],
            cwd=str(safe_cwd),
            env=_child_env(),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            shell=False,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        result = {
            "exit_code": proc.returncode,
            "stdout": proc.stdout[-MAX_CAPTURE:],
            "stderr": proc.stderr[-MAX_CAPTURE:],
            "duration_s": round(time.monotonic() - started, 3),
        }
        record(
            "command",
            "OK" if proc.returncode == 0 else "ERROR",
            executable=exe,
            args=safe_args,
            cwd=str(safe_cwd),
            exit_code=proc.returncode,
        )
        return result
    except subprocess.TimeoutExpired as exc:
        record("command", "TIMEOUT", executable=exe, args=safe_args, cwd=str(safe_cwd), timeout=timeout)
        return {
            "exit_code": None,
            "stdout": (exc.stdout or "")[-MAX_CAPTURE:] if isinstance(exc.stdout, str) else "",
            "stderr": (exc.stderr or "")[-MAX_CAPTURE:] if isinstance(exc.stderr, str) else "",
            "duration_s": round(time.monotonic() - started, 3),
            "timeout": True,
        }
