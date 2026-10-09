"""Managed Windows processes: launch, identity-verified control, durable metadata.

Every launched process is recorded under ``<state>/procs/<id>/`` (meta.json,
stdout.log, stderr.log). Output goes to files, not pipes, so it survives an MCP
server restart; a monitor thread enforces timeout, output cap and cancellation.
After a restart ``recover()`` re-adopts live processes by ``(pid, creation time,
image)`` identity and marks the rest ``exited_unknown``.

Only processes launched through this module can be stopped. There is no
``taskkill``; termination is per-PID with creation-time verification.
"""
from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from mcp.types import ToolAnnotations
from personal_dc.policy import PolicyError

from . import procs
from .common import (ELEVATED, READ_ONLY, WORKSPACE_WRITE, approval_or_response, atomic_write_json, audit,
                     iso, limit, native_config, new_id, read_json, redact, redact_text, safe_path,
                     state_subdir, valid_id)

_RO = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
_WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False)
_STOP = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=False)

TERMINAL = {"exited", "exited_unknown", "stopped", "timed_out", "output_limit", "failed_to_start"}
_FORBIDDEN_ENV = {"PATH", "PATHEXT", "COMSPEC", "SYSTEMROOT", "WINDIR", "PYTHONPATH", "PYTHONSTARTUP",
                  "PYTHONHOME", "NODE_OPTIONS", "GIT_SSH_COMMAND", "GIT_ASKPASS", "LD_PRELOAD"}
_REGISTRY: dict[str, "Managed"] = {}
_REG_LOCK = threading.RLock()
_RECOVERED = False


class Managed:
    def __init__(self, meta: dict[str, Any], popen: subprocess.Popen | None = None,
                 job: procs.Job | None = None) -> None:
        self.meta = meta
        self.popen = popen
        self.job = job
        self.cancel = threading.Event()
        self.stop_reason: str | None = None
        self.done = threading.Event()
        self.lock = threading.RLock()

    @property
    def dir(self) -> Path:
        return state_subdir("procs") / self.meta["id"]

    def save(self) -> None:
        with self.lock:
            atomic_write_json(self.dir / "meta.json", self.meta)


# ---------------------------------------------------------------- env / exe
def build_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    cfg = native_config()
    env = {k: os.environ[k] for k in cfg["env_passthrough"] if k in os.environ}
    root = env.get("SystemRoot", r"C:\Windows")
    dirs = [os.path.join(root, "System32"), root, os.path.join(root, "System32", "Wbem"),
            os.path.join(root, "System32", "WindowsPowerShell", "v1.0")]
    dirs += [d for d in cfg["extra_path_dirs"] if os.path.isdir(d)]
    env["PATH"] = ";".join(dirs)
    env.setdefault("PATHEXT", ".COM;.EXE;.BAT;.CMD")
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    for name, value in (extra or {}).items():
        if (not isinstance(name, str) or not isinstance(value, str) or len(value) > 4096
                or not name.replace("_", "").isalnum() or name.upper() in _FORBIDDEN_ENV
                or name.upper().startswith("PDC_") or any(m in name.upper() for m in ("KEY", "TOKEN", "SECRET"))):
            raise PolicyError("ENV_VAR_NOT_ALLOWED:" + str(name)[:40])
        env[name] = value
    return env


def trusted_dirs(env: dict[str, str]) -> list[Path]:
    return [Path(p).resolve(strict=False) for p in env["PATH"].split(";") if p]


def resolve_exe(exe: str, env: dict[str, str]) -> Path:
    """Resolve to an absolute file. Bare names resolve ONLY on the sanitized PATH (never cwd)."""
    if not isinstance(exe, str) or not exe or "\x00" in exe:
        raise PolicyError("INVALID_EXECUTABLE")
    if any(ch in exe for ch in "\\/:") or exe.startswith("."):
        path = Path(exe)
        if not path.is_absolute():
            raise PolicyError("RELATIVE_EXECUTABLE_NOT_ALLOWED")
        found: str | None = str(path) if path.is_file() else None
    else:
        found = shutil.which(exe, path=env["PATH"])
    if not found:
        raise PolicyError("EXECUTABLE_NOT_FOUND:" + exe[:60])
    return Path(found).resolve(strict=True)


def is_trusted_dev_tool(exe_path: Path, env: dict[str, str]) -> bool:
    cfg = native_config()
    names = {n.casefold() for n in cfg["dev_executables"]}
    return exe_path.name.casefold() in names and exe_path.parent in trusted_dirs(env)


def authorize_launch(mode: str, exe_path: Path, env: dict[str, str], params: dict[str, Any],
                     approval_id: str | None, force_approval: bool = False) -> dict[str, Any] | None:
    """``None`` = allowed; a dict = response to return to the caller (approval needed)."""
    if mode not in (READ_ONLY, WORKSPACE_WRITE, ELEVATED):
        raise PolicyError("UNKNOWN_TRUST_MODE")
    if mode == READ_ONLY:
        return None
    if mode == WORKSPACE_WRITE and not force_approval and is_trusted_dev_tool(exe_path, env):
        return None
    return approval_or_response("exec." + mode, params, approval_id, mode)


# ------------------------------------------------------------------ launch
def _live_count() -> int:
    with _REG_LOCK:
        return sum(1 for m in _REGISTRY.values() if m.meta["state"] == "running")


def launch(*, kind: str, label: str, argv: list[str] | None, cmdline: str | None, exe_path: Path,
           cwd: Path, env: dict[str, str], timeout_s: int, mode: str, approval_id: str | None,
           summary: dict[str, Any], kill_orphans: bool, memory_limit_mb: int | None = None) -> Managed:
    ensure_recovered()
    if _live_count() >= limit("max_managed_processes"):
        raise PolicyError("TOO_MANY_MANAGED_PROCESSES")
    pid_id = new_id("prc")
    directory = state_subdir("procs") / pid_id
    directory.mkdir(parents=True)
    meta: dict[str, Any] = {
        "id": pid_id, "kind": kind, "label": label[:80], "state": "starting", "mode": mode,
        "exe": str(exe_path), "summary": redact(summary), "cwd": str(cwd), "owner": procs.current_user(),
        "approval_id": approval_id, "started_at": iso(), "ended_at": None, "pid": None, "created": None,
        "timeout_s": timeout_s, "exit_code": None, "stop_reason": None, "output_truncated": False,
        "children_seen": [], "recovered": False,
    }
    audit("process.start", "START", process_id=pid_id, kind=kind, exe=str(exe_path), cwd=str(cwd), mode=mode,
          summary=summary, approval_id=approval_id)
    out = (directory / "stdout.log").open("xb")
    err = (directory / "stderr.log").open("xb")
    job = None
    try:
        job = procs.Job(memory_limit_bytes=(memory_limit_mb or 0) * 1024 * 1024 or None)
        flags = (subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP | procs.CREATE_SUSPENDED)
        args: Any = cmdline if cmdline is not None else [str(exe_path), *(argv or [])]
        popen = subprocess.Popen(args, cwd=str(cwd), env=env, stdin=subprocess.DEVNULL, stdout=out,
                                 stderr=err, shell=False, creationflags=flags)
    except (OSError, ValueError, PolicyError) as exc:
        out.close()
        err.close()
        if job:
            job.close()
        meta.update(state="failed_to_start", ended_at=iso(), stop_reason=type(exc).__name__)
        atomic_write_json(directory / "meta.json", meta)
        audit("process.start", "ERROR", process_id=pid_id, reason=type(exc).__name__)
        raise PolicyError("PROCESS_START_FAILED:" + type(exc).__name__) from exc
    out.close()
    err.close()
    handle = int(popen._handle)  # type: ignore[attr-defined]
    assigned = job.assign(handle)
    try:
        procs.resume_process(handle)
    except PolicyError:
        procs.terminate_exact(popen.pid, procs.creation_time(popen.pid) or 0)
        job.close()
        meta.update(state="failed_to_start", ended_at=iso(), stop_reason="RESUME_FAILED")
        atomic_write_json(directory / "meta.json", meta)
        raise
    meta.update(state="running", pid=popen.pid, created=procs.creation_time(popen.pid),
                job_assigned=assigned)
    managed = Managed(meta, popen, job)
    managed.kill_orphans = kill_orphans  # type: ignore[attr-defined]
    with _REG_LOCK:
        _REGISTRY[pid_id] = managed
    managed.save()
    threading.Thread(target=_monitor, args=(managed,), name="mon-" + pid_id, daemon=True).start()
    return managed


def _kill(managed: Managed) -> list[int]:
    killed: list[int] = []
    meta = managed.meta
    if meta.get("pid") and meta.get("created"):
        killed = procs.terminate_tree(meta["pid"], meta["created"])
    if managed.job:
        managed.job.terminate()
    return killed


def _finalize(managed: Managed, exit_code: int | None, state: str) -> None:
    with managed.lock:
        if managed.meta["state"] in TERMINAL:
            return
        reason = managed.stop_reason
        managed.meta.update(state=reason if reason in TERMINAL else state, exit_code=exit_code,
                            ended_at=iso(), stop_reason=reason)
        managed.save()
    if managed.job:
        if getattr(managed, "kill_orphans", True):
            managed.job.terminate()
        managed.job.close()
        managed.job = None
    audit("process.end", managed.meta["state"], process_id=managed.meta["id"], exit_code=exit_code)
    managed.done.set()


def _out_size(managed: Managed) -> int:
    total = 0
    for name in ("stdout.log", "stderr.log"):
        with contextlib.suppress(OSError):
            total += (managed.dir / name).stat().st_size
    return total


def _monitor(managed: Managed) -> None:
    meta = managed.meta
    cap = limit("max_output_bytes_per_stream") * 2
    deadline = time.monotonic() + (meta["timeout_s"] or limit("max_process_lifetime_s"))
    adopted = managed.popen is None
    seen: set[int] = set()
    while True:
        if adopted:
            alive = procs.is_alive(meta["pid"], meta["created"])
            if not alive:
                _finalize(managed, None, "exited_unknown")
                return
            time.sleep(0.5)
        else:
            try:
                code = managed.popen.wait(timeout=0.5)  # type: ignore[union-attr]
                _finalize(managed, code, "exited")
                return
            except subprocess.TimeoutExpired:
                pass
        reason = None
        if managed.cancel.is_set():
            reason = "stopped"
        elif time.monotonic() > deadline:
            reason = "timed_out"
        elif _out_size(managed) > cap:
            reason = "output_limit"
            meta["output_truncated"] = True
        if reason:
            managed.stop_reason = reason
            _kill(managed)
            if not adopted:
                with contextlib.suppress(subprocess.TimeoutExpired):
                    managed.popen.wait(timeout=5)  # type: ignore[union-attr]
                _finalize(managed, managed.popen.poll(), reason)  # type: ignore[union-attr]
            else:
                _finalize(managed, None, reason)
            return
        if managed.job:
            for p in managed.job.pids():
                if p not in seen and len(meta["children_seen"]) < 200:
                    seen.add(p)
                    if p != meta["pid"]:
                        meta["children_seen"].append(p)


def ensure_recovered() -> None:
    """Re-adopt or close out processes recorded by a previous server instance."""
    global _RECOVERED
    with _REG_LOCK:
        if _RECOVERED:
            return
        _RECOVERED = True
    base = state_subdir("procs")
    for directory in base.iterdir():
        if not directory.is_dir() or not valid_id(directory.name):
            continue
        meta = read_json(directory / "meta.json", None)
        if not isinstance(meta, dict) or meta.get("state") not in ("running", "starting"):
            continue
        managed = Managed(meta)
        managed.kill_orphans = False  # type: ignore[attr-defined]
        pid, created = meta.get("pid"), meta.get("created")
        if pid and created and procs.is_alive(pid, created) and (
                (procs.image_path(pid) or "").casefold() == str(meta.get("exe", "")).casefold()):
            meta["recovered"] = True
            with _REG_LOCK:
                _REGISTRY[meta["id"]] = managed
            managed.save()
            audit("process.recover", "ADOPTED", process_id=meta["id"], pid=pid)
            threading.Thread(target=_monitor, args=(managed,), daemon=True).start()
        else:
            meta.update(state="exited_unknown", ended_at=iso(), stop_reason="lost_across_restart")
            atomic_write_json(directory / "meta.json", meta)
            audit("process.recover", "LOST", process_id=meta["id"])


def get_managed(process_id: str) -> Managed:
    ensure_recovered()
    if not valid_id(process_id) or not process_id.startswith("prc-"):
        raise PolicyError("INVALID_PROCESS_ID")
    with _REG_LOCK:
        managed = _REGISTRY.get(process_id)
    if managed:
        return managed
    meta = read_json(state_subdir("procs") / process_id / "meta.json", None)
    if not isinstance(meta, dict):
        raise PolicyError("PROCESS_NOT_FOUND")
    return Managed(meta)  # historical, terminal


def wait_done(managed: Managed, timeout: float) -> bool:
    if managed.meta["state"] in TERMINAL:
        return True
    return managed.done.wait(timeout)


def stop_managed(managed: Managed, reason: str = "stopped") -> dict[str, Any]:
    meta = managed.meta
    if meta["owner"] != procs.current_user():
        raise PolicyError("PROCESS_OWNER_MISMATCH")
    if meta["state"] in TERMINAL:
        return {"id": meta["id"], "state": meta["state"], "already_ended": True}
    pid, created = meta["pid"], meta["created"]
    if not (pid and created and procs.is_alive(pid, created)):
        _finalize(managed, None, "exited_unknown")
        return {"id": meta["id"], "state": meta["state"], "already_ended": True}
    managed.stop_reason = reason
    managed.cancel.set()
    wait_done(managed, 10)
    if meta["state"] not in TERMINAL:
        _kill(managed)
        wait_done(managed, 5)
    audit("process.stop", meta["state"], process_id=meta["id"])
    return {"id": meta["id"], "state": meta["state"], "exit_code": meta["exit_code"]}


# ---------------------------------------------------------------- output
def read_output(managed: Managed, stream: str = "stdout", offset: int = 0, max_bytes: int = 16384) -> dict[str, Any]:
    if stream not in ("stdout", "stderr"):
        raise PolicyError("INVALID_STREAM")
    if type(offset) is not int or offset < 0:
        raise PolicyError("INVALID_OFFSET")
    cap = limit("max_page_bytes")
    max_bytes = max(1, min(int(max_bytes), cap))
    path = managed.dir / (stream + ".log")
    size = path.stat().st_size if path.exists() else 0
    if offset > size:
        raise PolicyError("OFFSET_BEYOND_END")
    with path.open("rb") as handle:
        handle.seek(offset)
        window = handle.read(max_bytes)
    if window and (window[0] & 0xC0) == 0x80:
        raise PolicyError("OFFSET_NOT_CHARACTER_ALIGNED")
    end = offset + len(window)
    if end < size:  # trim an incomplete trailing UTF-8 sequence
        cut = len(window)
        for back in range(1, min(4, len(window)) + 1):
            byte = window[-back]
            if byte & 0xC0 != 0x80:
                need = 4 if byte >= 0xF0 else 3 if byte >= 0xE0 else 2 if byte >= 0xC0 else 1
                if need > back:
                    cut = len(window) - back
                break
        if cut == 0 and window:
            raise PolicyError("PAGE_LIMIT_TOO_SMALL")
        window = window[:cut]
    text = redact_text(window.decode("utf-8", errors="replace"))
    next_offset = offset + len(window)
    finished = managed.meta["state"] in TERMINAL
    return {"id": managed.meta["id"], "stream": stream, "offset": offset, "next_offset": next_offset,
            "size": size, "text": text, "eof": finished and next_offset >= size,
            "state": managed.meta["state"], "output_truncated": bool(managed.meta.get("output_truncated"))}


def public_meta(meta: dict[str, Any]) -> dict[str, Any]:
    keys = ("id", "kind", "label", "state", "mode", "exe", "cwd", "summary", "owner", "started_at", "ended_at",
            "pid", "timeout_s", "exit_code", "stop_reason", "output_truncated", "children_seen", "recovered",
            "approval_id")
    return {k: meta.get(k) for k in keys}


# -------------------------------------------------------------- MCP tools
def process_list(name_contains: str = "", limit_rows: int = 200, only_managed: bool = False) -> dict[str, Any]:
    """List running Windows processes (pid, parent, name, threads) or only managed ones."""
    ensure_recovered()
    if only_managed:
        with _REG_LOCK:
            rows = [public_meta(m.meta) for m in _REGISTRY.values()]
        return {"managed": rows[-max(1, min(int(limit_rows), 500)):]}
    needle = str(name_contains).casefold()[:60]
    with _REG_LOCK:
        managed_pids = {m.meta["pid"]: m.meta["id"] for m in _REGISTRY.values() if m.meta["state"] == "running"}
    rows = [r for r in procs.snapshot() if needle in r["name"].casefold()]
    rows.sort(key=lambda r: (r["name"].casefold(), r["pid"]))
    out = []
    for row in rows[:max(1, min(int(limit_rows), 1000))]:
        row["managed_id"] = managed_pids.get(row["pid"])
        out.append(row)
    audit("process.list", "OK", count=len(out))
    return {"count": len(rows), "returned": len(out), "processes": out}


def process_inspect(pid: int) -> dict[str, Any]:
    """Inspect one process by PID: identity (creation time), image path, parent, children."""
    if type(pid) is not int or pid <= 0:
        raise PolicyError("INVALID_PID")
    rows = {r["pid"]: r for r in procs.snapshot()}
    row = rows.get(pid)
    if not row:
        return {"pid": pid, "exists": False}
    created = procs.creation_time(pid)
    managed_id = None
    with _REG_LOCK:
        for m in _REGISTRY.values():
            if m.meta["pid"] == pid and m.meta["created"] == created and m.meta["state"] == "running":
                managed_id = m.meta["id"]
    kids = [r["pid"] for r in rows.values() if r["ppid"] == pid][:100]
    return {"pid": pid, "exists": True, "name": row["name"], "ppid": row["ppid"], "threads": row["threads"],
            "created_filetime": created, "image_path": procs.image_path(pid), "child_pids": kids,
            "managed_id": managed_id, "identity_note": "use (pid, created_filetime) as identity; pid alone is reusable"}


def process_start(executable: str, args: list[str] | None = None, cwd: str = "", timeout_s: int = 3600,
                  mode: str = WORKSPACE_WRITE, env: dict[str, str] | None = None, label: str = "",
                  approval_id: str | None = None) -> dict[str, Any]:
    """Start a long-running managed process (argument vector, no shell, bounded output)."""
    args = list(args or [])
    if len(args) > 100 or any(not isinstance(a, str) or "\x00" in a or len(a) > 8192 for a in args):
        raise PolicyError("INVALID_ARGUMENTS")
    environment = build_env(env)
    exe_path = resolve_exe(executable, environment)
    workdir = safe_path(cwd or os.environ.get("PDC_DEFAULT_CWD", "D:\\Temp"))
    if not workdir.is_dir():
        raise PolicyError("CWD_NOT_A_DIRECTORY")
    if exe_path.name.casefold() == "git.exe":
        args = guard_git_args(args)
    timeout = max(1, min(int(timeout_s), limit("max_process_lifetime_s")))
    if mode == READ_ONLY:
        raise PolicyError("PROCESS_START_REQUIRES_WORKSPACE_OR_ELEVATED_MODE")
    params = {"exe": str(exe_path), "args": args, "cwd": str(workdir), "env": sorted((env or {}).keys()),
              "timeout_s": timeout}
    pending = authorize_launch(mode, exe_path, environment, params, approval_id)
    if pending:
        return pending
    managed = launch(kind="process", label=label or exe_path.name, argv=args, cmdline=None, exe_path=exe_path,
                     cwd=workdir, env=environment, timeout_s=timeout, mode=mode, approval_id=approval_id,
                     summary=params, kill_orphans=False)
    return {"status": "STARTED", **public_meta(managed.meta)}


def guard_git_args(args: list[str]) -> list[str]:
    """Defence in depth for git: no -c/--exec-path before the subcommand, no force/delete pushes."""
    lowered = [a.casefold() for a in args]
    if lowered and lowered[0].startswith("-"):
        raise PolicyError("GIT_GLOBAL_OPTIONS_NOT_ALLOWED")
    if lowered[:1] == ["push"] and any(a in ("-f", "--force", "--delete", "-d", "--mirror") or
                                       a.startswith("--force") or a.startswith("+") for a in lowered[1:]):
        raise PolicyError("GIT_FORCE_PUSH_NOT_ALLOWED")
    if lowered[:1] in (["config"], ["credential"]):
        raise PolicyError("GIT_SUBCOMMAND_NOT_ALLOWED")
    return ["-c", "core.fsmonitor=false", *args]


def process_status(process_id: str) -> dict[str, Any]:
    """Status of a managed process, with identity re-verification of the live PID."""
    managed = get_managed(process_id)
    meta = managed.meta
    live = bool(meta["state"] == "running" and meta["pid"] and procs.is_alive(meta["pid"], meta["created"]))
    out = public_meta(meta)
    out["alive_verified"] = live
    out["output_bytes"] = {s: (managed.dir / (s + ".log")).stat().st_size
                           if (managed.dir / (s + ".log")).exists() else 0 for s in ("stdout", "stderr")}
    return out


def process_output(process_id: str, stream: str = "stdout", offset: int = 0, max_bytes: int = 16384) -> dict[str, Any]:
    """Read a bounded UTF-8 page of a managed process's output; cursors are byte offsets."""
    return read_output(get_managed(process_id), stream, offset, max_bytes)


def process_stop(process_id: str) -> dict[str, Any]:
    """Stop a MANAGED process tree (identity verified). Unrelated processes are refused."""
    managed = get_managed(process_id)
    return stop_managed(managed)


def register_process_tools(server: Any) -> None:
    server.tool(annotations=_RO)(process_list)
    server.tool(annotations=_RO)(process_inspect)
    server.tool(annotations=_WRITE)(process_start)
    server.tool(annotations=_RO)(process_status)
    server.tool(annotations=_RO)(process_output)
    server.tool(annotations=_STOP)(process_stop)
