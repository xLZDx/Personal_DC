"""Managed Windows processes: launch, identity-verified control, durable metadata.

Every launched process is recorded under ``<state>/procs/<id>/`` (meta.json, stdout.log, stderr.log).
Output goes to files, not pipes, so it survives an MCP server restart; a monitor thread enforces
timeout, output cap and cancellation. After a restart ``ensure_recovered()`` re-adopts live processes by
``(pid, creation time, image)`` identity and marks the rest ``exited_unknown``.

Only processes launched through this module can be stopped (``process_*`` tools: kind ``process``;
``command_*`` tools: kind ``command``). There is no ``taskkill``; termination is per-PID with
creation-time verification and the result is verified before a terminal state is reported.
"""
from __future__ import annotations

import contextlib
import ctypes
import locale
import os
import re
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp.types import ToolAnnotations
from personal_dc.policy import PolicyError

from . import procs
from .common import (ELEVATED, READ_ONLY, WORKSPACE_WRITE, approval_or_response, atomic_write_json, audit,
                     iso, limit, native_config, new_id, read_json, redact, redact_text, safe_path,
                     sha256_text, state_subdir, threaded, valid_id)

_RO = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
_WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False)
_STOP = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=False)

TERMINAL = {"exited", "exited_unknown", "stopped", "timed_out", "output_limit", "failed_to_start"}
# Caller-supplied environment variables are an ALLOWLIST of harmless shapes: names that can redirect
# code loading, credentials, proxies, package registries or git behaviour are refused.
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,40}$")
_ENV_BLOCK_PREFIXES = ("PDC_", "GIT_", "PYTHON", "NODE_", "NPM_", "PIP_", "DOTNET_", "COR_", "CORECLR_",
                       "PSMODULE", "HTTP", "HTTPS", "ALL_PROXY", "NO_PROXY", "SSL_", "CURL_", "REQUESTS_",
                       "LD_", "DYLD_", "JAVA", "_JAVA", "MSBUILD", "NUGET", "__COMPAT", "COMSPEC", "PATH",
                       "SYSTEMROOT", "WINDIR", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP",
                       "PROGRAM", "ONECS", "ONEC")
_ENV_BLOCK_MARKERS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "PROXY", "REGISTRY", "INDEX")
_REGISTRY: dict[str, "Managed"] = {}
_REG_LOCK = threading.RLock()
_RECOVERY_LOCK = threading.RLock()
_RECOVERED = False
_RESERVED = 0   # launch slots reserved but not yet registered


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
        self.kill_orphans = True

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
    env["NoDefaultCurrentDirectoryInExePath"] = "1"
    for name, value in (extra or {}).items():
        if (not isinstance(name, str) or not isinstance(value, str) or len(value) > 2048
                or not _ENV_NAME.fullmatch(name) or name.startswith(_ENV_BLOCK_PREFIXES)
                or any(m in name for m in _ENV_BLOCK_MARKERS)):
            raise PolicyError("ENV_VAR_NOT_ALLOWED:" + str(name)[:40])
        env[name] = value
    return env


def env_fingerprint(extra: dict[str, str] | None) -> str:
    """Hash of caller env names AND values, bound into approval digests."""
    return sha256_text("\x00".join(f"{k}={v}" for k, v in sorted((extra or {}).items())))


def trusted_dirs(env: dict[str, str]) -> list[Path]:
    return [Path(p).resolve(strict=False) for p in env["PATH"].split(";") if p]


def system32() -> Path:
    return Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"


def resolve_exe(exe: str, env: dict[str, str]) -> Path:
    """Resolve to an absolute file. Bare names resolve ONLY in the sanitized PATH directories."""
    if not isinstance(exe, str) or not exe or "\x00" in exe or exe.startswith("\\\\") or exe.startswith("//"):
        raise PolicyError("INVALID_EXECUTABLE")
    if any(ch in exe for ch in "\\/:"):
        path = Path(exe)
        if not path.is_absolute():
            raise PolicyError("RELATIVE_EXECUTABLE_NOT_ALLOWED")
        found: Path | None = path if path.is_file() else None
    else:
        found = None
        names = [exe] if Path(exe).suffix else [exe + ext for ext in env.get("PATHEXT", ".EXE").split(";") if ext]
        for directory in trusted_dirs(env):          # explicit search: never the current directory
            for name in names:
                candidate = directory / name
                if candidate.is_file():
                    found = candidate
                    break
            if found:
                break
    if not found:
        raise PolicyError("EXECUTABLE_NOT_FOUND:" + exe[:60])
    return found.resolve(strict=True)


def _git_subcommand(args: list[str]) -> str:
    for arg in args:
        if not arg.startswith("-"):
            return arg.casefold()
    return ""


def guard_git_args(args: list[str]) -> tuple[list[str], bool]:
    """Return (hardened args, auto_trusted).

    Hooks, fsmonitor and external helper protocols are disabled for every git call. Only a small set
    of local, non-network subcommands is auto-trusted; push/fetch/pull/clone/rebase/config/... always
    require an approval, and any option that names a program to run is refused outright.
    """
    if not args:
        raise PolicyError("GIT_SUBCOMMAND_REQUIRED")
    if args[0].startswith("-"):
        raise PolicyError("GIT_GLOBAL_OPTIONS_NOT_ALLOWED")
    lowered = [a.casefold() for a in args]
    if any(a.startswith(("--upload-pack", "--receive-pack", "--exec", "--extcmd", "--ext-diff", "--textconv",
                         "--git-dir", "--work-tree", "--exec-path", "--config-env")) or a == "-x" or a == "-c"
           for a in lowered):
        raise PolicyError("GIT_PROGRAM_OPTION_NOT_ALLOWED")
    sub = lowered[0]
    if sub == "push" and any(a in ("-f", "--force", "--delete", "-d", "--mirror", "--prune") or a.startswith("--force")
                             or a.startswith("+") or a.startswith(":") or (a.startswith("-") and not a.startswith("--") and "f" in a)
                             for a in lowered[1:]):
        raise PolicyError("GIT_FORCE_OR_DELETE_PUSH_NOT_ALLOWED")
    if sub in ("config", "credential", "filter-branch", "daemon", "http-backend"):
        raise PolicyError("GIT_SUBCOMMAND_NOT_ALLOWED")
    free = set(native_config()["git_free_subcommands"])
    hardened = ["-c", "core.fsmonitor=false", "-c", "core.hooksPath=NUL", "-c", "protocol.ext.allow=never",
                "-c", "core.sshCommand=ssh", *args]
    return hardened, sub in free


def is_trusted_dev_tool(exe_path: Path, env: dict[str, str]) -> bool:
    names = {n.casefold() for n in native_config()["dev_executables"]}
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
        return sum(1 for m in _REGISTRY.values() if m.meta["state"] in ("running", "starting")) + _RESERVED


def _reserve_slot() -> None:
    global _RESERVED
    with _REG_LOCK:
        if _live_count() >= limit("max_managed_processes"):
            raise PolicyError("TOO_MANY_MANAGED_PROCESSES")
        _RESERVED += 1


def _release_slot() -> None:
    global _RESERVED
    with _REG_LOCK:
        _RESERVED = max(0, _RESERVED - 1)


def _audit_quiet(*args: Any, **kwargs: Any) -> None:
    """Audit that must never break lifecycle bookkeeping (process state must still become terminal)."""
    with contextlib.suppress(Exception):
        audit(*args, **kwargs)


def launch(*, kind: str, label: str, argv: list[str] | None, cmdline: str | None, exe_path: Path,
           cwd: Path, env: dict[str, str], timeout_s: int, mode: str, approval_id: str | None,
           summary: dict[str, Any], kill_orphans: bool, memory_limit_mb: int | None = None) -> Managed:
    ensure_recovered()
    _reserve_slot()
    try:
        return _launch(kind=kind, label=label, argv=argv, cmdline=cmdline, exe_path=exe_path, cwd=cwd, env=env,
                       timeout_s=timeout_s, mode=mode, approval_id=approval_id, summary=summary,
                       kill_orphans=kill_orphans, memory_limit_mb=memory_limit_mb)
    finally:
        _release_slot()


def _launch(*, kind: str, label: str, argv: list[str] | None, cmdline: str | None, exe_path: Path,
            cwd: Path, env: dict[str, str], timeout_s: int, mode: str, approval_id: str | None,
            summary: dict[str, Any], kill_orphans: bool, memory_limit_mb: int | None) -> Managed:
    pid_id = new_id("prc")
    directory = state_subdir("procs") / pid_id
    directory.mkdir(parents=True)
    meta: dict[str, Any] = {
        "id": pid_id, "kind": kind, "label": label[:80], "state": "starting", "mode": mode,
        "exe": str(exe_path), "summary": redact(summary), "cwd": str(cwd), "owner": procs.current_user(),
        "approval_id": approval_id, "started_at": iso(), "ended_at": None, "pid": None, "created": None,
        "timeout_s": timeout_s, "exit_code": None, "stop_reason": None, "output_truncated": False,
        "children_seen": [], "recovered": False, "job_assigned": False, "kill_verified": None,
    }
    atomic_write_json(directory / "meta.json", meta)          # durable BEFORE anything can run
    audit("process.start", "START", process_id=pid_id, kind=kind, exe=str(exe_path), cwd=str(cwd), mode=mode,
          summary=summary, approval_id=approval_id)
    out = (directory / "stdout.log").open("xb")
    err = (directory / "stderr.log").open("xb")
    job = None
    popen = None
    try:
        job = procs.Job(memory_limit_bytes=(memory_limit_mb or 0) * 1024 * 1024 or None,
                        max_active=64 if kill_orphans else None, kill_on_close=kill_orphans)
        flags = (subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP | procs.CREATE_SUSPENDED)
        args: Any = cmdline if cmdline is not None else [str(exe_path), *(argv or [])]
        popen = subprocess.Popen(args, cwd=str(cwd), env=env, stdin=subprocess.DEVNULL, stdout=out,
                                 stderr=err, shell=False, creationflags=flags)
        handle = int(popen._handle)  # type: ignore[attr-defined]
        created = procs.creation_time(popen.pid)
        if not created:
            raise PolicyError("PROCESS_IDENTITY_UNAVAILABLE")
        meta.update(pid=popen.pid, created=created)
        atomic_write_json(directory / "meta.json", meta)      # identity persisted while still suspended
        if not job.assign(handle):
            # Without the job we cannot guarantee tree containment: refuse rather than run uncontained.
            raise PolicyError("JOB_ASSIGNMENT_FAILED")
        meta["job_assigned"] = True
        procs.resume_process(handle)
        meta["state"] = "running"
        managed = Managed(meta, popen, job)
        managed.kill_orphans = kill_orphans
        with _REG_LOCK:
            _REGISTRY[pid_id] = managed
        managed.save()
        threading.Thread(target=_monitor, args=(managed,), name="mon-" + pid_id, daemon=True).start()
        return managed
    except BaseException as exc:
        if popen is not None:
            with contextlib.suppress(Exception):
                popen.kill()
                popen.wait(timeout=5)
        if job is not None:
            with contextlib.suppress(Exception):
                job.terminate()
                job.close()
        meta.update(state="failed_to_start", ended_at=iso(), stop_reason=type(exc).__name__)
        with contextlib.suppress(Exception):
            atomic_write_json(directory / "meta.json", meta)
        _audit_quiet("process.start", "ERROR", process_id=pid_id, reason=type(exc).__name__)
        if isinstance(exc, PolicyError):
            raise
        winerror = getattr(exc, "winerror", None)
        raise PolicyError("PROCESS_START_FAILED:" + type(exc).__name__ + (f":{winerror}" if winerror else "")) from exc
    finally:
        out.close()
        err.close()


def _verify_dead(meta: dict[str, Any], timeout: float = 5.0) -> bool:
    pid, created = meta.get("pid"), meta.get("created")
    if not (pid and created):
        return True
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not procs.is_alive(pid, created):
            return True
        time.sleep(0.1)
    return not procs.is_alive(pid, created)


def _kill(managed: Managed) -> list[int]:
    killed: list[int] = []
    meta = managed.meta
    job = managed.job
    with contextlib.suppress(Exception):
        if meta.get("pid") and meta.get("created"):
            killed = procs.terminate_tree(meta["pid"], meta["created"])
    if job is not None:
        with contextlib.suppress(Exception):
            job.terminate()
    meta["kill_verified"] = _verify_dead(meta)
    return killed


def _finalize(managed: Managed, exit_code: int | None, state: str) -> None:
    try:
        with managed.lock:
            if managed.meta["state"] in TERMINAL:
                return
            reason = managed.stop_reason
            managed.meta.update(state=reason if reason in TERMINAL else state, exit_code=exit_code,
                                ended_at=iso(), stop_reason=reason)
            with contextlib.suppress(Exception):
                managed.save()
        job, managed.job = managed.job, None
        if job is not None:
            with contextlib.suppress(Exception):
                if managed.kill_orphans:
                    job.terminate()
                job.close()
        _audit_quiet("process.end", managed.meta["state"], process_id=managed.meta["id"], exit_code=exit_code,
                     kill_verified=managed.meta.get("kill_verified"))
    finally:
        managed.done.set()


def _out_size(managed: Managed) -> int:
    total = 0
    for name in ("stdout.log", "stderr.log"):
        with contextlib.suppress(OSError):
            total += (managed.dir / name).stat().st_size
    return total


def _deadline_for(meta: dict[str, Any]) -> float:
    """Monotonic deadline anchored to ``started_at`` so adoption never extends a timeout."""
    budget = meta["timeout_s"] or limit("max_process_lifetime_s")
    try:
        started = datetime.fromisoformat(meta["started_at"])
        elapsed = (datetime.now(timezone.utc) - started).total_seconds()
    except (ValueError, TypeError, KeyError):
        elapsed = 0.0
    return time.monotonic() + max(0.0, budget - elapsed)


def _monitor(managed: Managed) -> None:
    try:
        _monitor_loop(managed)
    except BaseException as exc:  # a dead monitor must never leave an unenforced process behind
        _audit_quiet("process.monitor", "CRASHED", process_id=managed.meta["id"], reason=type(exc).__name__)
        managed.stop_reason = "stopped"
        with contextlib.suppress(Exception):
            _kill(managed)
        _finalize(managed, None, "exited_unknown")


def _monitor_loop(managed: Managed) -> None:
    meta = managed.meta
    cap = limit("max_output_bytes_per_stream") * 2
    deadline = _deadline_for(meta)
    adopted = managed.popen is None
    seen: set[int] = set()
    while True:
        if adopted:
            if not procs.is_alive(meta["pid"], meta["created"]):
                _finalize(managed, None, "exited_unknown")
                return
            time.sleep(0.25)
        else:
            try:
                code = managed.popen.wait(timeout=0.25)  # type: ignore[union-attr]
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
            code = None
            if not adopted:
                with contextlib.suppress(subprocess.TimeoutExpired):
                    managed.popen.wait(timeout=5)  # type: ignore[union-attr]
                code = managed.popen.poll()  # type: ignore[union-attr]
            _finalize(managed, code, reason)
            return
        job = managed.job
        if job is not None:
            for p in job.pids():
                if p not in seen and len(meta["children_seen"]) < 200:
                    seen.add(p)
                    if p != meta["pid"]:
                        meta["children_seen"].append(p)


def _prune_old() -> None:
    cutoff = time.time() - limit("process_retention_days") * 86400
    for directory in state_subdir("procs").iterdir():
        with contextlib.suppress(OSError, PolicyError):
            meta = directory / "meta.json"
            if directory.is_dir() and meta.is_file() and meta.stat().st_mtime < cutoff:
                data = read_json(meta, {})
                if data.get("state") in TERMINAL:
                    shutil.rmtree(directory, ignore_errors=True)


def ensure_recovered() -> None:
    """Re-adopt or close out processes recorded by a previous server instance (once, under a lock)."""
    global _RECOVERED
    with _RECOVERY_LOCK:
        if _RECOVERED:
            return
        _prune_old()
        for directory in state_subdir("procs").iterdir():
            if not directory.is_dir() or not valid_id(directory.name):
                continue
            try:
                meta = read_json(directory / "meta.json", None)
                if not isinstance(meta, dict) or meta.get("state") not in ("running", "starting"):
                    continue
                managed = Managed(meta)
                managed.kill_orphans = False
                pid, created = meta.get("pid"), meta.get("created")
                if meta.get("state") == "running" and pid and created and procs.is_alive(pid, created) and (
                        (procs.image_path(pid) or "").casefold() == str(meta.get("exe", "")).casefold()):
                    meta["recovered"] = True
                    with _REG_LOCK:
                        _REGISTRY[meta["id"]] = managed
                    managed.save()
                    _audit_quiet("process.recover", "ADOPTED", process_id=meta["id"], pid=pid)
                    threading.Thread(target=_monitor, args=(managed,), daemon=True).start()
                else:
                    if pid and created and procs.is_alive(pid, created) and meta.get("state") == "starting":
                        procs.terminate_tree(pid, created)   # crashed mid-launch: never leave it uncontained
                    meta.update(state="exited_unknown", ended_at=iso(), stop_reason="lost_across_restart")
                    atomic_write_json(directory / "meta.json", meta)
                    _audit_quiet("process.recover", "LOST", process_id=meta["id"])
            except Exception as exc:   # one damaged record must not block recovery of the others
                _audit_quiet("process.recover", "SKIPPED_CORRUPT", directory=directory.name, reason=type(exc).__name__)
        _RECOVERED = True


def get_managed(process_id: str, kind: str | None = None) -> Managed:
    ensure_recovered()
    if not valid_id(process_id) or not process_id.startswith("prc-"):
        raise PolicyError("INVALID_PROCESS_ID")
    with _REG_LOCK:
        managed = _REGISTRY.get(process_id)
    if managed is None:
        meta = read_json(state_subdir("procs") / process_id / "meta.json", None)
        if not isinstance(meta, dict):
            raise PolicyError("PROCESS_NOT_FOUND")
        managed = Managed(meta)   # historical record, terminal
    if kind and managed.meta.get("kind") != kind:
        raise PolicyError("WRONG_PROCESS_KIND:" + str(managed.meta.get("kind")))
    return managed


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
        code = managed.popen.poll() if managed.popen is not None else None
        _finalize(managed, code, "exited" if code is not None else "exited_unknown")
        return {"id": meta["id"], "state": meta["state"], "already_ended": True}
    managed.stop_reason = reason
    managed.cancel.set()
    wait_done(managed, 10)
    if meta["state"] not in TERMINAL:
        _kill(managed)
        wait_done(managed, 5)
    audit("process.stop", meta["state"], process_id=meta["id"], kill_verified=meta.get("kill_verified"))
    return {"id": meta["id"], "state": meta["state"], "exit_code": meta["exit_code"],
            "kill_verified": meta.get("kill_verified")}


# ---------------------------------------------------------------- output
def _decode(window: bytes) -> str:
    try:
        return window.decode("utf-8")
    except UnicodeDecodeError:
        # Native Windows tools redirected to a file write the OEM code page; fall back to it.
        for codec in (f"cp{ctypes.windll.kernel32.GetOEMCP()}", locale.getpreferredencoding(False)):
            with contextlib.suppress(LookupError, UnicodeDecodeError):
                return window.decode(codec)
        return window.decode("utf-8", errors="replace")


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
    end = offset + len(window)
    # Page boundaries only matter for UTF-8; pure-OEM output never contains valid multi-byte sequences,
    # so the alignment guard below is applied exactly when the data is valid UTF-8.
    if window and (window[0] & 0xC0) == 0x80 and _is_utf8_stream(path, size):
        raise PolicyError("OFFSET_NOT_CHARACTER_ALIGNED")
    if end < size and _is_utf8_stream(path, size):  # trim an incomplete trailing UTF-8 sequence
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
    text = redact_text(_decode(window))
    next_offset = offset + len(window)
    finished = managed.meta["state"] in TERMINAL
    return {"id": managed.meta["id"], "stream": stream, "offset": offset, "next_offset": next_offset,
            "size": size, "text": text, "eof": finished and next_offset >= size,
            "state": managed.meta["state"], "output_truncated": bool(managed.meta.get("output_truncated"))}


_UTF8_CACHE: dict[tuple[str, int], bool] = {}


def _is_utf8_stream(path: Path, size: int) -> bool:
    """True when the first 64 KiB decode as UTF-8 (ignoring a cut at the window end)."""
    key = (str(path), min(size, 65536))
    if key in _UTF8_CACHE:
        return _UTF8_CACHE[key]
    with path.open("rb") as handle:
        head = handle.read(65536)
    try:
        head.decode("utf-8")
        ok = True
    except UnicodeDecodeError as exc:
        ok = exc.start >= len(head) - 3 and size > len(head)
    if len(_UTF8_CACHE) > 256:
        _UTF8_CACHE.clear()
    _UTF8_CACHE[key] = ok
    return ok


def public_meta(meta: dict[str, Any]) -> dict[str, Any]:
    keys = ("id", "kind", "label", "state", "mode", "exe", "cwd", "summary", "owner", "started_at", "ended_at",
            "pid", "timeout_s", "exit_code", "stop_reason", "output_truncated", "children_seen", "recovered",
            "approval_id", "job_assigned", "kill_verified")
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


def launch_params(exe_path: Path, args: list[str], cwd: Path, timeout: int, env: dict[str, str] | None,
                  mode: str) -> dict[str, Any]:
    """The exact parameters an approval is bound to (resolved path, env values via fingerprint, cwd, mode)."""
    return {"exe": str(exe_path), "args": args, "cwd": str(cwd), "env_sha256": env_fingerprint(env),
            "env_names": sorted((env or {}).keys()), "timeout_s": timeout, "mode": mode}


def process_start(executable: str, args: list[str] | None = None, cwd: str = "", timeout_s: int = 3600,
                  mode: str = WORKSPACE_WRITE, env: dict[str, str] | None = None, label: str = "",
                  approval_id: str | None = None) -> dict[str, Any]:
    """Start a long-running managed process (argument vector, no shell, bounded output).

    Only git (local subcommands) runs without approval; every other executable needs an operator approval.
    """
    args = list(args or [])
    if len(args) > 100 or any(not isinstance(a, str) or "\x00" in a or len(a) > 8192 for a in args):
        raise PolicyError("INVALID_ARGUMENTS")
    if mode == READ_ONLY:
        raise PolicyError("PROCESS_START_REQUIRES_WORKSPACE_OR_ELEVATED_MODE")
    environment = build_env(env)
    exe_path = resolve_exe(executable, environment)
    workdir = safe_path(cwd or "D:\\Temp")
    if not workdir.is_dir():
        raise PolicyError("CWD_NOT_A_DIRECTORY")
    free = True
    if exe_path.name.casefold() == "git.exe":
        args, free = guard_git_args(args)
    timeout = max(1, min(int(timeout_s), limit("max_process_lifetime_s")))
    params = launch_params(exe_path, args, workdir, timeout, env, mode)
    pending = authorize_launch(mode, exe_path, environment, params, approval_id, force_approval=not free)
    if pending:
        return pending
    managed = launch(kind="process", label=label or exe_path.name, argv=args, cmdline=None, exe_path=exe_path,
                     cwd=workdir, env=environment, timeout_s=timeout, mode=mode, approval_id=approval_id,
                     summary=params, kill_orphans=False)
    return {"status": "STARTED", **public_meta(managed.meta)}


def process_status(process_id: str) -> dict[str, Any]:
    """Status of a managed process, with identity re-verification of the live PID."""
    managed = get_managed(process_id, "process")
    meta = managed.meta
    live = bool(meta["state"] == "running" and meta["pid"] and procs.is_alive(meta["pid"], meta["created"]))
    out = public_meta(meta)
    out["alive_verified"] = live
    out["output_bytes"] = {s: (managed.dir / (s + ".log")).stat().st_size
                           if (managed.dir / (s + ".log")).exists() else 0 for s in ("stdout", "stderr")}
    return out


def process_output(process_id: str, stream: str = "stdout", offset: int = 0, max_bytes: int = 16384) -> dict[str, Any]:
    """Read a bounded page of a managed process's output; cursors are byte offsets."""
    return read_output(get_managed(process_id, "process"), stream, offset, max_bytes)


def process_stop(process_id: str) -> dict[str, Any]:
    """Stop a MANAGED process tree (identity verified, result verified). Unrelated processes are refused."""
    return stop_managed(get_managed(process_id, "process"))


def register_process_tools(server: Any) -> None:
    server.tool(annotations=_RO)(threaded(process_list))
    server.tool(annotations=_RO)(threaded(process_inspect))
    server.tool(annotations=_WRITE)(threaded(process_start))
    server.tool(annotations=_RO)(threaded(process_status))
    server.tool(annotations=_RO)(threaded(process_output))
    server.tool(annotations=_STOP)(threaded(process_stop))
