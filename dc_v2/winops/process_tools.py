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
from .deletion_policy import deny_deletion_argv
from .git_policy import config_risk_from_listing, git_is_free, trusted_config_origins
from .common import (ELEVATED, READ_ONLY, WORKSPACE_WRITE, approval_or_response, atomic_write_json, audit,
                     is_reparse, iso, limit, native_config, new_id, read_json, redact, redact_text, safe_path,
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


def git_config_risk(cwd: Path) -> str | None:
    """Ask git itself for the effective configuration of ``cwd`` (any scope, nested dir, worktree, gitfile, includes).

    Returns the first program-launching key, or a ``GIT_CONFIG_*`` marker when the question cannot be answered.
    ``git config --list`` runs no configured program.
    """
    env = build_env(None)
    try:
        exe = resolve_exe("git.exe", env)
        done = subprocess.run([str(exe), "config", "--list", "--show-scope", "--show-origin"], cwd=str(cwd), env=env,
                              stdin=subprocess.DEVNULL, capture_output=True, timeout=10, check=False,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.SubprocessError, PolicyError):
        return "GIT_CONFIG_UNAVAILABLE"
    if done.returncode != 0:
        return "GIT_CONFIG_UNREADABLE"
    risky = config_risk_from_listing(done.stdout.decode("utf-8", errors="replace"), trusted_config_origins(env, exe))
    return risky or _git_containment_risk(exe, cwd, env)


def _git_containment_risk(exe: Path, cwd: Path, env: dict[str, str]) -> str | None:
    """Free git may only touch a work tree and git dir that lie inside the allowed roots (core.worktree, gitfile
    redirects and similar can point elsewhere). Uncertain containment fails closed."""
    try:
        done = subprocess.run([str(exe), "rev-parse", "--show-toplevel", "--absolute-git-dir"], cwd=str(cwd), env=env,
                              stdin=subprocess.DEVNULL, capture_output=True, timeout=10, check=False,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        lines = done.stdout.decode("utf-8", errors="replace").splitlines()
        if done.returncode != 0 or len(lines) != 2:
            return "GIT_CONTAINMENT_UNKNOWN"
        toplevel = safe_path(lines[0].strip())    # raises when outside the allowed roots / protected locations
        gitdir = Path(lines[1].strip())
        if os.path.normcase(os.path.normpath(str(gitdir))) != os.path.normcase(os.path.normpath(str(toplevel / ".git"))):
            return "GIT_DIR_NOT_INSIDE_WORKTREE"   # separate git dirs / linked worktrees: not provably contained
        if is_reparse(gitdir):
            return "GIT_OBJECT_DATABASE_REDIRECTED"
        budget = [MAX_REPARSE_SCAN_ENTRIES]
        # every entry under the git dir (loose objects, packs, indexes, refs, config...) must be a real file/directory
        return (_tree_reparse_risk(gitdir, budget, skip_git=False) or _alternates_risk(gitdir / "objects", 0, budget)
                or _tree_reparse_risk(toplevel, budget, skip_git=True))
    except (OSError, subprocess.SubprocessError, PolicyError):
        return "GIT_WORKTREE_OUTSIDE_ALLOWED_ROOTS"


MAX_REPARSE_SCAN_ENTRIES = 200000


def _tree_reparse_risk(root: Path, budget: list[int], *, skip_git: bool) -> str | None:
    """Symlinks/junctions/mount points anywhere in a tree let git read or stage data from another location: a
    redirected object file or directory, a work-tree junction. ``budget`` is shared by the whole check; a tree too large
    to verify is not provably contained, so free git is refused."""
    stack = [root]
    while stack:
        current = stack.pop()
        with os.scandir(current) as entries:
            for entry in entries:
                if skip_git and entry.name.casefold() == ".git":
                    if current != root:                  # a nested repository/submodule: its git dir is unvalidated
                        return "GIT_NESTED_REPOSITORY"   # (a .git FILE can point anywhere); only the outer .git is skipped
                    continue
                budget[0] -= 1
                if budget[0] < 0:
                    return "GIT_TREE_TOO_LARGE_TO_VERIFY"
                if entry.is_symlink() or entry.is_junction() or is_reparse(Path(entry.path)):
                    return "GIT_TREE_CONTAINS_REPARSE_POINT"
                if entry.is_dir(follow_symlinks=False):
                    stack.append(Path(entry.path))
    return None


def _alternates_risk(objects: Path, depth: int, budget: list[int]) -> str | None:
    """Every effective object store (``objects/info/alternates``, recursively) must be a ``<root>/.git/objects`` whose
    ``<root>`` is inside the allowed roots; anything else (outside, odd layout, http-alternates, too deep, unreadable)
    disables approval-free git, because git reads objects from alternates as if they were local."""
    if depth > 4:
        return "GIT_ALTERNATES_TOO_DEEP"
    info = objects / "info"
    if (info / "http-alternates").exists():
        return "GIT_HTTP_ALTERNATES"
    path = info / "alternates"
    if not path.exists():
        return None
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "GIT_ALTERNATES_UNREADABLE"
    for raw in lines:
        line = raw.strip().strip('"')
        if not line or line.startswith("#"):
            continue
        store = Path(line) if os.path.isabs(line) else objects / line
        store = Path(os.path.normpath(str(store)))
        if store.name.casefold() != "objects" or store.parent.name.casefold() != ".git":
            return "GIT_ALTERNATE_OUTSIDE_ALLOWED_ROOTS"
        if is_reparse(store.parent) or is_reparse(store) or _tree_reparse_risk(store, budget, skip_git=False):
            return "GIT_OBJECT_DATABASE_REDIRECTED"
        try:
            safe_path(str(store.parent.parent))
        except PolicyError:
            return "GIT_ALTERNATE_OUTSIDE_ALLOWED_ROOTS"
        nested = _alternates_risk(store, depth + 1, budget)
        if nested:
            return nested
    return None


def guard_git_args(args: list[str], cwd: Path | None = None) -> tuple[list[str], bool]:
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
    for a in lowered[1:]:
        if a == "--":
            break
        if a.startswith("--"):
            opt = a[2:].split("=", 1)[0]
            # git accepts unambiguous abbreviations of long options: block every spelling of the ones below.
            if (len(opt) >= 2 and "output".startswith(opt)) or opt.startswith("output")                     or (len(opt) >= 4 and "no-index".startswith(opt)) or opt.startswith("open-files-in-pager")                     or (len(opt) >= 3 and "open-files-in-pager".startswith(opt)):
                raise PolicyError("GIT_OUTPUT_OR_NOINDEX_OPTION_NOT_ALLOWED")
        elif a.startswith("-") and len(a) > 1 and (a[1] in "oO" or "o" in a[1:2]):
            raise PolicyError("GIT_OUTPUT_OR_NOINDEX_OPTION_NOT_ALLOWED")
    sub = lowered[0]
    if sub == "push" and any(a in ("-f", "--force", "--delete", "-d", "--mirror", "--prune") or a.startswith("--force")
                             or a.startswith("+") or a.startswith(":") or (a.startswith("-") and not a.startswith("--") and "f" in a)
                             for a in lowered[1:]):
        raise PolicyError("GIT_FORCE_OR_DELETE_PUSH_NOT_ALLOWED")
    if sub in ("config", "credential", "filter-branch", "daemon", "http-backend"):
        raise PolicyError("GIT_SUBCOMMAND_NOT_ALLOWED")
    cfg = native_config()
    free = set(cfg["git_free_subcommands"]) if cfg.get("git_auto_trust") else set()
    trusted, _why = git_is_free(sub, list(args[1:]), cwd, free, git_config_risk)
    rest = list(args)
    if sub in ("diff", "log", "show"):       # never run an external diff driver / textconv from repository config
        rest = [args[0], "--no-ext-diff", "--no-textconv", *args[1:]]
    hardened = ["-c", "core.fsmonitor=false", "-c", "core.hooksPath=NUL", "-c", "protocol.ext.allow=never",
                "-c", "core.sshCommand=ssh", "-c", "core.pager=cat", "-c", "core.editor=false",
                "-c", "sequence.editor=false", *rest]
    return hardened, trusted


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
    if not native_config().get("launch_requires_approval", False):
        audit("launch.approval_waived", "OK", mode=mode, exe=str(exe_path), by="operator_overlay")
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
           summary: dict[str, Any], kill_orphans: bool, memory_limit_mb: int | None = None,
           require_independent_holder: bool = False) -> Managed:
    ensure_recovered()
    _reserve_slot()
    try:
        return _launch(kind=kind, label=label, argv=argv, cmdline=cmdline, exe_path=exe_path, cwd=cwd, env=env,
                       timeout_s=timeout_s, mode=mode, approval_id=approval_id, summary=summary,
                       kill_orphans=kill_orphans, memory_limit_mb=memory_limit_mb,
                       require_independent_holder=require_independent_holder)
    finally:
        _release_slot()


def _launch(*, kind: str, label: str, argv: list[str] | None, cmdline: str | None, exe_path: Path,
            cwd: Path, env: dict[str, str], timeout_s: int, mode: str, approval_id: str | None,
            summary: dict[str, Any], kill_orphans: bool, memory_limit_mb: int | None,
            require_independent_holder: bool = False) -> Managed:
    pid_id = new_id("prc")
    directory = state_subdir("procs") / pid_id
    directory.mkdir(parents=True)
    meta: dict[str, Any] = {
        "id": pid_id, "kind": kind, "label": label[:80], "state": "starting", "mode": mode,
        "exe": str(exe_path), "summary": redact(summary), "cwd": str(cwd), "owner": procs.current_user(),
        "approval_id": approval_id, "started_at": iso(), "ended_at": None, "pid": None, "created": None,
        "timeout_s": timeout_s, "exit_code": None, "stop_reason": None, "output_truncated": False,
        "children_seen": [], "orphans": [], "recovered": False, "job_assigned": False, "kill_verified": None,
    }
    atomic_write_json(directory / "meta.json", meta)          # durable BEFORE anything can run
    audit("process.start", "START", process_id=pid_id, kind=kind, exe=str(exe_path), cwd=str(cwd), mode=mode,
          summary=summary, approval_id=approval_id)
    out = (directory / "stdout.log").open("xb")
    err = (directory / "stderr.log").open("xb")
    job = None
    popen = None
    try:
        job_name = None if kill_orphans else "Local\\pdc-job-" + pid_id      # detached trees stay reachable after a restart
        job = procs.Job(memory_limit_bytes=(memory_limit_mb or 0) * 1024 * 1024 or None,
                        max_active=64 if kill_orphans else None, kill_on_close=kill_orphans, name=job_name,
                        hosted=job_name is not None, require_independent_holder=require_independent_holder,
                        holder_marker=str(directory / "holder.clean"))
        meta["job_name"] = job_name
        meta["job_holder"] = ({"pid": job.holder_pid, "created": job.holder_created} if job_name else None)
        meta["containment"] = "job" if job_name is None or job.holder_independent else "job_holder_not_independent"
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


MAX_TRACKED_DESCENDANTS = 1000


def _record_descendants(managed: Managed, pids: list[int]) -> bool:
    """Persist (pid, creation time) of descendants of a detached process; returns True when something was added.

    Identities are written while the process runs so a backend restart or an early parent exit cannot lose them;
    overflow is flagged (``orphans_truncated``) instead of silently dropped.
    """
    meta = managed.meta
    meta.setdefault("orphans", [])
    known = {(o["pid"], o["created"]) for o in meta["orphans"]}          # identity = pid + creation time (PIDs get reused)
    added = False
    for pid in pids:
        created = procs.creation_time(pid)
        if not created or (pid, created) in known or (pid == meta.get("pid") and created == meta.get("created")):
            continue
        if len(meta["orphans"]) >= MAX_TRACKED_DESCENDANTS:
            meta["orphans_truncated"] = True
            added = True
            break
        meta["orphans"].append({"pid": pid, "created": created})
        known.add((pid, created))
        added = True
    if added:
        with managed.lock, contextlib.suppress(Exception):
            managed.save()
    return added


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
                else:       # explicit detach: last chance to record descendants (merged with those tracked live)
                    members = job.pids()
                    _record_descendants(managed, members)
                    if job.query_ok and not [p for p in members if not _is_root(managed.meta, p)]:
                        managed.meta["job_clean"] = True      # nothing is left that could spawn anything
                        with managed.lock, contextlib.suppress(Exception):
                            managed.save()
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
    last_scan = 0.0
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
            live = job.pids()
            for p in live:
                if p not in seen and len(meta["children_seen"]) < 200:
                    seen.add(p)
                    if p != meta["pid"]:
                        meta["children_seen"].append(p)
        elif adopted and time.monotonic() - last_scan >= 2.0:       # no Job Object after a restart: walk the tree
            last_scan = time.monotonic()
            live = [p for p, _created in procs.descendants(meta["pid"], meta["created"])]
        else:
            live = []
        if not managed.kill_orphans and live:
            _record_descendants(managed, live)


def _must_retain(data: dict[str, Any]) -> bool:
    """A record that is still the only handle on live or unverified descendants is never expired."""
    if data.get("stop_incomplete") or data.get("kill_verified") is False:
        return True
    if data.get("pid") and data.get("created") and procs.is_alive(data["pid"], data["created"]):
        return True                           # the original root itself is still running
    for item in data.get("orphans") or []:
        if procs.is_alive(item.get("pid"), item.get("created")):
            return True
    if not data.get("job_name") or _holder_clean(data):
        return False
    job = _open_owned_job(data)
    if job is None:
        return True                           # emptiness was never established and the job cannot be inspected
    try:
        return bool(job.pids()) or not job.query_ok       # ANY member counts: no pid-only exclusion of the root
    finally:
        job.close()


def _prune_old() -> None:
    cutoff = time.time() - limit("process_retention_days") * 86400
    for directory in state_subdir("procs").iterdir():
        with contextlib.suppress(OSError, PolicyError):
            meta = directory / "meta.json"
            if directory.is_dir() and meta.is_file() and meta.stat().st_mtime < cutoff:
                data = read_json(meta, {})
                if data.get("state") in TERMINAL and not _must_retain(data):
                    shutil.rmtree(directory, ignore_errors=True)


def _is_root(meta: dict[str, Any], pid: int) -> bool:
    """True only for the recorded root process itself: same pid AND same creation time (a reused pid is a stranger)."""
    return bool(pid == meta.get("pid") and meta.get("created") and procs.creation_time(pid) == meta.get("created"))


def _holder_clean(meta: dict[str, Any]) -> bool:
    """Durable proof that the job emptied: observed empty by the server, or the holder's clean-exit marker."""
    if meta.get("job_clean"):
        return True
    with contextlib.suppress(OSError, PolicyError):
        return (state_subdir("procs") / str(meta.get("id")) / "holder.clean").is_file()
    return False


def _open_owned_job(meta: dict[str, Any]) -> "procs.Job | None":
    """Re-open the job of a record ONLY if it is provably the original: the holder process recorded at launch (pid +
    creation time) must still be alive. A bare name can be re-created by anyone once the original object is gone, and
    terminating such a look-alike would kill unrelated processes."""
    name, holder = meta.get("job_name"), meta.get("job_holder")
    if not name or not isinstance(holder, dict) or not procs.is_alive(holder.get("pid"), holder.get("created")):
        return None
    return procs.Job.open(name)


def _reconcile_job_survivors(managed: Managed) -> None:
    """The root is gone but its named job may still hold live descendants: record their identities now."""
    name = managed.meta.get("job_name")
    job = _open_owned_job(managed.meta) if name else None
    if job is None:
        if name and _holder_clean(managed.meta):
            managed.meta["job_clean"] = True
        elif name:
            managed.meta["containment"] = "job_unreachable"     # unsampled descendants cannot be ruled out
        return
    try:
        members = [p for p in job.pids() if not _is_root(managed.meta, p)]
        if not members and job.query_ok:
            managed.meta["job_clean"] = True
        if members:
            _record_descendants(managed, members)
            managed.meta["containment"] = "job"
            _audit_quiet("process.recover", "SURVIVORS_RECORDED", process_id=managed.meta["id"], count=len(members))
    finally:
        job.close()


def ensure_recovered() -> None:
    """Re-adopt or close out processes recorded by a previous server instance (once, under a lock)."""
    global _RECOVERED
    with _RECOVERY_LOCK:
        if _RECOVERED:
            return
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
                    name = meta.get("job_name")
                    managed.job = _open_owned_job(meta) if name else None
                    # without the named job only periodic scans can find descendants: say so instead of implying completeness
                    meta["containment"] = "job" if managed.job is not None else "scan_only_incomplete"
                    with _REG_LOCK:
                        _REGISTRY[meta["id"]] = managed
                    managed.save()
                    _audit_quiet("process.recover", "ADOPTED", process_id=meta["id"], pid=pid)
                    threading.Thread(target=_monitor, args=(managed,), daemon=True).start()
                else:
                    if pid and created and procs.is_alive(pid, created) and meta.get("state") == "starting":
                        procs.terminate_tree(pid, created)   # crashed mid-launch: never leave it uncontained
                    _reconcile_job_survivors(managed)
                    meta.update(state="exited_unknown", ended_at=iso(), stop_reason="lost_across_restart")
                    atomic_write_json(directory / "meta.json", meta)
                    _audit_quiet("process.recover", "LOST", process_id=meta["id"])
            except Exception as exc:   # one damaged record must not block recovery of the others
                _audit_quiet("process.recover", "SKIPPED_CORRUPT", directory=directory.name, reason=type(exc).__name__)
        _prune_old()                          # only AFTER recovery has reconciled jobs and recorded survivors
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


def _stop_orphans(managed: Managed) -> list[int]:
    """Terminate a detached tree: through its kernel job first, then by recorded (pid, creation time) identity.

    The outcome is VERIFIED at the end (job empty and queryable, no recorded orphan alive); anything else is persisted
    as ``stop_incomplete`` so the caller never sees an ordinary success for an unverified stop.
    """
    meta = managed.meta
    stopped: list[int] = []
    remaining = []
    problem: str | None = None
    name = meta.get("job_name")
    job = _open_owned_job(meta) if name else None
    if name and job is None and _holder_clean(meta):
        meta["job_clean"] = True
    if name and job is None and not meta.get("job_clean"):
        # the job cannot be reached (holder gone, name released) and was never observed empty
        meta["containment"] = "job_unreachable"
        problem = "JOB_UNREACHABLE"
    try:
        if job is not None:                   # the kernel job is the authority on membership, not sampled PIDs
            members = [p for p in job.pids() if not _is_root(meta, p)]
            if members:
                _record_descendants(managed, members)
            identities = [(o["pid"], o["created"]) for o in meta.get("orphans") or [] if o["pid"] in members]
            # terminate regardless of whether enumeration worked or found anything: the job holds only our tree
            if not job.terminate():
                problem = "TERMINATE_JOB_FAILED"
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and (any(procs.is_alive(p, c) for p, c in identities) or job.pids()):
                time.sleep(0.1)
            stopped.extend(p for p, c in identities if not procs.is_alive(p, c))
        for item in meta.get("orphans") or []:       # identity fallback (also covers a job that could not be terminated)
            pid, created = item.get("pid"), item.get("created")
            if pid and created and procs.is_alive(pid, created):
                with contextlib.suppress(Exception):
                    procs.terminate_tree(pid, created)
                if procs.is_alive(pid, created):
                    remaining.append(item)
                elif pid not in stopped:
                    stopped.append(pid)
        if job is not None:                          # final verification of the job itself
            settle = time.monotonic() + 5
            left = job.pids()
            while left and job.query_ok and time.monotonic() < settle:
                time.sleep(0.1)                      # members killed by identity leave the job a moment later
                left = job.pids()
            if not job.query_ok:
                problem = "MEMBERSHIP_QUERY_FAILED"
            elif left:
                problem = problem if problem == "TERMINATE_JOB_FAILED" else "MEMBERS_STILL_ALIVE"
            elif problem == "TERMINATE_JOB_FAILED" and not remaining:
                problem = None                       # the identity fallback finished the job and it is verifiably empty
                meta["job_clean"] = True
            else:
                meta["job_clean"] = True
    finally:
        if job is not None:
            job.close()
    if remaining and not problem:
        problem = "ORPHANS_STILL_ALIVE"
    if problem:
        meta["stop_incomplete"] = problem
        if problem != "JOB_UNREACHABLE":
            meta["containment"] = "job_termination_unverified"
    else:
        meta.pop("stop_incomplete", None)
    meta["orphans"] = remaining
    with managed.lock, contextlib.suppress(Exception):
        managed.save()                        # always persisted: containment/stop_incomplete are part of the record
    audit("process.stop_orphans", "INCOMPLETE" if problem else "OK", process_id=meta["id"], stopped=stopped,
          remaining=len(remaining), reason=problem)
    return stopped


def stop_managed(managed: Managed, reason: str = "stopped") -> dict[str, Any]:
    meta = managed.meta
    if meta["owner"] != procs.current_user():
        raise PolicyError("PROCESS_OWNER_MISMATCH")
    if meta["state"] in TERMINAL:
        return _with_stop_status(managed, {"id": meta["id"], "state": meta["state"], "already_ended": True,
                                           "orphans_stopped": _stop_orphans(managed)})
    pid, created = meta["pid"], meta["created"]
    if not (pid and created and procs.is_alive(pid, created)):
        code = managed.popen.poll() if managed.popen is not None else None
        _finalize(managed, code, "exited" if code is not None else "exited_unknown")
        return _with_stop_status(managed, {"id": meta["id"], "state": meta["state"], "already_ended": True,
                                           "orphans_stopped": _stop_orphans(managed)})
    managed.stop_reason = reason
    managed.cancel.set()
    wait_done(managed, 10)
    if meta["state"] not in TERMINAL:
        _kill(managed)
        wait_done(managed, 5)
    audit("process.stop", meta["state"], process_id=meta["id"], kill_verified=meta.get("kill_verified"))
    return _with_stop_status(managed, {"id": meta["id"], "state": meta["state"], "exit_code": meta["exit_code"],
                                       "kill_verified": meta.get("kill_verified"),
                                       "orphans_stopped": _stop_orphans(managed)})


def _with_stop_status(managed: Managed, result: dict[str, Any]) -> dict[str, Any]:
    """A stop that could not be verified is never reported as an ordinary success."""
    reason = managed.meta.get("stop_incomplete")
    if reason:
        result.update(status="STOP_INCOMPLETE", stop_incomplete=reason, containment=managed.meta.get("containment"))
    return result


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


_CANON_CACHE: dict[str, tuple[tuple[int, int, bool], bytes, int]] = {}
_CANON_LOCK = threading.Lock()


def _canonical_output(path: Path, finished: bool) -> tuple[bytes, int]:
    """The redacted, UTF-8 representation of a stream that every page is cut from.

    Redaction runs over the WHOLE visible stream, never over a page, so no offset/length combination can
    start after a context prefix (``password=``) and expose its value. While the process still runs only
    complete lines are visible (a half-written secret never appears); the raw size is returned for reporting.
    """
    if not path.exists():
        return b"", 0
    st = path.stat()
    key = (st.st_size, st.st_mtime_ns, finished)
    with _CANON_LOCK:
        cached = _CANON_CACHE.get(str(path))
        if cached and cached[0] == key:
            return cached[1], cached[2]
    raw = path.read_bytes()[:st.st_size]
    if not finished:
        raw = raw[:raw.rfind(b"\n") + 1]
    canonical = redact_text(_decode(raw)).encode("utf-8")
    with _CANON_LOCK:
        if len(_CANON_CACHE) > 64:
            _CANON_CACHE.clear()
        _CANON_CACHE[str(path)] = (key, canonical, st.st_size)
    return canonical, st.st_size


def read_output(managed: Managed, stream: str = "stdout", offset: int = 0, max_bytes: int = 16384) -> dict[str, Any]:
    """Page the canonical redacted output; offsets count bytes of that redacted UTF-8 text."""
    if stream not in ("stdout", "stderr"):
        raise PolicyError("INVALID_STREAM")
    if type(offset) is not int or offset < 0:
        raise PolicyError("INVALID_OFFSET")
    max_bytes = max(1, min(int(max_bytes), limit("max_page_bytes")))
    finished = managed.meta["state"] in TERMINAL
    data, raw_size = _canonical_output(managed.dir / (stream + ".log"), finished)
    size = len(data)
    if offset > size:
        raise PolicyError("OFFSET_BEYOND_END")
    end = min(offset + max_bytes, size)
    if offset < size and (data[offset] & 0xC0) == 0x80:
        raise PolicyError("OFFSET_NOT_CHARACTER_ALIGNED")
    while end < size and end > offset and (data[end] & 0xC0) == 0x80:   # never split a character
        end -= 1
    if end == offset and offset < size:
        raise PolicyError("PAGE_LIMIT_TOO_SMALL")
    window = data[offset:end]
    finished = managed.meta["state"] in TERMINAL
    return {"id": managed.meta["id"], "stream": stream, "offset": offset, "next_offset": end,
            "size": size, "text": window.decode("utf-8", errors="replace"), "eof": finished and end >= size,
            "state": managed.meta["state"], "output_truncated": bool(managed.meta.get("output_truncated"))}


def public_meta(meta: dict[str, Any]) -> dict[str, Any]:
    keys = ("id", "kind", "label", "state", "mode", "exe", "cwd", "summary", "owner", "started_at", "ended_at",
            "pid", "timeout_s", "exit_code", "stop_reason", "output_truncated", "children_seen", "recovered",
            "approval_id", "job_assigned", "kill_verified", "orphans", "containment", "stop_incomplete",
            "job_clean")
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
                  approval_id: str | None = None, detach: bool = False) -> dict[str, Any]:
    """Start a long-running managed process (argument vector, no shell, bounded output).

    Only git (local subcommands) runs without approval; every other executable needs an operator approval.
    By default the whole process tree dies when the root exits. ``detach=true`` lets descendants outlive the
    root; they are recorded (pid + creation time) and ``process_stop`` still terminates them later.
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
    deny_deletion_argv(exe_path.name, args)
    if exe_path.name.casefold() == "git.exe":
        args, free = guard_git_args(args, workdir)
    timeout = max(1, min(int(timeout_s), limit("max_process_lifetime_s")))
    params = launch_params(exe_path, args, workdir, timeout, env, mode)
    if detach:
        params["detach"] = True
    pending = authorize_launch(mode, exe_path, environment, params, approval_id,
                               force_approval=(not free) or detach)
    if pending:
        return pending
    managed = launch(kind="process", label=label or exe_path.name, argv=args, cmdline=None, exe_path=exe_path,
                     cwd=workdir, env=environment, timeout_s=timeout, mode=mode, approval_id=approval_id,
                     summary=params, kill_orphans=not detach, require_independent_holder=detach)
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
