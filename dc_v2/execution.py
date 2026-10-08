"""Phase 03 isolated development execution (trusted local broker ONLY).

No MCP tool or HTTP route instantiates this module. Docker daemon authority and
the isolated workspace/control roots must be protected by the local installer.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .contracts import Denied, Manifest, Principal, digest, require
from .output import OutputBuffer
from .phase03_audit import AuditJournal
from .policy import TaskGrant, relative_name


def _under(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _safe_path(root: Path, key: str) -> Path:
    path = root.joinpath(*relative_name(key))
    cur = root
    require(root.is_dir() and not root.is_symlink(), "ACCESS_DENIED")
    for part in relative_name(key):
        cur = cur / part
        if cur.exists() or cur.is_symlink():
            info = cur.lstat()
            require(not stat.S_ISLNK(info.st_mode) and
                    not (getattr(info, "st_file_attributes", 0) & 0x400), "ACCESS_DENIED")
    require(_under(path.resolve(strict=False), root.resolve()), "ACCESS_DENIED")
    return path


@dataclass(frozen=True)
class Workspace:
    workspace_id: str
    path: Path
    baseline: Mapping[str, bytes]
    snapshot_digest: str


class WorkspacePool:
    """Server-generated object IDs, never client-supplied host paths."""
    def __init__(self, root: Path, forbidden: tuple[Path, ...]):
        require(root.is_absolute() and root.is_dir() and not root.is_symlink(), "INVALID_CONFIGURATION")
        home = root.resolve()
        for block in forbidden:
            other = block.resolve(strict=False)
            require(not _under(home, other) and not _under(other, home), "INVALID_CONFIGURATION")
        self.root = home
        self.items: dict[str, Workspace] = {}

    def create(self, contents: Mapping[str, bytes]) -> Workspace:
        require(type(contents) is dict and len(contents) <= 200, "INVALID_REQUEST")
        total = 0
        for key, data in contents.items():
            relative_name(key)
            require(type(data) is bytes and len(data) <= 2_000_000, "INVALID_REQUEST")
            total += len(data)
        require(total <= 10_000_000, "QUOTA_EXCEEDED")
        wid = "ws-" + secrets.token_hex(12)
        target = self.root / wid
        target.mkdir(mode=0o700)
        try:
            for key, data in contents.items():
                location = _safe_path(target, key)
                location.parent.mkdir(parents=True, exist_ok=True)
                with location.open("xb") as handle:
                    handle.write(data)
            record = Workspace(wid, target, dict(contents), digest(
                {k: hashlib.sha256(v).hexdigest() for k, v in sorted(contents.items())}))
            self.items[wid] = record
            return record
        except Exception:
            # Do not delete automatically. Report incomplete workspace for operator review.
            raise

    def get(self, workspace_id: str) -> Workspace:
        require(type(workspace_id) is str and re.fullmatch(r"ws-[0-9a-f]{24}", workspace_id) is not None,
                "ACCESS_DENIED")
        work = self.items.get(workspace_id)
        require(work is not None and work.path.is_dir(), "ACCESS_DENIED")
        return work

    def read(self, workspace_id: str, key: str) -> bytes:
        work = self.get(workspace_id)
        path = _safe_path(work.path, key)
        require(path.is_file() and path.stat().st_size <= 2_000_000, "ACCESS_DENIED")
        return path.read_bytes()

    def write(self, workspace_id: str, key: str, contents: bytes, expected_sha256: str | None = None) -> str:
        require(type(contents) is bytes and len(contents) <= 2_000_000, "QUOTA_EXCEEDED")
        work = self.get(workspace_id)
        path = _safe_path(work.path, key)
        if expected_sha256 is not None:
            require(type(expected_sha256) is str and re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is not None,
                    "INVALID_REQUEST")
            before = path.read_bytes() if path.exists() else b""
            require(hashlib.sha256(before).hexdigest() == expected_sha256, "MANIFEST_CHANGED")
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            require(path.is_file(), "ACCESS_DENIED")
        tmp = path.with_name(path.name + ".pdc-stage-" + secrets.token_hex(8))
        with tmp.open("xb") as handle:
            handle.write(contents)
        os.replace(tmp, path)
        return hashlib.sha256(contents).hexdigest()

    def diff(self, workspace_id: str, allowed_keys: frozenset[str] | None = None) -> str:
        """Default internal diff, or a grant-scoped diff of registered resources."""
        work = self.get(workspace_id)
        if allowed_keys is not None:
            require(type(allowed_keys) is frozenset and len(allowed_keys) <= 256,
                    "INVALID_REQUEST")
            for key in allowed_keys:
                relative_name(key)
        all_files = {}
        for path in work.path.rglob("*"):
            if path.is_symlink():
                raise Denied("ACCESS_DENIED")
            if path.is_file():
                key = path.relative_to(work.path).as_posix()
                if allowed_keys is not None and key not in allowed_keys:
                    continue
                _safe_path(work.path, key)
                require(path.stat().st_size <= 2_000_000, "QUOTA_EXCEEDED")
                all_files[key] = path.read_bytes()
        require(len(all_files) <= 256, "QUOTA_EXCEEDED")
        baseline_keys = set(work.baseline)
        if allowed_keys is not None:
            baseline_keys &= allowed_keys
        patches = []
        for key in sorted(set(all_files) | baseline_keys):
            old = work.baseline.get(key, b"")
            new = all_files.get(key, b"")
            if old == new:
                continue
            try:
                before = old.decode("utf-8").splitlines(keepends=True)
                after = new.decode("utf-8").splitlines(keepends=True)
            except UnicodeDecodeError:
                raise Denied("BINARY_DIFF_UNSUPPORTED") from None
            patches.extend(difflib.unified_diff(before, after, fromfile="a/"+key, tofile="b/"+key))
            require(sum(map(len, patches)) <= 500_000, "QUOTA_EXCEEDED")
        return "".join(patches)


@dataclass(frozen=True)
class RunningTask:
    task_id: str
    container: str
    principal_binding: str
    project_id: str
    workspace_id: str
    manifest_digest: str
    started_at: int
    timeout_s: int
    output_limit: int = 0  # Legacy task records cannot be granted a retroactive export quota.


class DockerExecutor:
    """Non-networked disposable Docker sandbox behind a trusted local broker.

    Docker is infrastructure, not an unprivileged sandbox. The host Docker socket
    must be inaccessible to model-controlled code, and the broker has no MCP
    listener. Control directory MUST NOT be mounted in the container.
    """
    IMAGE_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")

    def __init__(self, docker_binary: Path, image_id: str, pool: WorkspacePool,
                 control_root: Path, docker_host: str,
                 canaries: tuple[bytes, ...] = ()):
        require(docker_binary.is_absolute() and docker_binary.is_file(), "INVALID_CONFIGURATION")
        require(self.IMAGE_PATTERN.fullmatch(image_id) is not None, "INVALID_CONFIGURATION")
        require(control_root.is_absolute() and control_root.is_dir(), "INVALID_CONFIGURATION")
        require(not _under(control_root.resolve(), pool.root) and
                not _under(pool.root, control_root.resolve()), "INVALID_CONFIGURATION")
        require(docker_host.startswith(("npipe:////./pipe/", "unix:///")) and
                len(docker_host) <= 160, "INVALID_CONFIGURATION")
        self.docker = str(docker_binary)
        self.image_id = image_id
        self.pool = pool
        self.control = control_root.resolve()
        self.host = docker_host
        self.canaries = canaries
        self.stop_file = self.control / "EMERGENCY_STOP"
        self.state_file = self.control / "tasks.json"
        self.audit = AuditJournal(self.control / "audit.jsonl")
        self.tasks: dict[str, RunningTask] = {}
        if self.state_file.exists():
            raw = json.loads(self.state_file.read_text(encoding="utf-8"))
            require(type(raw) is list and len(raw) <= 1000, "INVALID_CONFIGURATION")
            for item in raw:
                obj = RunningTask(**item)
                require(re.fullmatch(r"pdc22-[0-9a-f]{24}", obj.container) is not None and
                        re.fullmatch(r"task-[0-9a-f]{24}", obj.task_id) is not None and
                        type(obj.output_limit) is int and
                        (obj.output_limit == 0 or 1024 <= obj.output_limit <= 1048576),
                        "INVALID_CONFIGURATION")
                self.tasks[obj.task_id] = obj

    @property
    def policy_digest(self) -> str:
        return digest({"backend": "docker-desktop-linux", "version": 1,
                       "network": "none", "uid": 65534, "cpu": 1, "ram": 536870912,
                       "image": self.image_id, "read_only_root": True})

    def _docker(self, *args: str, timeout: int = 20, permitted_failure: bool = False,
                include_stderr: bool = False) -> str:
        # Environment is constructed from minimal trusted Windows system values.
        clean = {"PATH": str(Path(self.docker).parent),
                 "SYSTEMROOT": os.environ.get("SYSTEMROOT", r"C:\Windows"),
                 "WINDIR": os.environ.get("WINDIR", r"C:\Windows"),
                 "DOCKER_HOST": self.host}
        try:
            result = subprocess.run([self.docker, *args], shell=False,
                                    stdin=subprocess.DEVNULL, capture_output=True,
                                    env=clean, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise Denied("ENVIRONMENT_UNAVAILABLE") from None
        require(len(result.stdout) <= 2_000_000 and len(result.stderr) <= 2_000_000,
                "QUOTA_EXCEEDED")
        if result.returncode and not permitted_failure:
            raise Denied("ENVIRONMENT_UNAVAILABLE")
        combined = result.stdout + (result.stderr if include_stderr else b"")
        return combined.decode("utf-8", errors="replace")

    def check(self) -> dict:
        require(not self.stop_file.exists(), "OPERATION_CANCELLED")
        engine = self._docker("info", "--format", "{{.OSType}}").strip()
        require(engine == "linux", "ENVIRONMENT_UNAVAILABLE")
        image = self._docker("image", "inspect", self.image_id, "--format", "{{.Id}}").strip()
        require(image == self.image_id, "ENVIRONMENT_UNAVAILABLE")
        return {"engine": "linux", "image_id": image, "network": "none",
                "host_execution": False}

    def _save(self) -> None:
        tmp = self.control / ("tasks.tmp." + secrets.token_hex(6))
        raw = [vars(v) for v in self.tasks.values()]
        with tmp.open("x", encoding="utf-8") as file:
            json.dump(raw, file, sort_keys=True)
            file.flush()
            os.fsync(file.fileno())
        os.replace(tmp, self.state_file)

    def _authorize_task(self, manifest: Manifest, grant: TaskGrant,
                        principal: Principal, workspace_id: str,
                        operation: str, now: int | None = None) -> int:
        require(not self.stop_file.exists(), "OPERATION_CANCELLED")
        current = int(time.time()) if now is None else now
        grant.authorize(manifest, principal, current)
        workspace = self.pool.get(workspace_id)
        require(not manifest.environment, "UNSUPPORTED")
        require(manifest.operation == operation and
                f"project:{manifest.project_id}" in principal.scopes and
                manifest.target_id == workspace_id and
                manifest.snapshot_digest == workspace.snapshot_digest and
                manifest.tool_digest == self.image_id.removeprefix("sha256:") and
                manifest.policy_digest == self.policy_digest and
                manifest.recipient_id == principal.recipient_id and
                "sandbox-exec" in manifest.capabilities,
                "MANIFEST_CHANGED")
        argv = manifest.argv
        require(0 < len(argv) <= 64 and sum(len(a) for a in argv) <= 16384 and
                all(type(arg) is str and 0 < len(arg) <= 8192 and "\0" not in arg
                    for arg in argv), "INVALID_REQUEST")
        require(len(self.tasks) < 1000, "QUOTA_EXCEEDED")
        self.audit.verify()
        return current

    def propose(self, manifest: Manifest, grant: TaskGrant, principal: Principal,
                workspace_id: str, now: int | None = None) -> dict:
        """Grant-scoped dry proposal; no container or host command is started."""
        self._authorize_task(manifest, grant, principal, workspace_id,
                             "task.propose", now)
        self.audit.append("TASK_PROPOSED", principal.binding, manifest.digest)
        return {"manifest_digest": manifest.digest,
                "workspace_id": workspace_id, "image_id": self.image_id,
                "network": "none", "host_execution": False,
                "timeout_s": manifest.timeout_s,
                "output_limit": manifest.output_limit, "starts_process": False}

    def start(self, manifest: Manifest, grant: TaskGrant, principal: Principal,
              workspace_id: str, now: int | None = None) -> dict:
        current = self._authorize_task(manifest, grant, principal, workspace_id,
                                       "task.start", now)
        workspace = self.pool.get(workspace_id)
        self.check()
        key = secrets.token_hex(12)
        container = "pdc22-" + key
        task = RunningTask("task-" + key, container, principal.binding,
                           manifest.project_id, workspace_id, manifest.digest,
                           current, manifest.timeout_s, manifest.output_limit)
        # Docker CLI *only*; argv is interpreted exclusively inside the offline guest.
        run_args = (
            "run", "--detach", "--name", container,
            "--label", "personal-dc.owner=phase03",
            "--pull", "never", "--network", "none", "--read-only",
            "--init", "--entrypoint", "/usr/bin/timeout",
            "--user", "65534:65534", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "--pids-limit", "128", "--memory", "536870912",
            "--memory-swap", "536870912", "--cpus", "1",
            "--ipc", "none", "--ulimit", "nofile=128:128",
            "--log-driver", "local", "--log-opt", "max-size=1m",
            "--log-opt", "max-file=2",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m,mode=1777",
            "--env", "HOME=/tmp", "--env", "PYTHONDONTWRITEBYTECODE=1",
            "--env", "PYTHONUNBUFFERED=1",
            "--mount", "type=bind,src=" + str(workspace.path) + ",dst=/workspace",
            "--workdir", "/workspace", self.image_id,
            "--signal=TERM", "--kill-after=3s", str(manifest.timeout_s) + "s", *manifest.argv
        )
        self.audit.append("TASK_RESERVED", principal.binding, task.task_id)
        self.tasks[task.task_id] = task
        self._save()  # Persist ownership BEFORE creating an external process.
        try:
            response = self._docker(*run_args, timeout=40)
            require(response.strip().startswith(key) or
                    re.fullmatch(r"[0-9a-f]{64}", response.strip()) is not None,
                    "ENVIRONMENT_UNAVAILABLE")
            self.audit.append("TASK_STARTED", principal.binding, task.task_id)
        except Exception:
            # Even when post-launch audit fails, stop this one owned container.
            self._docker("stop", "--time", "2", task.container,
                         timeout=12, permitted_failure=True)
            # Preserve registry for investigation; no automatic deletion.
            raise
        return {"task_id": task.task_id, "status": "RUNNING",
                "workspace_id": workspace_id, "host_execution": False}

    def _owned(self, task_id: str, principal: Principal, scope: str) -> RunningTask:
        require(type(task_id) is str and re.fullmatch(r"task-[0-9a-f]{24}", task_id) is not None,
                "ACCESS_DENIED")
        obj = self.tasks.get(task_id)
        require(obj is not None and obj.principal_binding == principal.binding and
                f"project:{obj.project_id}" in principal.scopes and
                scope in principal.scopes, "ACCESS_DENIED")
        return obj

    def status(self, task_id: str, principal: Principal) -> dict:
        task = self._owned(task_id, principal, "task.status")
        text = self._docker("inspect", "--format", "{{json .State}}", task.container)
        try:
            state = json.loads(text)
            require(type(state) is dict, "ENVIRONMENT_UNAVAILABLE")
        except ValueError:
            raise Denied("ENVIRONMENT_UNAVAILABLE") from None
        running = state.get("Running") is True
        if running and int(time.time()) - task.started_at > task.timeout_s:
            self._docker("stop", "--time", "2", task.container, timeout=12)
            return {"task_id": task_id, "status": "TIMEOUT"}
        return {"task_id": task_id, "status": "RUNNING" if running else "EXITED",
                "exit_code": None if running else state.get("ExitCode")}

    def output(self, task_id: str, principal: Principal, cursor: int = 0,
               limit: int = 65536) -> dict:
        task = self._owned(task_id, principal, "task.output")
        require(task.output_limit > 0, "APPROVAL_REQUIRED")
        self.audit.append("TASK_OUTPUT", principal.binding, task_id)
        require(type(cursor) is int and cursor >= 0 and
                type(limit) is int and 1 <= limit <= 65536, "INVALID_REQUEST")
        output = self._docker("logs", task.container, timeout=15,
                              include_stderr=True).encode("utf-8")
        # The configured Docker log driver bounds retained raw logs to 2 MiB.
        # Redact the WHOLE snapshot before applying a requested page cursor;
        # otherwise a secret split across output calls could be disclosed.
        require(len(output) <= 2_000_000, "QUOTA_EXCEEDED")
        buf = OutputBuffer(1048576, self.canaries)
        for offset in range(0, len(output), 65536):
            buf.append(output[offset:offset+65536])
        buf.append(b"", final=True)
        # A grant binds the *total visible* output, not just the page size.
        # Rotated/evicted logs cannot be used to skip ahead past this boundary.
        require(buf.dropped_bytes == 0, "OUTPUT_TRUNCATED")
        require(cursor <= min(buf.total_bytes, task.output_limit), "INVALID_CURSOR")
        if cursor == task.output_limit:
            return {"task_id": task_id, "cursor": cursor, "data": "",
                    "has_more": False, "truncated": buf.total_bytes > task.output_limit,
                    "available_from": 0, "redactions": buf.redactor.redactions,
                    "trust": "UNTRUSTED"}
        page_limit = min(limit, task.output_limit - cursor)
        data = buf.read(cursor, page_limit)
        more_authorized = data["next_cursor"] < min(buf.total_bytes, task.output_limit)
        return {"task_id": task_id, "cursor": data["next_cursor"],
                "data": data["data"].decode("utf-8", errors="replace"),
                "has_more": more_authorized,
                "truncated": buf.total_bytes > task.output_limit,
                "available_from": data["available_from"],
                "redactions": buf.redactor.redactions, "trust": "UNTRUSTED"}

    def cancel(self, task_id: str, principal: Principal) -> dict:
        task = self._owned(task_id, principal, "task.cancel")
        self.audit.append("TASK_CANCEL", principal.binding, task_id)
        self._docker("stop", "--time", "2", task.container, timeout=12)
        return {"task_id": task_id, "status": "CANCEL_REQUESTED"}

    def list_tasks(self, principal: Principal) -> list[str]:
        require("task.list" in principal.scopes, "ACCESS_DENIED")
        return sorted(v.task_id for v in self.tasks.values()
                      if v.principal_binding == principal.binding and
                      f"project:{v.project_id}" in principal.scopes)

    def emergency_stop(self) -> dict:
        """Trusted local OS operator entrypoint. No network resume endpoint."""
        with self.stop_file.open("a", encoding="utf-8") as file:
            file.write("STOP " + str(int(time.time())) + "\n")
            file.flush()
            os.fsync(file.fileno())
        results = {}
        for task in self.tasks.values():
            try:
                self._docker("stop", "--time", "2", task.container,
                             timeout=12)
                results[task.task_id] = "STOP_REQUESTED"
            except Denied:
                results[task.task_id] = "STOP_UNVERIFIED"
        return {"stop_latched": True, "tasks": results}
