"""Immutable redacted output snapshots for completed synthetic Docker tasks.

A snapshot binds to the owning task and recipient; cursor pages are stable
across subsequent Docker log rotation. No raw Docker output is stored on disk.
The owner-provisioned control-root ACL is a deployment prerequisite.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from pathlib import Path

from .contracts import Denied, Principal, require
from .execution import DockerExecutor
from .output import OutputBuffer


def _sha(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


class OutputSnapshots:
    def __init__(self, runner: DockerExecutor, root: Path):
        require(isinstance(root, Path) and root.is_absolute() and root.is_dir() and
                not root.is_symlink(), "INVALID_CONFIGURATION")
        require(root.resolve().parent == runner.control and
                root.resolve() != runner.pool.root, "INVALID_CONFIGURATION")
        self.runner = runner
        self.root = root.resolve()

    def _paths(self, task_id: str) -> tuple[Path, Path]:
        require(type(task_id) is str and re.fullmatch(r"task-[0-9a-f]{24}", task_id),
                "ACCESS_DENIED")
        return (self.root / (task_id + ".bin"),
                self.root / (task_id + ".json"))

    def _existing(self, task_id: str, binding: str, max_output: int) -> tuple[bytes, dict] | None:
        payload_path, meta_path = self._paths(task_id)
        if not payload_path.exists() and not meta_path.exists():
            return None
        require(payload_path.is_file() and meta_path.is_file() and
                not payload_path.is_symlink() and not meta_path.is_symlink(),
                "OUTPUT_INTEGRITY_ERROR")
        try:
            meta = json.loads(meta_path.read_bytes())
            require(type(meta) is dict and
                    set(meta) == {"task_id", "principal_binding", "size",
                                  "sha256", "redactions", "version"} and
                    meta["task_id"] == task_id and
                    meta["principal_binding"] == binding and
                    meta["version"] == 1 and
                    type(meta["size"]) is int and
                    0 <= meta["size"] <= max_output and
                    type(meta["redactions"]) is int and
                    meta["redactions"] >= 0, "OUTPUT_INTEGRITY_ERROR")
            require(payload_path.stat().st_size == meta["size"],
                    "OUTPUT_INTEGRITY_ERROR")
            content = payload_path.read_bytes()
            require(_sha(content) == meta["sha256"], "OUTPUT_INTEGRITY_ERROR")
            return content, meta
        except Denied:
            raise
        except (OSError, ValueError, KeyError, TypeError):
            raise Denied("OUTPUT_INTEGRITY_ERROR") from None

    def seal(self, task_id: str, principal: Principal) -> dict:
        task = self.runner._owned(task_id, principal, "task.output")
        require(task.output_limit > 0, "APPROVAL_REQUIRED")
        self.runner.audit.verify()
        existing = self._existing(task_id, principal.binding, task.output_limit)
        if existing is not None:
            data, meta = existing
            return {"task_id": task_id, "sha256": meta["sha256"],
                    "size": len(data), "already_sealed": True,
                    "redactions": meta["redactions"]}
        state = self.runner.status(task_id, principal)
        require(state["status"] != "RUNNING", "TASK_RUNNING")
        raw = self.runner._docker("logs", task.container,
                                  include_stderr=True, timeout=15).encode("utf-8")
        require(len(raw) <= 2_000_000, "QUOTA_EXCEEDED")
        redactor = OutputBuffer(1048576, self.runner.canaries)
        for pos in range(0, len(raw), 65536):
            redactor.append(raw[pos:pos+65536])
        redactor.append(b"", final=True)
        require(redactor.dropped_bytes == 0 and
                redactor.total_bytes <= task.output_limit, "QUOTA_EXCEEDED")
        data = redactor.read(0, 65536)["data"]
        cursor = len(data)
        chunks = [data]
        while cursor < redactor.total_bytes:
            chunk = redactor.read(cursor, 65536)["data"]
            require(bool(chunk), "OUTPUT_INTEGRITY_ERROR")
            chunks.append(chunk)
            cursor += len(chunk)
        payload = b"".join(chunks)
        require(len(payload) == redactor.total_bytes, "OUTPUT_INTEGRITY_ERROR")
        meta = {"task_id": task_id, "principal_binding": principal.binding,
                "size": len(payload), "sha256": _sha(payload),
                "redactions": redactor.redactor.redactions, "version": 1}
        payload_path, meta_path = self._paths(task_id)
        # A half-written or externally planted pair is not a fresh snapshot.
        # Refuse to replace any existing artifact on first seal.
        require(not payload_path.exists() and not meta_path.exists() and
                not payload_path.is_symlink() and not meta_path.is_symlink(),
                "OUTPUT_INTEGRITY_ERROR")
        self.runner.audit.append("OUTPUT_SNAPSHOT_SEAL", principal.binding, task_id)
        # Exclusive creation is essential: os.replace would overwrite an
        # artifact planted by a concurrent caller after the preflight check.
        # An interrupted pair is deliberately left incomplete and denied on
        # every subsequent read/seal, until a separately authorized recovery.
        for destination, content in (
            (payload_path, payload),
            (meta_path, json.dumps(meta, sort_keys=True, separators=(",", ":")).encode()),
        ):
            try:
                with destination.open("xb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
            except OSError:
                raise Denied("OUTPUT_INTEGRITY_ERROR") from None
        self.runner.audit.append("OUTPUT_SNAPSHOT_SEALED", principal.binding, task_id)
        return {"task_id": task_id, "sha256": meta["sha256"],
                "size": len(payload), "already_sealed": False,
                "redactions": meta["redactions"]}

    def read(self, task_id: str, principal: Principal,
             cursor: int = 0, limit: int = 65536) -> dict:
        task = self.runner._owned(task_id, principal, "task.output")
        require(type(cursor) is int and type(limit) is int and cursor >= 0 and
                1 <= limit <= 65536, "INVALID_REQUEST")
        self.runner.audit.verify()
        existing = self._existing(task_id, principal.binding, task.output_limit)
        require(existing is not None, "OUTPUT_NOT_SEALED")
        content, meta = existing
        require(cursor <= len(content), "INVALID_CURSOR")
        # Cursor denotes a UTF-8 byte boundary. Do not corrupt multi-byte
        # characters by splitting them between pages.
        try:
            content[:cursor].decode("utf-8", "strict")
            content.decode("utf-8", "strict")
        except UnicodeDecodeError:
            raise Denied("OUTPUT_INTEGRITY_ERROR") from None
        next_cursor = min(len(content), cursor + limit)
        if next_cursor < len(content):
            while next_cursor > cursor:
                try:
                    content[cursor:next_cursor].decode("utf-8", "strict")
                    break
                except UnicodeDecodeError:
                    next_cursor -= 1
            require(next_cursor > cursor, "PAGE_LIMIT_TOO_SMALL")
        self.runner.audit.append("OUTPUT_SNAPSHOT_READ", principal.binding, task_id)
        return {"task_id": task_id, "cursor": next_cursor,
                "data": content[cursor:next_cursor].decode("utf-8", "strict"),
                "has_more": next_cursor < len(content),
                "sha256": meta["sha256"], "trust": "UNTRUSTED",
                "redactions": meta["redactions"]}
