"""Grant-bound local workspace operations; no arbitrary host path parameters.

A privileged local service owns the resource registry. This module deliberately
has no network or MCP entrypoint; production identity/approval ceremony HOLD.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Mapping

from .contracts import Denied, Manifest, Principal, identifier, require
from .execution import DockerExecutor, WorkspacePool, _safe_path
from .output import OutputBuffer
from .policy import TaskGrant, relative_name


def _redacted_text(data: bytes, canaries: tuple[bytes, ...]) -> tuple[str, int]:
    require(len(data) <= 1048576, "QUOTA_EXCEEDED")
    out = OutputBuffer(1048576, canaries)
    for pos in range(0, len(data), 65536):
        out.append(data[pos:pos+65536])
    out.append(b"", final=True)
    items = []
    cursor = 0
    while True:
        part = out.read(cursor)
        items.append(part["data"])
        cursor = part["next_cursor"]
        if part["eof"]:
            break
    return b"".join(items).decode("utf-8", errors="replace"), out.redactor.redactions


class WorkspaceBroker:
    """Object-level PEP over detached synthetic workspaces."""

    def __init__(self, pool: WorkspacePool, runner: DockerExecutor,
                 resources: Mapping[str, str], canaries: tuple[bytes, ...] = ()):
        require(type(resources) is dict and len(resources) <= 256, "INVALID_CONFIGURATION")
        for resource_id, path in resources.items():
            identifier(resource_id)
            relative_name(path)
        require(pool is runner.pool, "INVALID_CONFIGURATION")
        self.pool = pool
        self.runner = runner
        self.resources = dict(resources)
        self.canaries = canaries

    def _authorize(self, manifest: Manifest, grant: TaskGrant,
                   principal: Principal, workspace_id: str, operation: str,
                   resource_id: str, now: int) -> str | None:
        require(not self.runner.stop_file.exists(), "OPERATION_CANCELLED")
        grant.authorize(manifest, principal, now)
        ws = self.pool.get(workspace_id)
        require(manifest.operation == operation and manifest.target_id == workspace_id and
                manifest.snapshot_digest == ws.snapshot_digest and
                manifest.tool_digest == self.runner.image_id.removeprefix("sha256:") and
                manifest.policy_digest == self.runner.policy_digest and
                manifest.recipient_id == principal.recipient_id and
                f"project:{manifest.project_id}" in principal.scopes and
                manifest.argv == (resource_id,), "MANIFEST_CHANGED")
        cap = "workspace-write" if operation in ("file.write", "file.patch", "file.mkdir") else "workspace-read"
        require(cap in manifest.capabilities, "APPROVAL_REQUIRED")
        if resource_id == "all":
            require(operation in ("file.search", "file.diff"), "ACCESS_DENIED")
            return None
        require(resource_id in self.resources, "ACCESS_DENIED")
        return self.resources[resource_id]

    def read(self, manifest: Manifest, grant: TaskGrant, principal: Principal,
             workspace_id: str, resource_id: str, now: int) -> dict:
        key = self._authorize(manifest, grant, principal, workspace_id, "file.read", resource_id, now)
        self.runner.audit.append("FILE_READ", principal.binding, resource_id)
        data = self.pool.read(workspace_id, key)
        content, redactions = _redacted_text(data, self.canaries)
        require(len(content.encode("utf-8")) <= manifest.output_limit, "QUOTA_EXCEEDED")
        return {"resource_id": resource_id, "sha256": hashlib.sha256(data).hexdigest(),
                "content": content, "redactions": redactions, "data_trust": "UNTRUSTED"}

    def write(self, manifest: Manifest, grant: TaskGrant, principal: Principal,
              workspace_id: str, resource_id: str, content: bytes,
              expected_digest: str, now: int) -> dict:
        key = self._authorize(manifest, grant, principal, workspace_id, "file.write", resource_id, now)
        self.runner.audit.append("FILE_WRITE", principal.binding, resource_id)
        result = self.pool.write(workspace_id, key, content, expected_digest)
        return {"resource_id": resource_id, "sha256": result}

    def patch(self, manifest: Manifest, grant: TaskGrant, principal: Principal,
              workspace_id: str, resource_id: str, original: str,
              replacement: str, expected_digest: str, expected_count: int,
              now: int) -> dict:
        key = self._authorize(manifest, grant, principal, workspace_id, "file.patch", resource_id, now)
        require(type(original) is str and 0 < len(original) <= 200_000 and
                type(replacement) is str and len(replacement) <= 200_000 and
                type(expected_count) is int and 1 <= expected_count <= 100,
                "INVALID_REQUEST")
        self.runner.audit.append("FILE_PATCH", principal.binding, resource_id)
        prior = self.pool.read(workspace_id, key)
        require(hashlib.sha256(prior).hexdigest() == expected_digest, "MANIFEST_CHANGED")
        try:
            text = prior.decode("utf-8")
        except UnicodeDecodeError:
            raise Denied("UNSUPPORTED") from None
        require(text.count(original) == expected_count, "MANIFEST_CHANGED")
        updated = text.replace(original, replacement).encode("utf-8")
        result = self.pool.write(workspace_id, key, updated, expected_digest)
        return {"resource_id": resource_id, "sha256": result, "replacements": expected_count}

    def mkdir(self, manifest: Manifest, grant: TaskGrant, principal: Principal,
              workspace_id: str, resource_id: str, now: int) -> dict:
        key = self._authorize(manifest, grant, principal, workspace_id, "file.mkdir", resource_id, now)
        self.runner.audit.append("FILE_MKDIR", principal.binding, resource_id)
        ws = self.pool.get(workspace_id)
        path = _safe_path(ws.path, key)
        path.mkdir(parents=True, exist_ok=True)
        require(path.is_dir() and not path.is_symlink(), "ACCESS_DENIED")
        return {"resource_id": resource_id, "created": True}

    def search(self, manifest: Manifest, grant: TaskGrant, principal: Principal,
               workspace_id: str, literal: str, now: int) -> list[dict]:
        self._authorize(manifest, grant, principal, workspace_id, "file.search", "all", now)
        self.runner.audit.append("FILE_SEARCH", principal.binding, workspace_id)
        require(type(literal) is str and 1 <= len(literal) <= 128 and
                all(32 <= ord(c) <= 126 for c in literal), "INVALID_REQUEST")
        results = []
        for resource_id, key in sorted(self.resources.items()):
            try:
                data = self.pool.read(workspace_id, key).decode("utf-8")
            except (Denied, UnicodeDecodeError):
                continue
            for i, line in enumerate(data.splitlines(), 1):
                if literal in line:
                    results.append({"resource_id": resource_id, "line": i})
                if len(results) == 100:
                    break
            if len(results) == 100:
                break
        require(len(json.dumps(results).encode("utf-8")) <= manifest.output_limit,
                "QUOTA_EXCEEDED")
        return results

    def diff(self, manifest: Manifest, grant: TaskGrant, principal: Principal,
             workspace_id: str, now: int) -> dict:
        self._authorize(manifest, grant, principal, workspace_id, "file.diff", "all", now)
        self.runner.audit.append("FILE_DIFF", principal.binding, workspace_id)
        value = self.pool.diff(workspace_id, frozenset(self.resources.values())).encode("utf-8")
        require(len(value) <= 500_000, "QUOTA_EXCEEDED")
        content, redactions = _redacted_text(value, self.canaries)
        require(len(content.encode("utf-8")) <= manifest.output_limit, "QUOTA_EXCEEDED")
        return {"diff": content, "redactions": redactions, "data_trust": "UNTRUSTED"}
