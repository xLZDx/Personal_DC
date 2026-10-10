"""Trusted snapshot ingestion for disposable developer workspaces.

Not exposed through MCP. The owner supplies an explicit resource registry
of individually classified regular files with pinned SHA-256. This does not
claim Windows handle-level race protection against an adversarial host.
"""
from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .contracts import Denied, require, identifier, sha256_hex
from .execution import WorkspacePool, Workspace, _safe_path
from .policy import Classification, relative_name


@dataclass(frozen=True)
class ImportResource:
    resource_id: str
    relative_path: str
    expected_sha256: str
    classification: Classification
    recipients: frozenset[str]

    def __post_init__(self):
        identifier(self.resource_id)
        relative_name(self.relative_path)
        sha256_hex(self.expected_sha256)
        require(type(self.classification) is Classification and
                type(self.recipients) is frozenset and
                all(type(x) is str and identifier(x) for x in self.recipients),
                "INVALID_CONFIGURATION")


class SnapshotImporter:
    def __init__(self, source_root: Path, pool: WorkspacePool,
                 forbidden: tuple[Path, ...]):
        require(source_root.is_absolute() and source_root.is_dir() and
                not source_root.is_symlink(), "INVALID_CONFIGURATION")
        root = source_root.resolve(strict=True)
        require(root != pool.root and root not in pool.root.parents and
                pool.root not in root.parents, "INVALID_CONFIGURATION")
        for entry in forbidden:
            banned = entry.resolve(strict=False)
            require(root != banned and root not in banned.parents and
                    banned not in root.parents, "INVALID_CONFIGURATION")
        self.root = root
        self.pool = pool

    def import_approved(self, resources: tuple[ImportResource, ...],
                        recipient: str) -> tuple[Workspace, dict[str, str]]:
        identifier(recipient)
        require(type(resources) is tuple and 0 < len(resources) <= 200,
                "INVALID_REQUEST")
        require(len({r.resource_id for r in resources}) == len(resources) and
                len({r.relative_path.casefold() for r in resources}) == len(resources),
                "INVALID_REQUEST")
        contents: dict[str, bytes] = {}
        resource_map: dict[str, str] = {}
        total = 0
        for resource in resources:
            require(type(resource) is ImportResource, "INVALID_REQUEST")
            require(resource.classification in
                    (Classification.PUBLIC, Classification.MODEL_EXPORT_ALLOWED) and
                    recipient in resource.recipients, "EXPORT_DENIED")
            source = _safe_path(self.root, resource.relative_path)
            try:
                before = source.stat()
                require(stat.S_ISREG(before.st_mode) and
                        before.st_size <= 2_000_000, "ACCESS_DENIED")
                flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(source, flags)
                with os.fdopen(fd, "rb") as stream:
                    opened = os.fstat(stream.fileno())
                    require(stat.S_ISREG(opened.st_mode) and
                            opened.st_size <= 2_000_000, "ACCESS_DENIED")
                    data = stream.read(2_000_001)
                    after = os.fstat(stream.fileno())
                require(len(data) <= 2_000_000 and
                        (before.st_ino, before.st_size, before.st_mtime_ns) ==
                        (opened.st_ino, opened.st_size, opened.st_mtime_ns) ==
                        (after.st_ino, after.st_size, after.st_mtime_ns),
                        "MANIFEST_CHANGED")
                require(hashlib.sha256(data).hexdigest() == resource.expected_sha256,
                        "MANIFEST_CHANGED")
            except Denied:
                raise
            except (OSError, ValueError):
                raise Denied("ACCESS_DENIED") from None
            total += len(data)
            require(total <= 10_000_000, "QUOTA_EXCEEDED")
            contents[resource.relative_path] = data
            resource_map[resource.resource_id] = resource.relative_path
        # No workspace is created until every resource has passed validation.
        return self.pool.create(contents), resource_map
