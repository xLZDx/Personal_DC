"""Pure PEP decisions, exact data-export registry and no-execution tool discovery.

Filesystem checks are defense in depth, NOT a Windows handle/ACL or VM boundary.
They cannot authorize mutable host snapshots for execution; execution stays HOLD.
"""
from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PureWindowsPath
from typing import Mapping

from .contracts import Denied, Manifest, Principal, Request, identifier, require, sha256_hex


class Classification(str, Enum):
    PUBLIC = "PUBLIC"
    MODEL_EXPORT_ALLOWED = "MODEL_EXPORT_ALLOWED"
    LOCAL_ONLY = "LOCAL_ONLY"
    SECRET = "SECRET"


PROTECTED_NAMES = frozenset({".git", ".ssh", ".aws", ".azure", ".gnupg", ".git-credentials",
    ".npmrc", ".pypirc", "credentials", "credentials.json", "secrets.json", "id_rsa", "id_ed25519"})
PROTECTED_SUFFIXES = frozenset({".pem", ".key", ".pfx", ".p12", ".kdbx"})


def relative_name(name: str) -> tuple[str, ...]:
    """Portable restricted file keys; reject Windows path tricks even on Linux."""
    require(type(name) is str and 0 < len(name) <= 1024, "ACCESS_DENIED")
    require(not any(ord(c) < 32 or ord(c) == 127 for c in name), "ACCESS_DENIED")
    require(not PureWindowsPath(name).drive and not name.startswith(("/", "\\")), "ACCESS_DENIED")
    require("\\" not in name and ":" not in name and "~" not in name, "ACCESS_DENIED")
    parts = tuple(name.split("/"))
    for part in parts:
        require(part not in ("", ".", "..") and part == part.rstrip(". "), "ACCESS_DENIED")
        low = part.casefold()
        stem = low.split(".")[0]
        require(stem not in {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
                             *(f"lpt{i}" for i in range(1, 10))}, "ACCESS_DENIED")
        require(low not in PROTECTED_NAMES and not low.startswith(".env"), "ACCESS_DENIED")
    require(Path(parts[-1]).suffix.casefold() not in PROTECTED_SUFFIXES, "ACCESS_DENIED")
    return parts


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _no_links(path: Path) -> None:
    for candidate in (*reversed(path.parents), path):
        info = candidate.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not
                (getattr(info, "st_file_attributes", 0) & 0x400), "ACCESS_DENIED")


@dataclass(frozen=True)
class ExportEntry:
    resource_id: str
    relative_path: str
    classification: Classification
    recipients: frozenset[str]
    expected_digest: str
    max_bytes: int = 1048576

    def __post_init__(self) -> None:
        identifier(self.resource_id)
        relative_name(self.relative_path)
        require(type(self.classification) is Classification and type(self.recipients) is frozenset, "INVALID_CONFIGURATION")
        sha256_hex(self.expected_digest)
        require(type(self.max_bytes) is int and 1 <= self.max_bytes <= 10485760, "INVALID_CONFIGURATION")
        for r in self.recipients:
            identifier(r)


class ExportRegistry:
    """Configured by a trusted owner; resource IDs never become arbitrary paths."""
    def __init__(self, snapshot_root: Path, entries: tuple[ExportEntry, ...], protected_roots: tuple[Path, ...]):
        require(snapshot_root.is_absolute() and snapshot_root.exists(), "INVALID_CONFIGURATION")
        _no_links(snapshot_root)
        self.root = snapshot_root.resolve(strict=True)
        self.protected = tuple(p.resolve(strict=False) for p in protected_roots)
        require(not any(_inside(self.root, p) or _inside(p, self.root) for p in self.protected), "ACCESS_DENIED")
        self.entries = {e.resource_id: e for e in entries}
        require(len(self.entries) == len(entries), "INVALID_CONFIGURATION")

    def read(self, resource_id: str, principal: Principal) -> bytes:
        require("file.read" in principal.scopes, "ACCESS_DENIED")
        entry = self.entries.get(resource_id)
        require(entry is not None, "ACCESS_DENIED")
        require(entry.classification in (Classification.PUBLIC, Classification.MODEL_EXPORT_ALLOWED) and
                principal.recipient_id in entry.recipients, "EXPORT_DENIED")
        path = self.root.joinpath(*relative_name(entry.relative_path))
        try:
            _no_links(path)
            safe = path.resolve(strict=True)
            require(_inside(safe, self.root) and not any(_inside(safe, p) for p in self.protected), "ACCESS_DENIED")
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(safe, flags)
            with os.fdopen(fd, "rb") as handle:
                before = os.fstat(handle.fileno())
                require(stat.S_ISREG(before.st_mode) and before.st_size <= entry.max_bytes, "EXPORT_DENIED")
                data = handle.read(entry.max_bytes + 1)
                after = os.fstat(handle.fileno())
            require(len(data) <= entry.max_bytes and (before.st_ino, before.st_size, before.st_mtime_ns) ==
                    (after.st_ino, after.st_size, after.st_mtime_ns), "MANIFEST_CHANGED")
            require(hashlib.sha256(data).hexdigest() == entry.expected_digest, "MANIFEST_CHANGED")
            return data
        except Denied:
            raise
        except (OSError, ValueError):
            raise Denied("ACCESS_DENIED") from None


@dataclass(frozen=True)
class TaskGrant:
    principal_binding: str
    project_id: str
    snapshot_digest: str
    tool_digest: str
    policy_digest: str
    target_id: str
    recipient_id: str
    operations: frozenset[str]
    capabilities: frozenset[str]
    expires_at: int
    timeout_s: int
    output_limit: int

    def authorize(self, manifest: Manifest, principal: Principal, now: int) -> None:
        require(type(now) is int and now < self.expires_at, "GRANT_EXPIRED")
        require(manifest.principal_binding == principal.binding == self.principal_binding, "ACCESS_DENIED")
        for field in ("project_id", "snapshot_digest", "tool_digest", "policy_digest", "target_id", "recipient_id"):
            require(getattr(self, field) == getattr(manifest, field), "MANIFEST_CHANGED")
        require(manifest.operation in self.operations and manifest.operation in principal.scopes, "ACCESS_DENIED")
        require(set(manifest.capabilities) <= self.capabilities, "APPROVAL_REQUIRED")
        require(manifest.timeout_s <= self.timeout_s and manifest.output_limit <= self.output_limit, "QUOTA_EXCEEDED")


def clean_environment(configured: Mapping[str, str]) -> dict[str, str]:
    """Construct from explicit safe values; NEVER merge with os.environ."""
    allowed = {"LANG", "LC_ALL", "TZ", "TERM", "NO_COLOR"}
    require(set(configured) <= allowed and all(type(v) is str and len(v) <= 256 and
            "\0" not in v and "\r" not in v and "\n" not in v for v in configured.values()), "INVALID_ENVIRONMENT")
    return dict(configured)


def inspect_tool(path: Path, expected_digest: str, trusted_root: Path) -> dict:
    """Metadata-only, explicit path/hash. Does not search PATH or run --version."""
    sha256_hex(expected_digest)
    require(path.is_absolute() and trusted_root.is_absolute(), "TOOL_UNTRUSTED")
    try:
        _no_links(trusted_root)
        _no_links(path)
        safe, root = path.resolve(strict=True), trusted_root.resolve(strict=True)
        require(_inside(safe, root) and safe.is_file() and safe.stat().st_size <= 268435456, "TOOL_UNTRUSTED")
        h = hashlib.sha256()
        with safe.open("rb") as handle:
            while chunk := handle.read(65536):
                h.update(chunk)
        require(h.hexdigest() == expected_digest, "TOOL_UNTRUSTED")
        return {"sha256": h.hexdigest(), "size": safe.stat().st_size, "executed": False,
                "signature_verified": False, "execution_supported": False}
    except Denied:
        raise
    except OSError:
        raise Denied("TOOL_UNTRUSTED") from None
