"""Owner-approved local promotion prototype; deliberately not wired to MCP.

Only exact, existing, registered target files can be replaced. The caller must
supply a Ledger whose independent verifier was enrolled by an owner-controlled
service. Default Ledger RejectAll can NEVER approve a promotion.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .contracts import Denied, Manifest, Principal, digest, identifier, require
from .execution import WorkspacePool, _safe_path, _under
from .ledger import Ledger
from .phase03_audit import AuditJournal
from .policy import TaskGrant, relative_name


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class Change:
    resource_id: str
    relative_path: str
    expected_digest: str
    new_digest: str


@dataclass(frozen=True)
class PromotionPlan:
    project_id: str
    source_workspace_id: str
    snapshot_digest: str
    target_id: str
    changes: tuple[Change, ...]
    updated: tuple[bytes, ...]

    @property
    def digest(self) -> str:
        return digest({"project": self.project_id,
                       "source": self.source_workspace_id,
                       "snapshot": self.snapshot_digest,
                       "target": self.target_id,
                       "changes": [vars(c) for c in self.changes]})


class Promoter:
    """Testable broker-side CAS for owned target files, no implicit execution."""

    def __init__(self, pool: WorkspacePool, target_root: Path, target_id: str,
                 resources: Mapping[str, str], forbidden: tuple[Path, ...],
                 ledger: Ledger, audit: AuditJournal):
        identifier(target_id)
        require(target_root.is_absolute() and target_root.is_dir() and
                not target_root.is_symlink(), "INVALID_CONFIGURATION")
        target = target_root.resolve()
        require(not _under(target, pool.root) and not _under(pool.root, target),
                "INVALID_CONFIGURATION")
        for blocked in forbidden:
            fixed = blocked.resolve(strict=False)
            require(not _under(target, fixed) and not _under(fixed, target),
                    "INVALID_CONFIGURATION")
        require(type(resources) is dict and 0 < len(resources) <= 50,
                "INVALID_CONFIGURATION")
        for rid, name in resources.items():
            identifier(rid)
            relative_name(name)
        self.pool = pool
        self.root = target
        self.target_id = target_id
        self.resources = dict(resources)
        self.ledger = ledger
        self.audit = audit

    def prepare(self, workspace_id: str, project_id: str,
                resource_ids: tuple[str, ...]) -> PromotionPlan:
        identifier(project_id)
        require(type(resource_ids) is tuple and 1 <= len(resource_ids) <= 50 and
                len(set(resource_ids)) == len(resource_ids), "INVALID_REQUEST")
        ws = self.pool.get(workspace_id)
        updates = []
        entries = []
        for rid in resource_ids:
            require(rid in self.resources, "ACCESS_DENIED")
            rel = self.resources[rid]
            new = self.pool.read(workspace_id, rel)
            target = _safe_path(self.root, rel)
            require(target.is_file() and target.stat().st_size <= 2_000_000,
                    "ACCESS_DENIED")
            before = target.read_bytes()
            if before == new:
                continue
            require(len(new) <= 2_000_000, "QUOTA_EXCEEDED")
            entries.append(Change(rid, rel, _sha(before), _sha(new)))
            updates.append(new)
        require(entries, "NO_CHANGES")
        return PromotionPlan(project_id, workspace_id, ws.snapshot_digest,
                             self.target_id, tuple(entries), tuple(updates))

    def _authorize(self, plan: PromotionPlan, manifest: Manifest, grant: TaskGrant,
                   principal: Principal, now: int) -> None:
        grant.authorize(manifest, principal, now)
        require(manifest.operation == "changes.propose" and
                manifest.project_id == plan.project_id and
                manifest.target_id == self.target_id == plan.target_id and
                manifest.snapshot_digest == plan.snapshot_digest and
                manifest.argv == (plan.digest,) and
                "promotion" in manifest.capabilities and
                f"project:{plan.project_id}" in principal.scopes and
                manifest.recipient_id == principal.recipient_id,
                "MANIFEST_CHANGED")
        ws = self.pool.get(plan.source_workspace_id)
        require(ws.snapshot_digest == plan.snapshot_digest, "MANIFEST_CHANGED")
        require(len(plan.changes) == len(plan.updated), "INVALID_REQUEST")
        for entry, payload in zip(plan.changes, plan.updated):
            require(self.resources.get(entry.resource_id) == entry.relative_path and
                    _sha(payload) == entry.new_digest and
                    self.pool.read(plan.source_workspace_id, entry.relative_path) == payload,
                    "MANIFEST_CHANGED")

    def propose(self, plan: PromotionPlan, manifest: Manifest, grant: TaskGrant,
                principal: Principal, now: int) -> dict:
        self._authorize(plan, manifest, grant, principal, now)
        self.audit.append("PROMOTION_PROPOSE", principal.binding, plan.digest)
        return self.ledger.propose(manifest, principal)

    def apply(self, plan: PromotionPlan, manifest: Manifest, grant: TaskGrant,
              principal: Principal, challenge_id: str, idempotency_key: str,
              now: int) -> dict:
        self._authorize(plan, manifest, grant, principal, now)
        prior = self.ledger.find_reservation(principal, manifest, idempotency_key)
        if prior is not None:
            return {"status": "ALREADY_RESERVED", "operation_id": prior["operation_id"]}
        # Validate target before reserving approval; then validate AGAIN after
        # reservation. The trusted owner signature binds manifest + plan digest.
        targets = []
        for entry in plan.changes:
            file = _safe_path(self.root, entry.relative_path)
            require(file.is_file() and _sha(file.read_bytes()) == entry.expected_digest,
                    "MANIFEST_CHANGED")
            targets.append(file)
        reserved = self.ledger.reserve(challenge_id, manifest, principal, idempotency_key)
        if not reserved["created"]:
            return {"status": "ALREADY_RESERVED", "operation_id": reserved["operation_id"]}
        self.audit.append("PROMOTION_RESERVED", principal.binding, plan.digest)
        for file, entry in zip(targets, plan.changes):
            require(_sha(file.read_bytes()) == entry.expected_digest, "MANIFEST_CHANGED")
        # All paths checked first. OS atomic replace is per-file, NOT whole-tree
        # transactional. Production cross-file promotion remains HOLD.
        applied = []
        try:
            for file, entry, data in zip(targets, plan.changes, plan.updated):
                stage = file.with_name(file.name + ".pdc-promotion-" + secrets.token_hex(8))
                with stage.open("xb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(stage, file)
                applied.append(entry.resource_id)
        except OSError:
            self.audit.append("PROMOTION_PARTIAL", principal.binding, plan.digest)
            raise Denied("PARTIAL_PROMOTION") from None
        self.audit.append("PROMOTION_APPLIED", principal.binding, plan.digest)
        return {"status": "APPLIED", "operation_id": reserved["operation_id"],
                "resources": applied, "plan_digest": plan.digest,
                "automatic_execution": False}
