"""Trusted local approval-to-execution transaction (not a public endpoint).

An approved challenge is reserved *before* any external Docker side effect.
A reservation never gets replayed. On ambiguity it remains reserved and
requires owner-led reconciliation. Default Ledger RejectAll denies execution.
"""
from __future__ import annotations

from .contracts import Denied, Manifest, Principal, require
from .execution import DockerExecutor
from .ledger import Ledger
from .policy import TaskGrant


class ApprovedExecution:
    def __init__(self, runner: DockerExecutor, approvals: Ledger):
        require(type(runner) is DockerExecutor or isinstance(runner, DockerExecutor),
                "INVALID_CONFIGURATION")
        require(type(approvals) is Ledger, "INVALID_CONFIGURATION")
        self.runner = runner
        self.ledger = approvals

    def propose(self, manifest: Manifest, grant: TaskGrant,
                principal: Principal, workspace_id: str) -> dict:
        require(manifest.operation == "task.start", "INVALID_REQUEST")
        self.runner._authorize_task(manifest, grant, principal, workspace_id,
                                    "task.start")
        # This produces a challenge only; it does not create a container.
        return self.ledger.propose(manifest, principal)

    def start_once(self, manifest: Manifest, grant: TaskGrant,
                   principal: Principal, workspace_id: str,
                   challenge_id: str, idempotency_key: str) -> dict:
        require(manifest.operation == "task.start", "INVALID_REQUEST")
        self.runner._authorize_task(manifest, grant, principal, workspace_id,
                                    "task.start")
        require(not self.runner.stop_file.exists(), "OPERATION_CANCELLED")
        prior = self.ledger.find_reservation(principal, manifest, idempotency_key)
        if prior is not None:
            return {"status": "ALREADY_RESERVED", "operation_id": prior["operation_id"],
                    "started_another_process": False}
        reservation = self.ledger.reserve(challenge_id, manifest, principal,
                                          idempotency_key)
        if not reservation["created"]:
            return {"status": "ALREADY_RESERVED", "operation_id": reservation["operation_id"],
                    "started_another_process": False}
        # After reservation, failures are intentionally NOT retried.
        task = self.runner.start(manifest, grant, principal, workspace_id)
        return {"status": "STARTED", "operation_id": reservation["operation_id"],
                "task_id": task["task_id"], "host_execution": False,
                "started_another_process": True}
