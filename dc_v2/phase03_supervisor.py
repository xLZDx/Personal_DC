"""One-shot fail-closed STOP reconciliation for a future independent supervisor.

Trusted local caller only. No MCP/HTTP listener, service installation or cleanup.
The independent host process must own its config/ACL before deployment.
"""
from __future__ import annotations

import json
from .contracts import Denied, require
from .execution import DockerExecutor
from .phase03_inventory import inspect_owned_workers
from .phase03_container_policy import check_container_policy


def reconcile_stop_latch(runner: DockerExecutor) -> dict:
    """Stop only registered and inspected owned workers when STOP is latched.

    The caller owns a trusted, isolated Docker client. Never stop an unknown,
    merely labeled orphan. Never remove or modify any container or workspace.
    """
    if not runner.stop_file.exists():
        runner.audit.verify()
        return {"stop_latched": False, "mode": "NO_ACTION", "stopped": [],
                "unverified": [], "unknown": [], "deletion": False}
    # Emergency STOP must work even when mandatory audit is unavailable.
    # Only exact registered, inspected and policy-matching containers can be
    # stopped; all unknown containers remain untouched.
    audit_ok = True
    try:
        runner.audit.verify()
    except (Denied, OSError):
        audit_ok = False
    inventory = inspect_owned_workers(runner, enforce_audit=False)
    def evidence(action: str, binding: str, task_id: str) -> None:
        nonlocal audit_ok
        if audit_ok:
            try:
                runner.audit.append(action, binding, task_id)
            except (Denied, OSError):
                audit_ok = False
    registered = {task.container: task for task in runner.tasks.values()}
    stopped, unverified = [], []
    for container_name in sorted(set(registered) - set(inventory["registered_containers_missing"])):
        task = registered[container_name]
        try:
            description = json.loads(runner._docker("inspect", container_name))
            require(type(description) is list and len(description) == 1,
                    "INVENTORY_AMBIGUOUS")
            entry = description[0]
            require(type(entry) is dict, "INVENTORY_AMBIGUOUS")
            labels = entry.get("Config", {}).get("Labels", {})
            require(type(labels) is dict and
                    labels.get("personal-dc.owner") == "phase03",
                    "INVENTORY_AMBIGUOUS")
            expected_path = str(runner.pool.root / task.workspace_id)
            check_container_policy(entry, expected_image=runner.image_id,
                                   expected_workspace=expected_path)
            evidence("SUPERVISOR_STOP_REQUEST", task.principal_binding,
                     task.task_id)
            runner._docker("stop", "--time", "2", container_name, timeout=12)
            verified_state = json.loads(runner._docker(
                "inspect", "--format", "{{json .State}}", container_name))
            require(type(verified_state) is dict and
                    verified_state.get("Running") is False,
                    "STOP_UNVERIFIED")
            evidence("SUPERVISOR_STOP_CONFIRMED",
                     task.principal_binding, task.task_id)
            stopped.append(task.task_id)
        except (Denied, ValueError, TypeError, KeyError):
            unverified.append(task.task_id)
    return {"stop_latched": True, "mode": "STOP_RECONCILIATION",
            "audit_verified": audit_ok,
            "stopped": sorted(stopped), "unverified": sorted(unverified),
            "unknown": inventory["unregistered_labeled_containers"],
            "missing": inventory["registered_containers_missing"],
            "deletion": False,
            "all_known_stopped": not unverified and not
                                 inventory["registered_containers_missing"] and
                                 not inventory["unregistered_labeled_containers"],
            "production_verified": False}
