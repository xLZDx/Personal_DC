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
    runner.audit.verify()
    if not runner.stop_file.exists():
        return {"stop_latched": False, "mode": "NO_ACTION", "stopped": [],
                "unverified": [], "unknown": [], "deletion": False}
    inventory = inspect_owned_workers(runner)
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
            runner.audit.append("SUPERVISOR_STOP_REQUEST", task.principal_binding,
                                task.task_id)
            runner._docker("stop", "--time", "2", container_name, timeout=12)
            runner.audit.append("SUPERVISOR_STOP_ACK", task.principal_binding,
                                task.task_id)
            stopped.append(task.task_id)
        except (Denied, ValueError, TypeError, KeyError):
            unverified.append(task.task_id)
    return {"stop_latched": True, "mode": "STOP_RECONCILIATION",
            "stopped": sorted(stopped), "unverified": sorted(unverified),
            "unknown": inventory["unregistered_labeled_containers"],
            "missing": inventory["registered_containers_missing"],
            "deletion": False,
            "all_known_stopped": not unverified and not
                                 inventory["registered_containers_missing"] and
                                 not inventory["unregistered_labeled_containers"],
            "production_verified": False}
