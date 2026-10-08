"""Read-only orphan/task inventory for a trusted local operator.

No automatic Docker stop, deletion, creation, or host shell fallback.
The Docker client must be injected by the trusted owner-side caller.
"""
from __future__ import annotations

import json
import re
from typing import Callable

from .contracts import Denied, require
from .execution import DockerExecutor

_CONTAINER = re.compile(r"pdc22-[0-9a-f]{24}\Z")
_TASK = re.compile(r"task-[0-9a-f]{24}\Z")


def inspect_owned_workers(
    runner: DockerExecutor,
    *,
    docker_call: Callable[..., str] | None = None,
    enforce_audit: bool = True,
) -> dict:
    """Reconcile persisted tasks and labeled containers without modifying them.

    A missing or malformed daemon response fails closed; no cleanup is implied.
    All returned worker IDs are opaque. Requires a working trusted local broker.
    """
    # Normal inventory requires intact audit. The trusted emergency STOP
    # reconciler may explicitly bypass it to prevent audit outage blocking STOP.
    if enforce_audit:
        runner.audit.verify()
    call = docker_call if docker_call is not None else runner._docker
    raw = call(
        "ps", "--all", "--filter", "label=personal-dc.owner=phase03",
        "--format", "{{json .}}",
    )
    require(type(raw) is str and len(raw) <= 1000000, "ENVIRONMENT_UNAVAILABLE")
    containers = {}
    for line in raw.splitlines():
        try:
            value = json.loads(line)
        except (ValueError, TypeError):
            raise Denied("ENVIRONMENT_UNAVAILABLE") from None
        require(type(value) is dict, "ENVIRONMENT_UNAVAILABLE")
        name = value.get("Names")
        require(type(name) is str and _CONTAINER.fullmatch(name) is not None,
                "INVENTORY_AMBIGUOUS")
        require(name not in containers, "INVENTORY_AMBIGUOUS")
        containers[name] = {"container": name, "reported_state": str(value.get("State", "unknown"))[:32]}
    registered = {}
    for task_id, task in runner.tasks.items():
        require(_TASK.fullmatch(task_id) is not None and
                _CONTAINER.fullmatch(task.container) is not None,
                "INVENTORY_AMBIGUOUS")
        require(task.container not in registered, "INVENTORY_AMBIGUOUS")
        registered[task.container] = task_id
    orphaned = sorted(set(containers) - set(registered))
    missing = sorted(set(registered) - set(containers))
    return {
        "mode": "READ_ONLY",
        "stop_latched": runner.stop_file.exists(),
        "registered_tasks": len(registered),
        "labeled_containers": len(containers),
        "unregistered_labeled_containers": orphaned,
        "registered_containers_missing": missing,
        "reconciled_tasks": sorted(registered[name] for name in containers if name in registered),
        "automatic_stop": False,
        "automatic_delete": False,
        "requires_operator_review": bool(orphaned or missing),
    }
