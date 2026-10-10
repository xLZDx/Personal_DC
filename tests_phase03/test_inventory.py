"""Negative checks for the read-only orphan inventory."""
from __future__ import annotations

import json
import pytest

from dc_v2.contracts import Denied
from dc_v2.phase03_inventory import inspect_owned_workers
from test_execution import harness  # reuse the disposable FakeDocker fixture


def test_inventory_is_read_only(harness):
    _, work, runner, principal, manifest, grant = harness
    result = runner.start(manifest, grant, principal, work.workspace_id)
    expected = runner.tasks[result["task_id"]].container
    calls = []

    def cli(*args, **kwargs):
        calls.append(args)
        return json.dumps({"Names": expected, "State": "running"})

    inventory = inspect_owned_workers(runner, docker_call=cli)
    assert inventory["registered_tasks"] == 1
    assert inventory["reconciled_tasks"] == [result["task_id"]]
    assert inventory["requires_operator_review"] is False
    assert inventory["automatic_stop"] is False
    assert calls == [("ps", "--all", "--filter", "label=personal-dc.owner=phase03",
                      "--format", "{{json .}}")]


def test_inventory_flags_orphans_and_missing(harness):
    _, work, runner, principal, manifest, grant = harness
    runner.start(manifest, grant, principal, work.workspace_id)
    orphan = "pdc22-" + "a" * 24
    inventory = inspect_owned_workers(
        runner, docker_call=lambda *a, **k: json.dumps({"Names": orphan, "State": "running"}))
    assert inventory["unregistered_labeled_containers"] == [orphan]
    assert len(inventory["registered_containers_missing"]) == 1
    assert inventory["requires_operator_review"] is True


@pytest.mark.parametrize("bad", [
    "not json", "{}", json.dumps({"Names": "unrelated-service", "State": "running"}),
    "\n".join([json.dumps({"Names": "pdc22-"+"a"*24})]*2),
])
def test_inventory_fails_closed_for_ambiguous_state(harness, bad):
    runner = harness[2]
    with pytest.raises(Denied):
        inspect_owned_workers(runner, docker_call=lambda *a, **k: bad)


def test_inventory_fails_closed_on_audit_corruption(harness):
    runner = harness[2]
    runner.audit.path.write_bytes(b"invalid\n")
    with pytest.raises(Denied, match="AUDIT_INTEGRITY_ERROR"):
        inspect_owned_workers(runner, docker_call=lambda *a, **k: "")
