"""Supervisor STOP recovery contract. Fake daemon; real engine tested separately."""
from __future__ import annotations

import json
from copy import deepcopy
import pytest

from dc_v2.contracts import Denied
from dc_v2.phase03_supervisor import reconcile_stop_latch
from test_execution import harness


def inspection(runner, name, *, privileged=False):
    task = next(t for t in runner.tasks.values() if t.container == name)
    return {
        "Image": runner.image_id,
        "Config": {"User": "65534:65534",
                   "Entrypoint": ["/usr/bin/timeout"],
                   "Labels": {"personal-dc.owner": "phase03"}},
        "HostConfig": {"NetworkMode": "none", "Privileged": privileged,
                       "ReadonlyRootfs": True, "CapDrop": ["ALL"],
                       "SecurityOpt": ["no-new-privileges:true"],
                       "PidsLimit": 128, "Memory": 536870912,
                       "NanoCpus": 1000000000, "IpcMode": "none",
                       "PidMode": "", "UsernsMode": "",
                       "CgroupnsMode": "private"},
        "Mounts": [{"Type": "bind", "Destination": "/workspace",
                    "Source": str(runner.pool.root / task.workspace_id)}],
    }


def bind_daemon(runner, names, *, privileged=False, fail_stop=False,
                still_running=False):
    called = []
    real = runner._docker

    def fake(*args, **kwargs):
        called.append(args)
        if args[0] == "ps":
            return "\n".join(json.dumps({"Names": name, "State": "running"})
                             for name in names)
        if args[0] == "inspect" and args[1] == "--format":
            return json.dumps({"Running": still_running})
        if args[0] == "inspect":
            return json.dumps([inspection(runner, args[1], privileged=privileged)])
        if args[0] == "stop":
            if fail_stop:
                raise Denied("ENVIRONMENT_UNAVAILABLE")
            return args[-1]
        return real(*args, **kwargs)
    runner._docker = fake
    return called


def test_no_stop_without_latch(harness):
    runner = harness[2]
    assert reconcile_stop_latch(runner)["mode"] == "NO_ACTION"
    assert runner.commands == []


def test_registered_owned_container_stopped_after_latch(harness):
    _, ws, runner, principal, manifest, grant = harness
    task_id = runner.start(manifest, grant, principal, ws.workspace_id)["task_id"]
    runner.stop_file.write_text("STOP operator\n")
    owned = runner.tasks[task_id].container
    called = bind_daemon(runner, [owned])
    response = reconcile_stop_latch(runner)
    assert response["stopped"] == [task_id]
    assert response["all_known_stopped"] is True
    assert [x[0] for x in called].count("stop") == 1
    assert runner.audit.verify()[0] >= 3


def test_supervisor_does_not_stop_unknown_labeled_orphan(harness):
    _, ws, runner, principal, manifest, grant = harness
    task_id = runner.start(manifest, grant, principal, ws.workspace_id)["task_id"]
    runner.stop_file.write_text("STOP operator\n")
    owned = runner.tasks[task_id].container
    orphan = "pdc22-" + "b"*24
    called = bind_daemon(runner, [owned, orphan])
    response = reconcile_stop_latch(runner)
    assert response["stopped"] == [task_id]
    assert response["unknown"] == [orphan]
    assert response["all_known_stopped"] is False
    assert [x[-1] for x in called if x[0] == "stop"] == [owned]


@pytest.mark.parametrize("cause", ("privileged", "daemon_stop_failure"))
def test_unverified_status_never_claims_success(harness, cause):
    _, ws, runner, principal, manifest, grant = harness
    task_id = runner.start(manifest, grant, principal, ws.workspace_id)["task_id"]
    runner.stop_file.write_text("STOP operator\n")
    owned = runner.tasks[task_id].container
    called = bind_daemon(runner, [owned],
                         privileged=cause == "privileged",
                         fail_stop=cause == "daemon_stop_failure")
    response = reconcile_stop_latch(runner)
    assert response["stopped"] == []
    assert response["unverified"] == [task_id]
    assert response["all_known_stopped"] is False
    if cause == "privileged":
        assert not any(a[0] == "stop" for a in called)


def test_untrusted_audit_prevents_supervisor_action(harness):
    runner = harness[2]
    runner.stop_file.write_text("STOP operator\n")
    runner.audit.path.write_bytes(b"bad audit\n")
    with pytest.raises(Denied, match="AUDIT_INTEGRITY_ERROR"):
        reconcile_stop_latch(runner)

def test_stop_ack_without_running_false_is_unverified(harness):
    _, ws, runner, principal, manifest, grant = harness
    tid = runner.start(manifest, grant, principal, ws.workspace_id)["task_id"]
    runner.stop_file.write_text("STOP operator\n")
    owned = runner.tasks[tid].container
    called = bind_daemon(runner, [owned], still_running=True)
    result = reconcile_stop_latch(runner)
    assert result["stopped"] == []
    assert result["unverified"] == [tid]
    assert result["all_known_stopped"] is False
    assert any(x[0] == "stop" for x in called)
