"""Phase 03 contract/security tests. Fake Docker only tests argument policy;
it is never counted as evidence that guest isolation actually works."""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import replace
from pathlib import Path

import pytest

from dc_v2.contracts import Denied, Manifest, Principal
from dc_v2.execution import DockerExecutor, WorkspacePool
from dc_v2.policy import TaskGrant

IMAGE = "sha256:" + "a" * 64


class FakeDocker(DockerExecutor):
    def _docker(self, *args, **kwargs):
        self.commands.append(args)
        if args[:2] == ("info", "--format"):
            return "linux\n"
        if args[:2] == ("image", "inspect"):
            return self.image_id + "\n"
        if args[0] == "run":
            return "b" * 64
        if args[0] == "inspect":
            return json.dumps({"Running": True})
        if args[0] == "logs":
            return "token=SYNTHETIC-CANARY\n"
        if args[0] == "stop":
            return ""
        raise AssertionError(args)


@pytest.fixture
def harness(tmp_path):
    workspace_root = tmp_path / "workspace-pool"
    workspace_root.mkdir()
    control = tmp_path / "private-control"
    control.mkdir()
    binary = tmp_path / "docker.exe"
    binary.write_bytes(b"TEST STUB NOT RUN")
    pool = WorkspacePool(workspace_root, (control,))
    work = pool.create({"src/main.py": b'print("ok")\n'})
    broker = FakeDocker(binary, IMAGE, pool, control,
                        "npipe:////./pipe/dockerDesktopLinuxEngine",
                        canaries=(b"SYNTHETIC-CANARY",))
    broker.commands = []
    principal = Principal("owner", "client", "recipient",
                          frozenset({"task.start", "task.status", "task.output",
                                     "task.cancel", "task.list", "project:demo"}))
    manifest = Manifest(principal.binding, "demo", "task.start", work.snapshot_digest,
                        IMAGE[7:], broker.policy_digest, work.workspace_id,
                        principal.recipient_id, ("python", "src/main.py"), (),
                        ("sandbox-exec",), 30, 8192)
    grant = TaskGrant(principal.binding, "demo", work.snapshot_digest, IMAGE[7:],
                      broker.policy_digest, work.workspace_id, "recipient",
                      frozenset({"task.start"}), frozenset({"sandbox-exec"}),
                      int(time.time()) + 90, 60, 8192)
    return pool, work, broker, principal, manifest, grant


def test_workspace_write_patch_diff(harness):
    pool, work, *_ = harness
    assert pool.read(work.workspace_id, "src/main.py") == b'print("ok")\n'
    original = hashlib.sha256(b'print("ok")\n').hexdigest()
    after = pool.write(work.workspace_id, "src/main.py", b'print("fixed")\n',
                       expected_sha256=original)
    assert after == hashlib.sha256(b'print("fixed")\n').hexdigest()
    assert '-print("ok")' in pool.diff(work.workspace_id)
    assert '+print("fixed")' in pool.diff(work.workspace_id)
    with pytest.raises(Denied, match="MANIFEST_CHANGED"):
        pool.write(work.workspace_id, "src/main.py", b'evil', expected_sha256=original)


@pytest.mark.parametrize("name", ("../outside", ".git/config", ".env", "C:/Windows/file",
                                  "a:stream", "foo/../../bar", "NUL.txt"))
def test_workspace_path_escape_denied(harness, name):
    pool, work, *_ = harness
    with pytest.raises(Denied):
        pool.write(work.workspace_id, name, b"evil")
    with pytest.raises(Denied):
        pool.read(work.workspace_id, name)


def test_workspace_cross_root_fails(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    with pytest.raises(Denied, match="INVALID_CONFIGURATION"):
        WorkspacePool(root, (tmp_path,))
    with pytest.raises(Denied, match="INVALID_CONFIGURATION"):
        WorkspacePool(root, (root / "protected",))


def test_symlink_workspace_denied(harness, tmp_path):
    pool, work, *_ = harness
    evil = work.path / "alias"
    outside = tmp_path / "secret"
    outside.write_text("SECRET")
    try:
        evil.symlink_to(outside)
    except OSError:
        pytest.skip("Windows symlink creation privilege unavailable")
    with pytest.raises(Denied):
        pool.read(work.workspace_id, "alias")
    with pytest.raises(Denied):
        pool.diff(work.workspace_id)


def test_start_is_guest_only_and_offline(harness):
    _, work, broker, principal, manifest, grant = harness
    result = broker.start(manifest, grant, principal, work.workspace_id)
    assert result["host_execution"] is False
    cmd = next(args for args in broker.commands if args[0] == "run")
    assert ("--network", "none") == cmd[cmd.index("--network"):cmd.index("--network")+2]
    for flag in ("--read-only", "--cap-drop", "--security-opt", "--pids-limit",
                 "--memory", "--memory-swap", "--cpus", "--user", "--tmpfs",
                 "--pull", "--ipc", "--log-driver"):
        assert flag in cmd
    assert "privileged" not in " ".join(cmd)
    assert "/var/run/docker.sock" not in " ".join(cmd)
    assert str(work.path) in " ".join(cmd)
    assert "--env" in cmd
    assert "GH_TOKEN" not in " ".join(cmd)
    assert result["task_id"] in broker.list_tasks(principal)


def test_task_status_output_redaction_cancel(harness):
    _, work, broker, principal, manifest, grant = harness
    result = broker.start(manifest, grant, principal, work.workspace_id)
    tid = result["task_id"]
    assert broker.status(tid, principal)["status"] == "RUNNING"
    assert "SYNTHETIC-CANARY" not in broker.output(tid, principal)["data"]
    assert "[REDACTED]" in broker.output(tid, principal)["data"]
    assert broker.cancel(tid, principal)["status"] == "CANCEL_REQUESTED"
    assert any(args[0] == "stop" for args in broker.commands)


def test_cross_subject_and_unknown_ids_fail(harness):
    _, work, broker, principal, manifest, grant = harness
    tid = broker.start(manifest, grant, principal, work.workspace_id)["task_id"]
    other = replace(principal, client_id="attacker")
    for func in (broker.status, broker.output, broker.cancel):
        with pytest.raises(Denied, match="ACCESS_DENIED"):
            func(tid, other)
        with pytest.raises(Denied, match="ACCESS_DENIED"):
            func("task-"+"0"*24, principal)


@pytest.mark.parametrize("mutation", ("argv", "target_id", "tool_digest", "policy_digest",
                                      "snapshot_digest", "capabilities"))
def test_manifest_binding_is_not_forged(harness, mutation):
    _, work, broker, principal, manifest, grant = harness
    changes = {"argv": ("python", "-c", "print(1)"),
               "target_id": "ws-" + "1"*24,
               "tool_digest": "4"*64,
               "policy_digest": "5"*64,
               "snapshot_digest": "6"*64,
               "capabilities": ("network",)}
    new = replace(manifest, **{mutation: changes[mutation]})
    if mutation == "argv":
        broker.start(new, grant, principal, work.workspace_id)
        return  # repeated CLI inside one trusted grant is intentionally supported
    with pytest.raises(Denied):
        broker.start(new, grant, principal, work.workspace_id)


def test_latched_stop_survives_restart(harness):
    pool, work, broker, principal, manifest, grant = harness
    tid = broker.start(manifest, grant, principal, work.workspace_id)["task_id"]
    result = broker.emergency_stop()
    assert result["stop_latched"]
    assert result["tasks"][tid] == "STOP_REQUESTED"
    broker2 = FakeDocker(Path(broker.docker), IMAGE, pool, broker.control, broker.host)
    broker2.commands = []
    assert broker2.list_tasks(principal) == [tid]
    with pytest.raises(Denied, match="OPERATION_CANCELLED"):
        broker2.start(manifest, grant, principal, work.workspace_id)


def test_environment_failure_not_host_fallback(harness):
    _, work, broker, principal, manifest, grant = harness
    def unavailable(*args, **kwargs):
        raise Denied("ENVIRONMENT_UNAVAILABLE")
    broker._docker = unavailable
    with pytest.raises(Denied, match="ENVIRONMENT_UNAVAILABLE"):
        broker.start(manifest, grant, principal, work.workspace_id)


def test_secret_redacted_before_cursor_paging(harness):
    _, work, broker, principal, manifest, grant = harness
    manifest = replace(manifest, output_limit=131072)
    grant = replace(grant, output_limit=131072)
    tid = broker.start(manifest, grant, principal, work.workspace_id)["task_id"]
    def fake_docker(*args, **kwargs):
        if args[0] == "logs":
            return ("x"*65530) + "SYNTHETIC-CANARY" + ("y"*20)
        return FakeDocker._docker(broker, *args, **kwargs)
    broker._docker = fake_docker
    first = broker.output(tid, principal, 0, 65536)
    second = broker.output(tid, principal, first["cursor"], 100)
    combined = first["data"] + second["data"]
    assert "SYNTHETIC-CANARY" not in combined
    assert "[REDACTED]" in combined
    assert first["redactions"] == 1


def test_output_supports_small_pages(harness):
    _, work, broker, principal, manifest, grant = harness
    tid = broker.start(manifest, grant, principal, work.workspace_id)["task_id"]
    page = broker.output(tid, principal, cursor=0, limit=1)
    assert page["cursor"] == 1
    assert page["has_more"]


def resource_session(harness, operation, resource_id="source"):
    from dc_v2.workspace_broker import WorkspaceBroker
    pool, work, runner, principal, manifest, grant = harness
    broker = WorkspaceBroker(pool, runner, {"source": "src/main.py", "generated": "generated"})
    cap = "workspace-write" if operation in ("file.write","file.patch","file.mkdir") else "workspace-read"
    principal = replace(principal, scopes=frozenset({"project:demo", operation}))
    manifest = replace(manifest, operation=operation, argv=(resource_id,), capabilities=(cap,))
    grant = replace(grant, operations=frozenset({operation}), capabilities=frozenset({cap}))
    return broker, work, principal, manifest, grant


def test_resource_id_bound_file_patch_and_diff(harness):
    broker, work, principal, manifest, grant = resource_session(harness, "file.patch")
    original = hashlib.sha256(b'print("ok")\n').hexdigest()
    out = broker.patch(manifest, grant, principal, work.workspace_id, "source",
                       "ok", "fixed", original, 1, int(time.time()))
    assert out["replacements"] == 1
    broker2, work, p2, m2, g2 = resource_session(harness, "file.diff", "all")
    assert '+print("fixed")' in broker2.diff(m2, g2, p2, work.workspace_id, int(time.time()))["diff"]


def test_resource_read_and_search(harness):
    broker, work, principal, manifest, grant = resource_session(harness, "file.read")
    result = broker.read(manifest, grant, principal, work.workspace_id, "source", int(time.time()))
    assert result["content"] == 'print("ok")\n'
    s, w, p, m, g = resource_session(harness, "file.search", "all")
    assert s.search(m, g, p, w.workspace_id, "print", int(time.time())) == [
        {"resource_id": "source", "line": 1}]


def test_resource_unknown_id_and_forged_grant_denied(harness):
    broker, work, principal, manifest, grant = resource_session(harness, "file.read")
    with pytest.raises(Denied, match="MANIFEST_CHANGED"):
        broker.read(manifest, grant, principal, work.workspace_id, "unknown", int(time.time()))
    with pytest.raises(Denied, match="ACCESS_DENIED"):
        broker.read(manifest, grant, replace(principal, client_id="attacker"),
                    work.workspace_id, "source", int(time.time()))
    with pytest.raises(Denied, match="GRANT_EXPIRED"):
        broker.read(manifest, grant, principal, work.workspace_id, "source", grant.expires_at)


def test_resource_write_with_compare_and_swap(harness):
    broker, work, principal, manifest, grant = resource_session(harness, "file.write")
    original = hashlib.sha256(b'print("ok")\n').hexdigest()
    result = broker.write(manifest, grant, principal, work.workspace_id, "source",
                          b'print("new")\n', original, int(time.time()))
    assert result["sha256"] == hashlib.sha256(b'print("new")\n').hexdigest()
    with pytest.raises(Denied, match="MANIFEST_CHANGED"):
        broker.write(manifest, grant, principal, work.workspace_id, "source",
                     b'print("bad")\n', original, int(time.time()))


def test_resource_mkdir_is_mapped_and_latched(harness):
    broker, work, principal, manifest, grant = resource_session(harness, "file.mkdir", "generated")
    response = broker.mkdir(manifest, grant, principal, work.workspace_id,
                            "generated", int(time.time()))
    assert response["created"] and (work.path/"generated").is_dir()
    harness[2].emergency_stop()
    with pytest.raises(Denied, match="OPERATION_CANCELLED"):
        broker.mkdir(manifest, grant, principal, work.workspace_id,
                     "generated", int(time.time()))


def test_resource_read_longer_than_one_page(harness):
    broker, work, principal, manifest, grant = resource_session(harness, "file.read")
    manifest = replace(manifest, output_limit=131072)
    grant = replace(grant, output_limit=131072)
    old = hashlib.sha256(b'print("ok")\n').hexdigest()
    harness[0].write(work.workspace_id, "src/main.py", b"a"*70000 + b"END", old)
    response = broker.read(manifest, grant, principal, work.workspace_id, "source", int(time.time()))
    assert response["content"] == "a"*70000+"END"


def test_audit_hash_chain_and_tamper_detection(tmp_path):
    from dc_v2.phase03_audit import AuditJournal
    file = tmp_path / "audit.jsonl"
    journal = AuditJournal(file)
    journal.append("TEST", "subject", "object")
    journal.append("TEST", "subject", "second")
    assert journal.verify()[0] == 2
    raw = file.read_text()
    file.write_text(raw.replace('"kind":"TEST"', '"kind":"EVIL"', 1))
    with pytest.raises(Denied, match="AUDIT_INTEGRITY_ERROR"):
        journal.verify()
    with pytest.raises(Denied, match="AUDIT_INTEGRITY_ERROR"):
        journal.append("TEST", "subject", "third")


def test_corrupt_audit_denies_new_execution(harness):
    _, work, broker, principal, manifest, grant = harness
    broker.audit.path.write_bytes(b'{"forged":true}\n')
    with pytest.raises(Denied, match="AUDIT_INTEGRITY_ERROR"):
        broker.start(manifest, grant, principal, work.workspace_id)
    assert not broker.commands  # audit failed before Docker inspection or run


def test_corrupt_audit_blocks_file_export(harness):
    broker, work, principal, manifest, grant = resource_session(harness, "file.read")
    harness[2].audit.path.write_bytes(b'broken log\n')
    with pytest.raises(Denied, match="AUDIT_INTEGRITY_ERROR"):
        broker.read(manifest, grant, principal, work.workspace_id, "source", int(time.time()))


def test_project_scope_required_to_start_and_read_task(harness):
    _, work, broker, principal, manifest, grant = harness
    revoked = replace(principal, scopes=frozenset({"task.start", "task.status",
                                                    "task.output", "task.cancel", "task.list"}))
    with pytest.raises(Denied):
        broker.start(manifest, grant, revoked, work.workspace_id)
    tid = broker.start(manifest, grant, principal, work.workspace_id)["task_id"]
    with pytest.raises(Denied, match="ACCESS_DENIED"):
        broker.status(tid, revoked)
    with pytest.raises(Denied, match="ACCESS_DENIED"):
        broker.output(tid, revoked)


def test_operation_scope_required_on_existing_task(harness):
    _, work, broker, principal, manifest, grant = harness
    tid = broker.start(manifest, grant, principal, work.workspace_id)["task_id"]
    for scope, action in (("task.status",broker.status),("task.output",broker.output),
                          ("task.cancel",broker.cancel)):
        missing = replace(principal, scopes=frozenset(principal.scopes-{scope}))
        with pytest.raises(Denied, match="ACCESS_DENIED"):
            action(tid, missing)
    with pytest.raises(Denied, match="ACCESS_DENIED"):
        broker.list_tasks(replace(principal, scopes=frozenset(principal.scopes-{"task.list"})))


def test_file_diff_excludes_unregistered_guest_outputs(harness):
    broker, work, principal, manifest, grant = resource_session(harness, "file.diff", "all")
    harness[0].write(work.workspace_id, "src/main.py", b'print("fixed")\n')
    # Simulate files created by guest which were never registered as export resources.
    (work.path / "unregistered.txt").write_text("PRIVATE_UNREGISTERED_VALUE\n")
    visible = broker.diff(manifest, grant, principal, work.workspace_id, int(time.time()))["diff"]
    assert 'print("fixed")' in visible
    assert "PRIVATE_UNREGISTERED_VALUE" not in visible
    assert "unregistered.txt" not in visible


def test_guest_environment_requires_supported_policy(harness):
    _, work, broker, principal, manifest, grant = harness
    forged = replace(manifest, environment=(("SECRET_FROM_HOST", "not-allowed"),))
    with pytest.raises(Denied, match="UNSUPPORTED"):
        broker.start(forged, grant, principal, work.workspace_id)
    assert broker.commands == []


def test_output_grant_is_total_not_per_page(harness):
    _, work, broker, principal, manifest, grant = harness
    tid = broker.start(manifest, grant, principal, work.workspace_id)["task_id"]
    original = broker._docker

    def fake_logs(*args, **kwargs):
        if args[0] == "logs":
            return "x" * 9000
        return original(*args, **kwargs)

    broker._docker = fake_logs
    first = broker.output(tid, principal, 0, 65536)
    assert len(first["data"]) == 8192
    assert first["cursor"] == 8192
    assert first["has_more"] is False
    assert first["truncated"] is True
    final = broker.output(tid, principal, 8192, 100)
    assert final["data"] == ""
    with pytest.raises(Denied, match="INVALID_CURSOR"):
        broker.output(tid, principal, 8193, 100)


def test_old_task_state_recovery_requires_new_export_approval(harness):
    pool, work, broker, principal, manifest, grant = harness
    tid = broker.start(manifest, grant, principal, work.workspace_id)["task_id"]
    state = json.loads(broker.state_file.read_text())
    state[0].pop("output_limit")
    broker.state_file.write_text(json.dumps(state))
    recovered = FakeDocker(Path(broker.docker), IMAGE, pool, broker.control, broker.host)
    assert recovered.tasks[tid].output_limit == 0
    with pytest.raises(Denied, match="APPROVAL_REQUIRED"):
        recovered.output(tid, principal)


def test_file_read_refuses_output_larger_than_grant(harness):
    broker, work, principal, manifest, grant = resource_session(harness, "file.read")
    harness[0].write(work.workspace_id, "src/main.py", b"A" * 9000)
    with pytest.raises(Denied, match="QUOTA_EXCEEDED"):
        broker.read(manifest, grant, principal, work.workspace_id, "source", int(time.time()))


def test_file_diff_refuses_output_larger_than_grant(harness):
    broker, work, principal, manifest, grant = resource_session(harness, "file.diff", "all")
    harness[0].write(work.workspace_id, "src/main.py", b"B" * 9000)
    with pytest.raises(Denied, match="QUOTA_EXCEEDED"):
        broker.diff(manifest, grant, principal, work.workspace_id, int(time.time()))


def test_file_search_respects_export_limit(harness):
    broker, work, principal, manifest, grant = resource_session(harness, "file.search", "all")
    manifest = replace(manifest, output_limit=1024)
    grant = replace(grant, output_limit=1024)
    harness[0].write(work.workspace_id, "src/main.py", b"findme\n" * 110)
    with pytest.raises(Denied, match="QUOTA_EXCEEDED"):
        broker.search(manifest, grant, principal, work.workspace_id, "findme", int(time.time()))


def test_task_proposal_is_authorized_but_does_not_start_container(harness):
    _, work, broker, principal, manifest, grant = harness
    p = replace(principal, scopes=frozenset(set(principal.scopes) | {"task.propose"}))
    m = replace(manifest, operation="task.propose")
    g = replace(grant, operations=frozenset({"task.propose"}))
    proposal = broker.propose(m, g, p, work.workspace_id)
    assert proposal["manifest_digest"] == m.digest
    assert proposal["starts_process"] is False
    assert proposal["network"] == "none"
    assert broker.commands == []
    assert broker.audit.verify()[0] == 1
    with pytest.raises(Denied, match="ACCESS_DENIED"):
        broker.propose(m, g, principal, work.workspace_id)


def test_cancel_does_not_report_success_when_docker_stop_fails(harness):
    _, work, broker, principal, manifest, grant = harness
    tid = broker.start(manifest, grant, principal, work.workspace_id)["task_id"]
    original = broker._docker

    def failure(*args, **kwargs):
        if args[0] == "stop":
            raise Denied("ENVIRONMENT_UNAVAILABLE")
        return original(*args, **kwargs)

    broker._docker = failure
    with pytest.raises(Denied, match="ENVIRONMENT_UNAVAILABLE"):
        broker.cancel(tid, principal)
    outcome = broker.emergency_stop()
    assert outcome["stop_latched"] is True
    assert outcome["tasks"][tid] == "STOP_UNVERIFIED"


def test_workspace_import_rejects_casefold_alias_and_parent_file(tmp_path):
    root = tmp_path / "workspaces"
    root.mkdir()
    pool = WorkspacePool(root, ())
    with pytest.raises(Denied, match="INVALID_REQUEST"):
        pool.create({"src/Foo.py": b"first", "src/foo.py": b"second"})
    with pytest.raises(Denied, match="INVALID_REQUEST"):
        pool.create({"src": b"file", "src/module.py": b"nested"})
    assert not list(root.iterdir())


def test_workspace_import_rejects_protected_nested_paths_before_writing(tmp_path):
    root = tmp_path / "workspaces"
    root.mkdir()
    pool = WorkspacePool(root, ())
    with pytest.raises(Denied, match="ACCESS_DENIED"):
        pool.create({"ok.txt": b"ok", "src/.git/config": b"secret"})
    assert not list(root.iterdir())


def test_workspace_write_enforces_aggregate_size_limit(tmp_path):
    root = tmp_path / "pool"
    root.mkdir()
    pool = WorkspacePool(root, ())
    work = pool.create({f"file-{i}.txt": b"x" * 100_000 for i in range(100)})
    with pytest.raises(Denied, match="QUOTA_EXCEEDED"):
        pool.write(work.workspace_id, "extra.txt", b"X")
    assert not (work.path / "extra.txt").exists()


def test_workspace_write_enforces_post_import_file_count(tmp_path):
    root = tmp_path / "pool"
    root.mkdir()
    pool = WorkspacePool(root, ())
    work = pool.create({f"f-{i}.txt": b"a" for i in range(200)})
    with pytest.raises(Denied, match="QUOTA_EXCEEDED"):
        pool.write(work.workspace_id, "new.txt", b"new")
    assert not (work.path / "new.txt").exists()
    assert pool.write(work.workspace_id, "f-0.txt", b"ok") == hashlib.sha256(b"ok").hexdigest()
