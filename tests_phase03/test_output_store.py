"""Output snapshot tests on synthetic, immutable fixture state."""
from __future__ import annotations
from dataclasses import replace
import pytest

from dc_v2.contracts import Denied
from dc_v2.phase03_output_store import OutputSnapshots
from test_execution import harness


def make(harness):
    _, ws, runner, principal, manifest, grant = harness
    task_id = runner.start(manifest, grant, principal, ws.workspace_id)["task_id"]
    root = runner.control / "output-snapshots"
    root.mkdir()
    return runner, principal, task_id, OutputSnapshots(runner, root)


def test_output_seal_is_repeatable_and_redacted(harness):
    runner, principal, task_id, store = make(harness)
    original = runner._docker
    def fake(*args, **kwargs):
        if args[0] == "inspect":
            return '{"Running":false,"ExitCode":0}'
        return original(*args, **kwargs)
    runner._docker = fake
    sealed = store.seal(task_id, principal)
    assert sealed["already_sealed"] is False
    assert store.seal(task_id, principal)["already_sealed"] is True
    pages = []
    cursor = 0
    while True:
        page = store.read(task_id, principal, cursor, 5)
        pages.append(page["data"])
        cursor = page["cursor"]
        if not page["has_more"]:
            break
    assert "[REDACTED]" in "".join(pages)
    assert "SYNTHETIC-CANARY" not in "".join(pages)
    assert sealed["sha256"] == page["sha256"]


def test_output_unsealed_does_not_read_docker_logs(harness):
    runner, principal, task_id, store = make(harness)
    with pytest.raises(Denied, match="OUTPUT_NOT_SEALED"):
        store.read(task_id, principal)


def test_output_tamper_fails_closed(harness):
    runner, principal, task_id, store = make(harness)
    original = runner._docker
    runner._docker = lambda *a, **k: '{"Running":false,"ExitCode":0}' if a[0]=="inspect" else original(*a, **k)
    store.seal(task_id, principal)
    payload, _ = store._paths(task_id)
    payload.write_bytes(b"tamper")
    with pytest.raises(Denied, match="OUTPUT_INTEGRITY_ERROR"):
        store.read(task_id, principal)


def test_output_cross_principal_denied(harness):
    runner, principal, task_id, store = make(harness)
    other = replace(principal, client_id="other")
    with pytest.raises(Denied, match="ACCESS_DENIED"):
        store.read(task_id, other)

def test_output_seal_rejects_excessive_data(harness):
    runner, principal, task_id, store = make(harness)
    original = runner._docker
    def fake(*args, **kwargs):
        if args[0] == "inspect":
            return '{"Running":false,"ExitCode":0}'
        if args[0] == "logs":
            return "x" * 9000
        return original(*args, **kwargs)
    runner._docker = fake
    with pytest.raises(Denied, match="QUOTA_EXCEEDED"):
        store.seal(task_id, principal)
    data, meta = store._paths(task_id)
    assert not data.exists()
    assert not meta.exists()

def test_preexisting_partial_snapshot_refuses_seal(harness):
    runner, principal, task_id, store = make(harness)
    original = runner._docker
    runner._docker = lambda *a, **k: '{"Running":false,"ExitCode":0}' if a[0]=="inspect" else original(*a, **k)
    payload, meta = store._paths(task_id)
    payload.write_bytes(b"externally-planted")
    with pytest.raises(Denied, match="OUTPUT_INTEGRITY_ERROR"):
        store.seal(task_id, principal)
    assert payload.read_bytes() == b"externally-planted"
    assert not meta.exists()
