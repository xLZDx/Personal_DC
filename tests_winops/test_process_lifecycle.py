"""Managed process lifecycle on real Windows: identity, timeout, tree kill, output paging, recovery/adoption.

The interpreter is made an auto-trusted dev tool through the operator overlay (interpreters normally need an
approval; that gate is covered in ``test_command_policy.py`` / ``test_approval_execution.py``). Every test
leaves no process behind: the root conftest kills whatever remains in the registry.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import timedelta

import pytest
from personal_dc.policy import PolicyError

from dc_v2.winops import command_tools as ct
from dc_v2.winops import common, procs
from dc_v2.winops import process_tools as pt

PY = sys.executable
SLEEP = "import time;time.sleep(60)"
GRANDCHILD = ("import subprocess,sys,time;"
              "g=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
              "print(g.pid,flush=True);time.sleep(60)")

pytestmark = pytest.mark.usefixtures("trust_current_python")


def _run(work, code, **kw):
    return ct.command_execute(shell="exec", argv=[PY, "-c", code], cwd=str(work), mode="workspace_write", **kw)


def _wait(predicate, timeout=15.0, step=0.1):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(step)
    return bool(predicate())


def _start_process(work, code=SLEEP, **kw):
    started = pt.process_start(PY, ["-c", code], cwd=str(work), timeout_s=kw.pop("timeout_s", 120), **kw)
    assert started["status"] == "STARTED", started
    return started


def _printed_pid(process_id):
    holder = {}

    def ready():
        text = pt.read_output(pt.get_managed(process_id, "process"), "stdout", 0, 100)["text"].strip()
        if text:
            holder["pid"] = int(text.split()[0])
        return bool(text)
    assert _wait(ready, 20)
    return holder["pid"]


# ------------------------------------------------------------- execution
def test_exit_code_stdout_stderr_unicode(work):
    out = _run(work, "import sys;print('привет ✓');sys.stderr.write('err');sys.exit(3)")
    assert out["state"] == "exited" and out["exit_code"] == 3 and out["timed_out"] is False
    assert "привет ✓" in out["stdout"] and out["stderr"].strip() == "err"
    meta = pt.get_managed(out["id"]).meta
    assert meta["job_assigned"] is True and meta["pid"] and meta["created"] and meta["kind"] == "command"


def test_read_only_catalog_runs_without_approval():
    out = ct.command_execute("whoami")
    assert out["state"] == "exited" and out["exit_code"] == 0 and out["stdout"].strip()
    assert out["command"] == "whoami"


def test_output_secrets_are_redacted_when_read(work):
    out = _run(work, "print('password=hunter2sentinel');print('visible-out-marker')")
    assert "visible-out-marker" in out["stdout"]
    assert "hunter2sentinel" not in out["stdout"] and "password=***" in out["stdout"]
    page = pt.read_output(pt.get_managed(out["id"]), "stdout", 0, 4096)
    assert "hunter2sentinel" not in page["text"]


def test_timeout_kills_whole_tree_including_grandchild(work):
    start = time.monotonic()
    out = _run(work, GRANDCHILD, timeout_s=4)
    assert out["state"] == "timed_out" and out["timed_out"] is True and time.monotonic() - start < 25
    grandchild = int(out["stdout"].split()[0])
    meta = pt.get_managed(out["id"]).meta
    assert grandchild in meta["children_seen"]            # proves it was alive and inside the job before the kill
    assert _wait(lambda: not procs.is_alive(grandchild))
    assert not procs.is_alive(meta["pid"], meta["created"])
    assert meta["kill_verified"] is True


def test_output_pages_are_utf8_aligned(work):
    out = _run(work, "print('ж'*5000)")
    managed = pt.get_managed(out["id"])
    offset, rebuilt = 0, ""
    for _ in range(500):
        page = pt.read_output(managed, "stdout", offset, 101)
        assert len(page["text"].encode("utf-8")) <= 101
        rebuilt += page["text"]
        offset = page["next_offset"]
        if page["eof"]:
            break
    else:
        pytest.fail("pagination did not reach EOF within 500 pages")
    assert rebuilt.strip() == "ж" * 5000
    assert "\ufffd" not in rebuilt                                   # no page ever split a character


def test_output_paging_error_contract(work):
    managed = pt.get_managed(_run(work, "print('ж'*50)")["id"])
    with pytest.raises(PolicyError, match="NOT_CHARACTER_ALIGNED"):
        pt.read_output(managed, "stdout", 1, 10)
    with pytest.raises(PolicyError, match="PAGE_LIMIT_TOO_SMALL"):
        pt.read_output(managed, "stdout", 0, 1)
    with pytest.raises(PolicyError, match="OFFSET_BEYOND_END"):
        pt.read_output(managed, "stdout", 10_000, 10)
    for bad in (-1, True, "0", 1.5):
        with pytest.raises(PolicyError, match="INVALID_OFFSET"):
            pt.read_output(managed, "stdout", bad, 10)
    with pytest.raises(PolicyError, match="INVALID_STREAM"):
        pt.read_output(managed, "stdin", 0, 10)


def test_output_cap_stops_runaway_process(work, native_overlay):
    native_overlay(limits={"max_output_bytes_per_stream": 100_000})
    out = _run(work, "import sys\nwhile True: sys.stdout.write('x'*10000)", timeout_s=30)
    assert out["state"] == "output_limit"
    meta = pt.get_managed(out["id"]).meta
    assert meta["output_truncated"] is True and not procs.is_alive(meta["pid"], meta["created"])


def test_command_cancel_and_history(work):
    started = ct.command_start(shell="exec", argv=[PY, "-c", SLEEP], cwd=str(work), mode="workspace_write")
    assert started["status"] == "STARTED"
    cid = started["id"]
    assert ct.command_status(cid)["terminal"] is False
    result = ct.command_cancel(cid)
    assert result["state"] == "stopped"
    assert ct.command_status(cid)["terminal"] is True
    assert cid in [row["id"] for row in ct.command_history(10)["commands"]]
    assert cid in [row["id"] for row in ct.command_history(10, state="stopped")["commands"]]
    assert ct.command_history(10, state="exited")["commands"] == []
    with pytest.raises(PolicyError, match="WRONG_PROCESS_KIND"):
        pt.process_status(cid)


# ---------------------------------------------------- managed (process_*) tools
def test_stop_refuses_unmanaged_and_wrong_kind_and_verifies_identity(work):
    started = _start_process(work)
    pid_id = started["id"]
    managed = pt.get_managed(pid_id, "process")
    pid, created = managed.meta["pid"], managed.meta["created"]
    status = pt.process_status(pid_id)
    assert status["alive_verified"] is True and status["state"] == "running"
    assert pt.process_inspect(pid)["managed_id"] == pid_id
    with pytest.raises(PolicyError, match="PROCESS_NOT_FOUND"):
        pt.process_stop("prc-" + "0" * 16)
    with pytest.raises(PolicyError, match="INVALID_PROCESS_ID"):
        pt.process_stop("notanid")
    with pytest.raises(PolicyError, match="WRONG_PROCESS_KIND"):
        ct.command_cancel(pid_id)
    result = pt.process_stop(pid_id)
    assert result["state"] == "stopped" and result["kill_verified"] is True
    assert not procs.is_alive(pid, created)
    assert pt.process_stop(pid_id)["already_ended"] is True


def test_process_stop_kills_grandchild(work):
    started = _start_process(work, GRANDCHILD)
    grandchild = _printed_pid(started["id"])
    assert procs.is_alive(grandchild)
    result = pt.process_stop(started["id"])
    assert result["state"] == "stopped"
    assert _wait(lambda: not procs.is_alive(grandchild))


def test_process_start_modes_and_slot_limit(work, native_overlay):
    with pytest.raises(PolicyError, match="PROCESS_START_REQUIRES_WORKSPACE_OR_ELEVATED_MODE"):
        pt.process_start(PY, ["-c", "pass"], cwd=str(work), mode="read_only")
    native_overlay(limits={"max_managed_processes": 1})
    first = _start_process(work)
    with pytest.raises(PolicyError, match="TOO_MANY_MANAGED_PROCESSES"):
        pt.process_start(PY, ["-c", SLEEP], cwd=str(work))
    pt.process_stop(first["id"])
    second = _start_process(work)                         # the slot really was released by the stop
    pt.process_stop(second["id"])


def test_process_list_and_inspect_contract():
    listing = pt.process_list(limit_rows=5)
    assert listing["returned"] <= 5 and listing["count"] >= listing["returned"]
    info = pt.process_inspect(os.getpid())
    assert info["exists"] and info["created_filetime"] and info["image_path"]
    for bad in (0, -1, True, "1"):
        with pytest.raises(PolicyError, match="INVALID_PID"):
            pt.process_inspect(bad)
    unused = max(r["pid"] for r in procs.snapshot()) + 100_000
    assert pt.process_inspect(unused) == {"pid": unused, "exists": False}


def test_pid_reuse_cannot_kill_other_process():
    me = procs.creation_time(os.getpid())
    assert procs.terminate_exact(os.getpid(), (me or 0) + 12345) is False
    assert procs.is_alive(os.getpid(), me)
    assert procs.is_alive(os.getpid(), (me or 0) + 1) is False


# ------------------------------------------------------ recovery and adoption
def _foreign_process():
    """A live process that was NOT launched through the managed layer (stands in for a pre-restart child)."""
    proc = subprocess.Popen([PY, "-c", "import time;time.sleep(120)"], stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    assert _wait(lambda: procs.creation_time(proc.pid) and procs.image_path(proc.pid), 10)
    return proc


def _write_record(state, rid, work, **override):
    directory = state / "procs" / rid
    directory.mkdir(parents=True)
    meta = {"id": rid, "kind": "process", "label": "recorded", "state": "running", "mode": "workspace_write",
            "exe": "C:\\x\\recorded.exe", "summary": {}, "cwd": str(work), "owner": procs.current_user(),
            "approval_id": None, "started_at": common.iso(), "ended_at": None, "pid": None, "created": None,
            "timeout_s": 120, "exit_code": None, "stop_reason": None, "output_truncated": False,
            "children_seen": [], "recovered": False, "job_assigned": False, "kill_verified": None}
    meta.update(override)
    (directory / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    return directory


def _disk_meta(directory):
    return json.loads((directory / "meta.json").read_text(encoding="utf-8"))


def _audit_text(state):
    return (state / "audit" / "native-audit.jsonl").read_text(encoding="utf-8")


def test_recovery_marks_lost_process(isolated_state, work):
    directory = _write_record(isolated_state, "prc-aaaaaaaaaaaaaaaa", work, pid=999999, created=1)
    assert pt._RECOVERED is False
    pt.ensure_recovered()
    meta = _disk_meta(directory)
    assert meta["state"] == "exited_unknown" and meta["stop_reason"] == "lost_across_restart" and meta["ended_at"]
    assert '"status": "LOST"' in _audit_text(isolated_state)
    assert "prc-aaaaaaaaaaaaaaaa" not in pt._REGISTRY and pt._RECOVERED is True


def test_recovery_adopts_live_process_by_identity_and_can_stop_it(isolated_state, work):
    proc = _foreign_process()
    try:
        directory = _write_record(isolated_state, "prc-1111111111111111", work, pid=proc.pid,
                                  created=procs.creation_time(proc.pid), exe=procs.image_path(proc.pid))
        pt.ensure_recovered()
        managed = pt._REGISTRY["prc-1111111111111111"]
        assert managed.popen is None and managed.meta["recovered"] is True and managed.kill_orphans is False
        status = pt.process_status("prc-1111111111111111")
        assert status["alive_verified"] is True and status["recovered"] is True and status["state"] == "running"
        assert _disk_meta(directory)["recovered"] is True
        assert '"status": "ADOPTED"' in _audit_text(isolated_state)
        result = pt.process_stop("prc-1111111111111111")
        assert result["state"] == "stopped" and result["kill_verified"] is True
        assert proc.wait(timeout=10) is not None
    finally:
        proc.kill()


def test_adopted_process_exit_is_noticed(isolated_state, work):
    proc = _foreign_process()
    try:
        _write_record(isolated_state, "prc-2222222222222222", work, pid=proc.pid,
                      created=procs.creation_time(proc.pid), exe=procs.image_path(proc.pid))
        pt.ensure_recovered()
        managed = pt._REGISTRY["prc-2222222222222222"]
        proc.kill()
        proc.wait(timeout=10)
        assert managed.done.wait(15)
        assert managed.meta["state"] == "exited_unknown"
    finally:
        proc.kill()


def test_adoption_does_not_extend_the_original_timeout(isolated_state, work):
    proc = _foreign_process()
    try:
        started = common.iso(common.utcnow() - timedelta(seconds=100))
        _write_record(isolated_state, "prc-3333333333333333", work, pid=proc.pid, created=procs.creation_time(proc.pid),
                      exe=procs.image_path(proc.pid), timeout_s=1, started_at=started)
        pt.ensure_recovered()
        managed = pt._REGISTRY["prc-3333333333333333"]
        assert managed.done.wait(20)
        assert managed.meta["state"] == "timed_out"
        assert proc.wait(timeout=10) is not None
    finally:
        proc.kill()


def test_recovery_never_adopts_or_kills_a_process_with_a_different_image(isolated_state, work):
    proc = _foreign_process()
    try:
        directory = _write_record(isolated_state, "prc-4444444444444444", work, pid=proc.pid,
                                  created=procs.creation_time(proc.pid), exe="C:\\somewhere\\else.exe")
        pt.ensure_recovered()
        assert _disk_meta(directory)["state"] == "exited_unknown"
        assert "prc-4444444444444444" not in pt._REGISTRY
        assert proc.poll() is None                              # an unrelated live process is left alone
    finally:
        proc.kill()


def test_recovery_ignores_record_of_another_incarnation_of_the_pid(isolated_state, work):
    proc = _foreign_process()
    try:
        created = procs.creation_time(proc.pid)
        directory = _write_record(isolated_state, "prc-5555555555555555", work, pid=proc.pid, created=created + 1,
                                  exe=procs.image_path(proc.pid), state="starting")
        pt.ensure_recovered()
        assert _disk_meta(directory)["state"] == "exited_unknown"
        assert proc.poll() is None                              # creation time differs: pid was recycled, not ours
    finally:
        proc.kill()


def test_recovery_kills_process_left_uncontained_by_a_crash_mid_launch(isolated_state, work):
    proc = _foreign_process()
    try:
        directory = _write_record(isolated_state, "prc-6666666666666666", work, pid=proc.pid,
                                  created=procs.creation_time(proc.pid), exe=procs.image_path(proc.pid),
                                  state="starting")
        pt.ensure_recovered()
        assert proc.wait(timeout=10) is not None
        assert _disk_meta(directory)["state"] == "exited_unknown"
    finally:
        proc.kill()


def test_one_corrupt_record_does_not_block_recovery_of_the_others(isolated_state, work):
    bad = isolated_state / "procs" / "prc-bbbbbbbbbbbbbbbb"
    bad.mkdir(parents=True)
    (bad / "meta.json").write_text("{not json", encoding="utf-8")
    (isolated_state / "procs" / "not-a-process-dir").mkdir()
    good = _write_record(isolated_state, "prc-cccccccccccccccc", work, pid=999999, created=1)
    pt.ensure_recovered()
    assert _disk_meta(good)["state"] == "exited_unknown"
    assert (bad / "meta.json").read_text(encoding="utf-8") == "{not json"
    assert '"status": "SKIPPED_CORRUPT"' in _audit_text(isolated_state)
    assert pt._RECOVERED is True


def test_recovery_runs_once_per_process(isolated_state, work):
    pt.ensure_recovered()
    late = _write_record(isolated_state, "prc-dddddddddddddddd", work, pid=999999, created=1)
    pt.ensure_recovered()
    assert _disk_meta(late)["state"] == "running"               # second call is a no-op by design


def test_stop_refuses_records_owned_by_another_user(isolated_state, work):
    _write_record(isolated_state, "prc-eeeeeeeeeeeeeeee", work, state="exited", owner="OTHERDOMAIN\\someone",
                  ended_at=common.iso(), exit_code=0)
    with pytest.raises(PolicyError, match="PROCESS_OWNER_MISMATCH"):
        pt.process_stop("prc-eeeeeeeeeeeeeeee")
