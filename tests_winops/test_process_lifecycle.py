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


def _write_record(sdir, rid, work, **override):
    directory = sdir / "procs" / rid
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


# ------------------------------------------- canonical redacted paging (F02)
SECRET_PROGRAM = (
    "print('start-marker');"
    "print('password=SENSITIVE_VALUE_123');"
    "print('Authorization: Bearer abcDEF123456tokenSECRETxyz');"
    "print('Server=db01;Database=acc;User Id=sa;Password=ConnSECRETvalue987;');"
    "print('end-marker')")
SECRET_VALUES = ("SENSITIVE_VALUE_123", "abcDEF123456tokenSECRETxyz", "ConnSECRETvalue987")


def _all_pages(managed, length, start=0):
    offset, text = start, ""
    for _ in range(2000):
        page = pt.read_output(managed, "stdout", offset, length)
        text += page["text"]
        if page["next_offset"] == offset or page["eof"]:
            break
        offset = page["next_offset"]
    return text


def _assert_no_secret(text):
    for secret in SECRET_VALUES:
        assert secret not in text, secret


def test_paging_never_exposes_a_secret_for_any_offset_and_length(work):
    managed = pt.get_managed(_run(work, SECRET_PROGRAM)["id"])
    full = _all_pages(managed, 4096)
    _assert_no_secret(full)
    assert "start-marker" in full and "end-marker" in full and "password=***" in full     # control: redaction, not loss
    size = pt.read_output(managed, "stdout", 0, 1)["size"]
    assert size == len(full.encode("utf-8")) and size > 100                               # offsets are redacted-text offsets
    for length in range(1, 65):
        for offset in range(0, size + 1):
            _assert_no_secret(pt.read_output(managed, "stdout", offset, length)["text"])
        _assert_no_secret(_all_pages(managed, length))                                   # concatenation of pages too
    for start in range(0, size, 3):                                                        # tails from every start
        tail = _all_pages(managed, 7, start)
        _assert_no_secret(tail)
        assert tail == full[start:]


def test_paging_stays_redacted_after_cache_clear_and_recovery(isolated_state, work):
    out = _run(work, SECRET_PROGRAM)
    managed = pt.get_managed(out["id"])
    pt._CANON_CACHE.clear()
    _assert_no_secret(_all_pages(managed, 5))
    for offset in range(0, pt.read_output(managed, "stdout", 0, 1)["size"] + 1):
        _assert_no_secret(pt.read_output(managed, "stdout", offset, 9)["text"])
    with pt._REG_LOCK:
        pt._REGISTRY.clear()
    pt._RECOVERED = False
    pt._CANON_CACHE.clear()
    pt.ensure_recovered()
    historical = pt.get_managed(out["id"])
    assert historical is not managed
    _assert_no_secret(_all_pages(historical, 3))
    assert "password=***" in _all_pages(historical, 4096)
    assert SECRET_VALUES[0] in (managed.dir / "stdout.log").read_text(encoding="utf-8")   # raw log keeps it; only reads redact


def test_running_process_exposes_only_complete_lines(work):
    code = ("import sys,time;print('done-line',flush=True);"
            "sys.stdout.write('password=HALFWRITTENSECRET');sys.stdout.flush();time.sleep(60)")
    started = _start_process(work, code)
    managed = pt.get_managed(started["id"], "process")
    assert _wait(lambda: (managed.dir / "stdout.log").exists()
                 and b"HALFWRITTEN" in (managed.dir / "stdout.log").read_bytes(), 20)
    page = pt.read_output(managed, "stdout", 0, 4096)
    assert page["text"].strip() == "done-line" and page["eof"] is False
    assert page["size"] == len(page["text"].encode("utf-8")) and page["next_offset"] == page["size"]
    assert "HALFWRITTEN" not in page["text"]
    pt.process_stop(started["id"])
    after = pt.read_output(managed, "stdout", 0, 4096)                                    # finished: remainder becomes visible
    assert "HALFWRITTENSECRET" not in after["text"] and "password=***" in after["text"] and after["eof"] is True


# ------------------------------------------------- tree kill / detach / orphans (F09)
# The root prints its child's pid, waits until the harness has seen it, and exits; the child outlives it
# unless the managed layer kills the tree.
ROOT_EXITS_LEAVING_CHILD = (
    "import subprocess,sys,time;"
    "g=subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)']);"
    "print(g.pid,flush=True);time.sleep(2)")


def test_default_process_start_kills_the_tree_when_the_root_exits(work):
    started = _start_process(work, ROOT_EXITS_LEAVING_CHILD)
    assert "detach" not in pt.get_managed(started["id"]).meta["summary"]
    child = _printed_pid(started["id"])
    managed = pt.get_managed(started["id"], "process")
    assert managed.done.wait(30)
    assert managed.meta["state"] == "exited" and managed.kill_orphans is True and managed.meta["orphans"] == []
    assert _wait(lambda: not procs.is_alive(child), 15)             # child pid printed by the parent is dead


def _detached(work, approvals_ready_fixture=None):
    pending = pt.process_start(PY, ["-c", ROOT_EXITS_LEAVING_CHILD], cwd=str(work), timeout_s=120, detach=True)
    assert pending["status"] == "APPROVAL_REQUIRED", pending
    return pending


def test_detach_always_requires_an_approval_bound_to_detach(work, approvals_ready):
    # PY is a trusted dev tool in this module, so only detach can be the reason approval is demanded.
    plain = pt.process_start(PY, ["-c", "pass"], cwd=str(work), timeout_s=120)
    assert plain["status"] == "STARTED"
    pending = _detached(work)
    request = json.loads((common.approvals_dir() / (pending["approval_id"] + ".json")).read_text(encoding="utf-8"))
    assert '"detach":true' in request["params_display"].replace(" ", "")
    common.grant_approval(pending["approval_id"])
    # the non-detached launch of the same command needs no approval at all, so the detach grant is never consumed by it
    plain_same = pt.process_start(PY, ["-c", ROOT_EXITS_LEAVING_CHILD], cwd=str(work), timeout_s=120,
                                  approval_id=pending["approval_id"])
    assert plain_same["status"] == "STARTED"
    assert not (common.approvals_dir() / (pending["approval_id"] + ".used")).exists()


def test_detached_orphans_are_recorded_stopped_and_survive_recovery(isolated_state, work, approvals_ready):
    pending = _detached(work)
    common.grant_approval(pending["approval_id"])
    started = pt.process_start(PY, ["-c", ROOT_EXITS_LEAVING_CHILD], cwd=str(work), timeout_s=120, detach=True,
                               approval_id=pending["approval_id"])
    assert started["status"] == "STARTED"
    child = _printed_pid(started["id"])
    managed = pt.get_managed(started["id"], "process")
    assert managed.done.wait(30) and managed.kill_orphans is False
    assert procs.is_alive(child)                                        # detach: the descendant outlived the root
    orphans = managed.meta["orphans"]
    assert child in [o["pid"] for o in orphans]                         # (a venv launcher may add an intermediate pid)
    assert next(o for o in orphans if o["pid"] == child)["created"] == procs.creation_time(child)
    assert _disk_meta(isolated_state / "procs" / started["id"])["orphans"] == orphans     # durable

    # a restart (empty registry, recovery re-run) still knows the orphan and stops it by exact identity
    with pt._REG_LOCK:
        pt._REGISTRY.clear()
    pt._RECOVERED = False
    pt.ensure_recovered()
    result = pt.process_stop(started["id"])
    assert result["already_ended"] is True and child in result["orphans_stopped"]
    assert _wait(lambda: not procs.is_alive(child), 15)
    assert _disk_meta(isolated_state / "procs" / started["id"])["orphans"] == []
    assert pt.process_stop(started["id"])["orphans_stopped"] == []


def test_orphan_stop_never_kills_a_process_with_a_different_creation_time(isolated_state, work):
    proc = _foreign_process()
    try:
        directory = _write_record(isolated_state, "prc-7777777777777777", work, state="exited", ended_at=common.iso(),
                                  exit_code=0, orphans=[{"pid": proc.pid, "created": procs.creation_time(proc.pid) + 1}])
        result = pt.process_stop("prc-7777777777777777")
        assert result["already_ended"] is True and result["orphans_stopped"] == []
        assert proc.poll() is None                                       # recycled-pid look-alike is left alone
        assert _disk_meta(directory)["orphans"] == []
    finally:
        proc.kill()


def test_restart_while_the_detached_parent_is_alive_keeps_gap_free_job_ownership(isolated_state, work, approvals_ready):
    pending = pt.process_start(PY, ["-c", GRANDCHILD], cwd=str(work), timeout_s=120, detach=True)
    assert pending["status"] == "APPROVAL_REQUIRED"
    common.grant_approval(pending["approval_id"])
    started = pt.process_start(PY, ["-c", GRANDCHILD], cwd=str(work), timeout_s=120, detach=True,
                               approval_id=pending["approval_id"])
    child = _printed_pid(started["id"])
    assert _disk_meta(isolated_state / "procs" / started["id"])["job_name"].startswith("Local\pdc-job-prc-")
    with pt._REG_LOCK:                                                  # backend restart: registry and job handle are gone
        old = pt._REGISTRY.pop(started["id"])
    old.cancel.set()
    pt._RECOVERED = False
    pt.ensure_recovered()
    adopted = pt.get_managed(started["id"], "process")
    assert adopted.meta["recovered"] is True and adopted.meta["containment"] == "job"
    assert child in adopted.job.pids()                                  # membership straight from the kernel job, no scan gap
    result = pt.process_stop(started["id"])
    assert _wait(lambda: not procs.is_alive(child) and not procs.is_alive(adopted.meta["pid"], adopted.meta["created"]), 15)
    assert result["state"] in ("stopped", "exited_unknown", "exited") or result.get("already_ended")


def test_a_detached_record_without_a_job_name_is_reported_as_incompletely_contained(isolated_state, work):
    proc = _foreign_process()
    try:
        _write_record(isolated_state, "prc-8888888888888888", work, state="running", exe=PY, pid=proc.pid,
                      created=procs.creation_time(proc.pid))
        pt._RECOVERED = False
        pt.ensure_recovered()
        meta = pt.get_managed("prc-8888888888888888", "process").meta
        assert meta["containment"] == "scan_only_incomplete"
    finally:
        proc.kill()


def _dead_root_with_job_survivor(isolated_state, work, rid, state):
    """A finished root + a live child that still belongs to the named job: what a restart finds after the parent died."""
    root = subprocess.Popen([PY, "-c", "pass"], stdin=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
    root_created = procs.creation_time(root.pid)
    root.wait(10)
    name = "Local\\pdc-job-" + rid
    job = procs.Job(name=name, hosted=True)
    child = subprocess.Popen([PY, "-c", "import time;time.sleep(120)"], stdin=subprocess.DEVNULL,
                             creationflags=subprocess.CREATE_NO_WINDOW)
    assert _wait(lambda: procs.creation_time(child.pid), 10)
    assert job.assign(int(child._handle))
    _write_record(isolated_state, rid, work, state=state, exe=PY, pid=root.pid, created=root_created, job_name=name,
                  job_holder={"pid": job.holder_pid, "created": job.holder_created})
    return job, child


def test_recovery_with_an_already_exited_root_records_job_survivors_and_stop_terminates_them(isolated_state, work):
    rid = "prc-9999999999999999"
    job, child = _dead_root_with_job_survivor(isolated_state, work, rid, "running")
    try:
        pt._RECOVERED = False
        pt.ensure_recovered()                                       # the root is dead; the named job still has a member
        meta = _disk_meta(isolated_state / "procs" / rid)
        assert meta["state"] == "exited_unknown" and meta["containment"] == "job"
        assert child.pid in [o["pid"] for o in meta["orphans"]]
        job.close()                                                  # the old backend's handle is gone: only the name remains
        result = pt.process_stop(rid)                                # original managed id, no PID sampling needed
        assert child.pid in result["orphans_stopped"]
        assert _wait(lambda: child.poll() is not None, 15)
        assert _disk_meta(isolated_state / "procs" / rid)["orphans"] == []
    finally:
        child.kill()


def test_stop_of_a_terminal_record_uses_job_membership_not_only_recorded_pids(isolated_state, work):
    rid = "prc-9999999999999998"
    job, child = _dead_root_with_job_survivor(isolated_state, work, rid, "exited")    # no orphans were ever recorded
    try:
        assert _disk_meta(isolated_state / "procs" / rid).get("orphans") in (None, [])
        result = pt.process_stop(rid)
        assert child.pid in result["orphans_stopped"]
        assert _wait(lambda: child.poll() is not None, 15)
    finally:
        job.close()
        child.kill()


def test_job_with_more_than_256_members_is_fully_enumerated_and_terminated(isolated_state, work):
    rid = "prc-9999999999999997"
    ping = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "PING.EXE")
    root = subprocess.Popen([PY, "-c", "pass"], stdin=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
    root_created = procs.creation_time(root.pid)
    root.wait(10)
    name = "Local\\pdc-job-" + rid
    job = procs.Job(name=name, hosted=True)
    foreign = _foreign_process()                                           # unrelated: must survive
    members = []
    try:
        for _ in range(270):
            member = subprocess.Popen([ping, "-n", "120", "127.0.0.1"], stdin=subprocess.DEVNULL,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                      creationflags=subprocess.CREATE_NO_WINDOW)
            members.append(member)
            assert job.assign(int(member._handle))
        listed = job.pids()
        assert job.query_ok and len(listed) >= 270                         # buffer grew past 256 instead of returning []
        _write_record(isolated_state, rid, work, state="running", exe=PY, pid=root.pid, created=root_created, job_name=name,
                      job_holder={"pid": job.holder_pid, "created": job.holder_created})
        job.close()
        pt._RECOVERED = False
        pt.ensure_recovered()                                              # dead parent, empty orphan list, 270 members
        meta = _disk_meta(isolated_state / "procs" / rid)
        assert meta["state"] == "exited_unknown" and len(meta["orphans"]) >= 270
        result = pt.process_stop(rid)
        assert len(result["orphans_stopped"]) >= 270
        assert _wait(lambda: all(m.poll() is not None for m in members), 30)
        assert foreign.poll() is None
    finally:
        for member in members:
            member.kill()
        foreign.kill()


def test_holder_must_break_away_from_a_parent_job_or_the_detached_launch_fails_closed(monkeypatch):
    real = subprocess.Popen
    seen = []

    def deny_breakaway(args, *a, **kw):
        flags = kw.get("creationflags", 0)
        seen.append(flags)
        if flags & procs.CREATE_BREAKAWAY_FROM_JOB:
            raise PermissionError(5, "Access is denied")                  # parent job forbids breakaway
        return real(args, *a, **kw)

    monkeypatch.setattr(procs.subprocess, "Popen", deny_breakaway)
    with pytest.raises(PolicyError, match="JOB_HOLDER_NOT_INDEPENDENT_OF_PARENT_JOB"):
        procs.Job(name="Local\\pdc-job-prc-1111111111111111", hosted=True, require_independent_holder=True)
    soft = procs.Job(name="Local\\pdc-job-prc-2222222222222222", hosted=True)         # non-detached users only get a flag
    try:
        assert soft.holder_independent is False
    finally:
        soft.terminate()
        soft.close()
    assert any(f & procs.CREATE_BREAKAWAY_FROM_JOB for f in seen)


def test_holder_normally_breaks_away_and_is_reported_independent(isolated_state):
    job = procs.Job(name="Local\\pdc-job-prc-3333333333333333", hosted=True, require_independent_holder=True)
    try:
        assert job.holder_independent is True
    finally:
        job.close()


def _assert_durable_failure(isolated_state, rid, result, reason):
    assert result["status"] == "STOP_INCOMPLETE" and result["stop_incomplete"] == reason
    assert _disk_meta(isolated_state / "procs" / rid)["stop_incomplete"] == reason          # persisted, not only returned
    assert pt.get_managed(rid, "process").meta["stop_incomplete"] == reason


def test_unreachable_job_with_unproven_emptiness_is_a_durable_explicit_failure(isolated_state, work):
    rid = "prc-9999999999999996"
    _write_record(isolated_state, rid, work, state="exited", exe=PY, pid=1, created=1,
                  job_name="Local\\pdc-job-" + rid + "-gone")            # nothing holds this name any more
    result = pt.process_stop(rid)
    _assert_durable_failure(isolated_state, rid, result, "JOB_UNREACHABLE")
    assert _disk_meta(isolated_state / "procs" / rid)["containment"] == "job_unreachable"


def test_a_job_observed_empty_is_clean_and_a_later_stop_is_an_ordinary_success(isolated_state, work):
    rid = "prc-9999999999999995"
    _write_record(isolated_state, rid, work, state="exited", exe=PY, pid=1, created=1,
                  job_name="Local\\pdc-job-" + rid + "-gone", job_clean=True)
    result = pt.process_stop(rid)
    assert result.get("status") is None and result["orphans_stopped"] == []


def test_terminate_failure_and_membership_query_failure_are_durable_failures(isolated_state, work, monkeypatch):
    rid = "prc-9999999999999994"
    job, child = _dead_root_with_job_survivor(isolated_state, work, rid, "exited")
    try:
        with monkeypatch.context() as m:
            m.setattr(procs.Job, "terminate", lambda self, exit_code=1: False)
            m.setattr(procs, "terminate_tree", lambda pid, created: [])          # the identity fallback fails too
            result = pt.process_stop(rid)
        _assert_durable_failure(isolated_state, rid, result, "TERMINATE_JOB_FAILED")
        assert child.poll() is None                                          # nothing was killed, and we said so
        real_pids = procs.Job.pids

        def failing(self):
            real_pids(self)
            self.query_ok = False
            return []

        with monkeypatch.context() as m:
            m.setattr(procs.Job, "pids", failing)
            result = pt.process_stop(rid)
        _assert_durable_failure(isolated_state, rid, result, "MEMBERSHIP_QUERY_FAILED")
    finally:
        job.close()
        child.kill()


def test_job_terminate_failure_is_success_only_when_the_identity_fallback_verifiably_finished_the_job(isolated_state, work, monkeypatch):
    rid = "prc-9999999999999993"
    job, child = _dead_root_with_job_survivor(isolated_state, work, rid, "exited")
    try:
        with monkeypatch.context() as m:
            m.setattr(procs.Job, "terminate", lambda self, exit_code=1: False)
            result = pt.process_stop(rid)
        assert result.get("status") is None and child.pid in result["orphans_stopped"]
        assert _wait(lambda: child.poll() is not None, 15)
        assert "stop_incomplete" not in _disk_meta(isolated_state / "procs" / rid)
    finally:
        job.close()
        child.kill()


def test_expired_terminal_record_with_a_live_job_member_is_not_pruned_and_stays_addressable(isolated_state, work):
    rid = "prc-9999999999999992"
    job, child = _dead_root_with_job_survivor(isolated_state, work, rid, "exited")
    directory = isolated_state / "procs" / rid
    old = time.time() - 40 * 86400
    os.utime(directory / "meta.json", (old, old))                         # far past the retention period
    try:
        pt._RECOVERED = False
        pt.ensure_recovered()                                              # recovery runs BEFORE cleanup
        assert directory.is_dir()
        result = pt.process_stop(rid)                                      # still addressable by its original id
        assert child.pid in result["orphans_stopped"]
        assert _wait(lambda: child.poll() is not None, 15)
        # now provably empty: the next cleanup may expire it
        os.utime(directory / "meta.json", (old, old))
        pt._prune_old()
        assert not directory.exists()
    finally:
        job.close()
        child.kill()


def test_expired_record_with_unverified_job_or_stop_failure_is_kept_but_clean_ones_expire(isolated_state, work):
    keep_unreachable = _write_record(isolated_state, "prc-9999999999999991", work, state="exited", exe=PY, pid=1, created=1,
                                     job_name="Local\\pdc-job-prc-9999999999999991", job_holder={"pid": 1, "created": 1})
    keep_failed = _write_record(isolated_state, "prc-9999999999999990", work, state="exited", exe=PY, pid=1, created=1,
                                stop_incomplete="TERMINATE_JOB_FAILED")
    drop_clean = _write_record(isolated_state, "prc-9999999999999989", work, state="exited", exe=PY, pid=1, created=1,
                               job_name="Local\\pdc-job-prc-9999999999999989", job_clean=True)
    drop_plain = _write_record(isolated_state, "prc-9999999999999988", work, state="exited", exe=PY, pid=1, created=1)
    old = time.time() - 40 * 86400
    for directory in (keep_unreachable, keep_failed, drop_clean, drop_plain):
        os.utime(directory / "meta.json", (old, old))
    pt._prune_old()
    assert keep_unreachable.is_dir() and keep_failed.is_dir()
    assert not drop_clean.exists() and not drop_plain.exists()


def test_holder_clean_marker_is_durable_proof_and_lets_a_record_expire(isolated_state, work):
    rid = "prc-9999999999999987"
    directory = _write_record(isolated_state, rid, work, state="exited", exe=PY, pid=1, created=1,
                              job_name="Local\\pdc-job-" + rid, job_holder={"pid": 1, "created": 1})
    (directory / "holder.clean").write_text("clean", encoding="ascii")
    result = pt.process_stop(rid)
    assert result.get("status") is None                                    # clean proof => not "unreachable"
    os.utime(directory / "meta.json", (time.time() - 40 * 86400,) * 2)
    pt._prune_old()
    assert not directory.exists()


def test_a_real_holder_writes_the_clean_marker_when_the_job_empties(isolated_state, work):
    marker = isolated_state / "holder.clean"
    job = procs.Job(name="Local\\pdc-job-prc-9999999999999986", hosted=True, holder_marker=str(marker))
    holder = (job.holder_pid, job.holder_created)
    member = subprocess.Popen([PY, "-c", "import time;time.sleep(1)"], stdin=subprocess.DEVNULL,
                              creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        assert job.assign(int(member._handle))
        member.wait(15)
        assert _wait(lambda: marker.is_file(), 20)
        assert _wait(lambda: not procs.is_alive(*holder), 20)              # and the holder exits afterwards
    finally:
        job.close()
        member.kill()


def test_a_job_re_created_under_the_same_name_is_never_terminated_for_a_finished_record(isolated_state, work):
    rid = "prc-9999999999999985"
    name = "Local\\pdc-job-" + rid
    original = procs.Job(name=name, hosted=True)
    holder = {"pid": original.holder_pid, "created": original.holder_created}
    member = subprocess.Popen([PY, "-c", "import time;time.sleep(1)"], stdin=subprocess.DEVNULL,
                              creationflags=subprocess.CREATE_NO_WINDOW)
    assert original.assign(int(member._handle))
    member.wait(15)                                                        # the job had a member and is empty again
    original.close()
    assert _wait(lambda: not procs.is_alive(holder["pid"], holder["created"]), 20)       # original job and holder are gone
    _write_record(isolated_state, rid, work, state="exited", exe=PY, pid=1, created=1, job_name=name, job_holder=holder)
    impostor_job = procs.Job(name=name)                                    # someone else re-uses the free name
    bystander = _foreign_process()
    try:
        assert impostor_job.assign(int(bystander._handle))
        result = pt.process_stop(rid)
        assert result["status"] == "STOP_INCOMPLETE" and result["stop_incomplete"] == "JOB_UNREACHABLE"
        assert bystander.poll() is None                                    # the unrelated process was NOT terminated
    finally:
        impostor_job.close()
        bystander.kill()


def _expired_terminal_record_with_member(isolated_state, work, rid, root_created_delta, **extra):
    """Terminal record whose recorded root pid is a LIVE member of its (hosted) job, as after a failed root kill."""
    job = procs.Job(name="Local\\pdc-job-" + rid, hosted=True)
    member = subprocess.Popen([PY, "-c", "import time;time.sleep(120)"], stdin=subprocess.DEVNULL,
                              creationflags=subprocess.CREATE_NO_WINDOW)
    assert _wait(lambda: procs.creation_time(member.pid), 10)
    assert job.assign(int(member._handle))
    directory = _write_record(isolated_state, rid, work, state="exited", exe=PY, pid=member.pid,
                              created=procs.creation_time(member.pid) + root_created_delta,
                              job_name="Local\\pdc-job-" + rid,
                              job_holder={"pid": job.holder_pid, "created": job.holder_created}, **extra)
    old = time.time() - 40 * 86400
    os.utime(directory / "meta.json", (old, old))
    return job, member, directory


@pytest.mark.parametrize("delta, extra", [
    (0, {"kill_verified": False}),            # the root is still alive and its termination was never verified
    (0, {}),                                  # root alive, terminal state recorded anyway
    (1, {}),                                  # same PID, different creation time: a stranger, still a live member
])
def test_retention_never_discards_a_record_while_its_job_still_has_a_live_member(isolated_state, work, delta, extra):
    rid = "prc-9999999999999984"
    job, member, directory = _expired_terminal_record_with_member(isolated_state, work, rid, delta, **extra)
    try:
        pt._prune_old()
        assert directory.is_dir()                                          # kept: addressable by the original id
        pt._RECOVERED = False
        pt.ensure_recovered()
        assert directory.is_dir()
        result = pt.process_stop(rid)
        assert member.pid in result["orphans_stopped"] or _wait(lambda: member.poll() is not None, 15)
        assert _wait(lambda: member.poll() is not None, 15)
    finally:
        job.close()
        member.kill()


def test_reused_root_pid_is_not_mistaken_for_the_root_when_reconciling(isolated_state, work):
    rid = "prc-9999999999999983"
    job, member, directory = _expired_terminal_record_with_member(isolated_state, work, rid, 1)
    try:
        meta = pt.get_managed(rid, "process").meta
        assert pt._is_root(meta, member.pid) is False                      # same pid, other creation time
        meta["created"] = procs.creation_time(member.pid)
        assert pt._is_root(meta, member.pid) is True
    finally:
        job.close()
        member.kill()
