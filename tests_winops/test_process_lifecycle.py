"""Managed process lifecycle on real Windows: identity, timeout, tree kill, output paging, recovery."""
from __future__ import annotations

import sys
import time

import pytest
from personal_dc.policy import PolicyError

from dc_v2.winops import command_tools as ct
from dc_v2.winops import procs
from dc_v2.winops import process_tools as pt

PY = sys.executable


def _run(work, code, **kw):
    return ct.command_execute(shell="exec", argv=[PY, "-c", code], cwd=str(work), mode="workspace_write", **kw)


@pytest.fixture(autouse=True)
def trust_current_python(monkeypatch):
    from pathlib import Path
    monkeypatch.setenv("PDC_TEST_PY", PY)
    from dc_v2.winops import common
    real = common.native_config

    def patched():
        cfg = real()
        cfg["extra_path_dirs"] = list(cfg["extra_path_dirs"]) + [str(Path(PY).parent)]
        return cfg
    monkeypatch.setattr(common, "native_config", patched)
    monkeypatch.setattr(pt, "native_config", patched)


def test_exit_code_stdout_stderr_unicode(work):
    out = _run(work, "import sys;print('привет ✓');sys.stderr.write('err');sys.exit(3)")
    assert out["state"] == "exited" and out["exit_code"] == 3
    assert "привет ✓" in out["stdout"] and out["stderr"].strip() == "err"


def test_timeout_kills_tree(work):
    code = ("import subprocess,sys,time;subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
            "time.sleep(60)")
    start = time.monotonic()
    out = _run(work, code, timeout_s=2)
    assert out["state"] == "timed_out" and time.monotonic() - start < 20
    meta = pt.get_managed(out["id"]).meta
    time.sleep(0.5)
    assert not procs.is_alive(meta["pid"], meta["created"])
    assert all(not procs.is_alive(c, procs.creation_time(c) or 0) for c in meta["children_seen"])


def test_output_pages_are_utf8_aligned(work):
    out = _run(work, "print('ж'*5000)")
    managed = pt.get_managed(out["id"])
    offset, rebuilt = 0, ""
    for _ in range(20):
        page = pt.read_output(managed, "stdout", offset, 101)
        rebuilt += page["text"]
        offset = page["next_offset"]
        if page["eof"]:
            break
    assert rebuilt.strip() == "ж" * 5000
    with pytest.raises(PolicyError, match="NOT_CHARACTER_ALIGNED"):
        pt.read_output(managed, "stdout", 1, 10)


def test_stop_refuses_unmanaged_and_identity_checked(work):
    started = ct.command_start(shell="exec", argv=[PY, "-c", "import time;time.sleep(60)"], cwd=str(work),
                               mode="workspace_write")
    pid_id = started["id"]
    assert pt.process_status(pid_id)["alive_verified"] is True
    with pytest.raises(PolicyError):
        pt.process_stop("prc-" + "0" * 16)
    result = pt.process_stop(pid_id)
    assert result["state"] == "stopped"
    assert pt.process_stop(pid_id)["already_ended"] is True


def test_pid_reuse_cannot_kill_other_process(work):
    me = procs.creation_time(__import__("os").getpid())
    assert procs.terminate_exact(__import__("os").getpid(), (me or 0) + 12345) is False
    assert procs.is_alive(__import__("os").getpid(), me)


def test_output_cap_stops_runaway_process(work, monkeypatch):
    from dc_v2.winops import common
    real = common.native_config

    def small():
        cfg = real()
        cfg["limits"]["max_output_bytes_per_stream"] = 100_000
        return cfg
    monkeypatch.setattr(common, "native_config", small)
    monkeypatch.setattr(pt, "native_config", small)
    out = _run(work, "import sys\nwhile True: sys.stdout.write('x'*10000)", timeout_s=30)
    assert out["state"] == "output_limit"


def test_recovery_marks_lost_process(isolated_state):
    import json
    directory = isolated_state / "procs" / "prc-aaaaaaaaaaaaaaaa"
    directory.mkdir(parents=True)
    (directory / "meta.json").write_text(json.dumps({
        "id": "prc-aaaaaaaaaaaaaaaa", "state": "running", "pid": 999999, "created": 1, "exe": "x.exe",
        "kind": "process", "owner": "x", "timeout_s": 10, "children_seen": []}), encoding="utf-8")
    pt._RECOVERED = False
    pt.ensure_recovered()
    assert json.loads((directory / "meta.json").read_text(encoding="utf-8"))["state"] == "exited_unknown"


def test_process_inspect_reports_identity():
    import os
    info = pt.process_inspect(os.getpid())
    assert info["exists"] and info["created_filetime"] and info["image_path"]
