"""The real execution path through ``require_approval``: command_execute / process_start with NO trusted interpreter.

Every test here starts from the default configuration (only ``git.exe`` is an auto-trusted dev tool), so Python,
PowerShell and CMD must come back as APPROVAL_REQUIRED, and a granted approval must be bound to the exact
launch (argv, cwd, timeout, environment values, mode), single-use, time-limited and revocable.
"""
from __future__ import annotations

import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from personal_dc.policy import PolicyError

from dc_v2.winops import command_tools as ct
from dc_v2.winops import common
from dc_v2.winops import process_tools as pt

PY = sys.executable
SENT_ARG = "Zq9-SENTINEL-argpw-1357"
SENT_ENV = "envSENTINELvalue2468"
SENT_OUT = "outSENTINEL13579"

pytestmark = pytest.mark.usefixtures("approvals_ready")


def _exec(work, code="print('ok')", **kw):
    return ct.command_execute(shell="exec", argv=[PY, "-c", code], cwd=str(work), mode="workspace_write", **kw)


def _started(state):
    return sorted((state / "procs").glob("prc-*"))


def _pending(work, **kw):
    out = _exec(work, **kw)
    assert out["status"] == "APPROVAL_REQUIRED", out
    return out["approval_id"]


def _resign(rid, **changes):
    path = common.approvals_dir() / (rid + ".grant.json")
    grant = json.loads(path.read_text(encoding="utf-8"))
    grant.pop("sig")
    grant.update(changes)
    grant["sig"] = common._sign(common._approval_key(), grant)
    path.write_text(json.dumps(grant), encoding="utf-8")


def test_python_needs_approval_then_runs_exactly_once(work, isolated_state):
    rid = _pending(work)
    assert _exec(work)["approval_id"] == rid                       # identical call: same pending request, not a new one
    assert not _started(isolated_state)
    with pytest.raises(PolicyError, match="APPROVAL_NOT_GRANTED"):
        _exec(work, approval_id=rid)
    assert not _started(isolated_state)
    common.grant_approval(rid)
    out = _exec(work, approval_id=rid)
    assert out["state"] == "exited" and out["exit_code"] == 0 and "ok" in out["stdout"]
    assert len(_started(isolated_state)) == 1
    assert pt.get_managed(out["id"]).meta["approval_id"] == rid
    with pytest.raises(PolicyError, match="APPROVAL_ALREADY_USED"):
        _exec(work, approval_id=rid)                                # replay
    assert len(_started(isolated_state)) == 1                       # the replay launched nothing
    assert _pending(work) != rid                                    # a consumed request is never handed out again


def test_granted_approval_is_bound_to_the_exact_launch(work, isolated_state):
    rid = _pending(work)
    common.grant_approval(rid)
    sub = work / "sub"
    sub.mkdir()
    for kw in (dict(code="print('evil')"), dict(timeout_s=31), dict(env={"MY_FLAG": "1"})):
        with pytest.raises(PolicyError, match="APPROVAL_DIGEST_MISMATCH"):
            _exec(work, approval_id=rid, **kw)
    with pytest.raises(PolicyError, match="APPROVAL_DIGEST_MISMATCH"):
        ct.command_execute(shell="exec", argv=[PY, "-c", "print('ok')"], cwd=str(sub), mode="workspace_write",
                           approval_id=rid)
    with pytest.raises(PolicyError, match="APPROVAL_DIGEST_MISMATCH"):
        ct.command_execute(shell="exec", argv=[PY, "-c", "print('ok')"], cwd=str(work), mode="elevated",
                           approval_id=rid)
    with pytest.raises(PolicyError, match="APPROVAL_DIGEST_MISMATCH"):
        ct.command_execute("print('ok')", shell="powershell", cwd=str(work), mode="workspace_write", approval_id=rid)
    assert not _started(isolated_state)                             # none of the mismatches ran anything
    assert _exec(work, approval_id=rid)["exit_code"] == 0           # ... and none of them burned the approval


def test_environment_values_are_part_of_the_approval(work):
    rid = _pending(work, env={"MY_FLAG": "one"})
    common.grant_approval(rid)
    with pytest.raises(PolicyError, match="APPROVAL_DIGEST_MISMATCH"):
        _exec(work, env={"MY_FLAG": "two"}, approval_id=rid)
    assert _exec(work, env={"MY_FLAG": "one"}, approval_id=rid)["exit_code"] == 0


def test_denied_approval_never_runs(work, isolated_state):
    rid = _pending(work)
    common.grant_approval(rid)
    common.deny_approval(rid)
    with pytest.raises(PolicyError, match="APPROVAL_DENIED_BY_OPERATOR"):
        _exec(work, approval_id=rid)
    assert not _started(isolated_state)
    rid2 = _pending(work)
    assert rid2 != rid                                              # the operator's denial is final for that request
    common.deny_approval(rid2)
    with pytest.raises(PolicyError, match="APPROVAL_DENIED_BY_OPERATOR"):
        _exec(work, approval_id=rid2)


def test_expired_approval_never_runs(work, isolated_state):
    rid = _pending(work)
    common.grant_approval(rid)
    _resign(rid, expires_at=common.iso(common.utcnow().replace(year=2020)))
    with pytest.raises(PolicyError, match="APPROVAL_EXPIRED"):
        _exec(work, approval_id=rid)
    assert not _started(isolated_state)


def test_forged_grant_never_runs(work, isolated_state):
    rid = _pending(work)
    path = common.approvals_dir() / (rid + ".grant.json")
    pending = json.loads((common.approvals_dir() / (rid + ".json")).read_text(encoding="utf-8"))
    path.write_text(json.dumps({"id": rid, "action": pending["action"], "digest": pending["digest"],
                                "granted_at": common.iso(), "expires_at": "2999-01-01T00:00:00+00:00",
                                "grantor": "attacker", "sig": "ab" * 32}), encoding="utf-8")
    with pytest.raises(PolicyError, match="APPROVAL_SIGNATURE_INVALID"):
        _exec(work, approval_id=rid)
    assert not _started(isolated_state)


@pytest.mark.parametrize("bad", ["x", "../x", "req-", "prc-0123456789abcdef", "req-0123456789abcdef/.."])
def test_malformed_approval_id_never_runs(work, isolated_state, bad):
    with pytest.raises(PolicyError, match="INVALID_APPROVAL_ID"):
        _exec(work, approval_id=bad)
    assert not _started(isolated_state)


def test_grant_for_another_request_cannot_be_borrowed(work, isolated_state):
    rid_a = _pending(work, code="print('a')")
    rid_b = _pending(work, code="print('b')")
    common.grant_approval(rid_a)
    base = isolated_state / "approvals"
    (base / (rid_b + ".grant.json")).write_bytes((base / (rid_a + ".grant.json")).read_bytes())
    with pytest.raises(PolicyError, match="APPROVAL_GRANT_ID_MISMATCH"):
        _exec(work, code="print('b')", approval_id=rid_b)
    assert not _started(isolated_state)


def test_concurrent_calls_with_one_approval_launch_exactly_one_process(work, isolated_state):
    rid = _pending(work)
    common.grant_approval(rid)
    barrier = threading.Barrier(4)

    def attempt(_):
        barrier.wait()
        try:
            return ("ok", _exec(work, approval_id=rid))
        except PolicyError as exc:
            return ("err", str(exc))

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(attempt, range(4)))
    assert [r[0] for r in results].count("ok") == 1
    assert [r[1] for r in results if r[0] == "err"] == ["APPROVAL_ALREADY_USED"] * 3
    assert len(_started(isolated_state)) == 1


def test_process_start_path_uses_the_same_gate(work, isolated_state):
    args = ["-c", "import time;time.sleep(30)"]
    pending = pt.process_start(PY, args, cwd=str(work))
    assert pending["status"] == "APPROVAL_REQUIRED" and pending["action"] == "exec.workspace_write"
    assert not _started(isolated_state)
    rid = pending["approval_id"]
    common.grant_approval(rid)
    with pytest.raises(PolicyError, match="APPROVAL_DIGEST_MISMATCH"):
        pt.process_start(PY, ["-c", "pass"], cwd=str(work), approval_id=rid)
    started = pt.process_start(PY, args, cwd=str(work), approval_id=rid)
    assert started["status"] == "STARTED" and started["approval_id"] == rid
    try:
        with pytest.raises(PolicyError, match="APPROVAL_ALREADY_USED"):
            pt.process_start(PY, args, cwd=str(work), approval_id=rid)
        assert len(_started(isolated_state)) == 1
    finally:
        pt.process_stop(started["id"])


def test_secrets_never_reach_audit_metadata_or_approval_files(work, isolated_state):
    code = "import os,sys;print('visible-run-marker', os.environ['MY_FLAG'])"
    argv = [PY, "-c", code, "--password", SENT_ARG]
    kwargs = dict(shell="exec", argv=argv, cwd=str(work), mode="workspace_write", env={"MY_FLAG": SENT_ENV})
    rid = ct.command_execute(**kwargs)["approval_id"]
    common.grant_approval(rid)
    out = ct.command_execute(**kwargs, approval_id=rid)
    assert out["exit_code"] == 0 and "visible-run-marker" in out["stdout"]
    assert SENT_ENV in out["stdout"]                                # the child really received the value
    persisted = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in isolated_state.rglob("*")
                          if p.is_file() and p.suffix in (".json", ".jsonl", ".used"))
    assert "visible-run-marker" in persisted                       # positive control: we scanned the right files
    assert SENT_ARG not in persisted and SENT_ENV not in persisted
    assert common.audit_verify()["ok"] is True


def test_powershell_and_cmd_run_only_after_approval_and_redact_output(work, isolated_state):
    script = f'Write-Output "token={SENT_OUT}"; Write-Output "ps-marker"; exit 7'
    pending = ct.command_execute(script, shell="powershell", cwd=str(work), mode="workspace_write")
    assert pending["status"] == "APPROVAL_REQUIRED" and not _started(isolated_state)
    common.grant_approval(pending["approval_id"])
    out = ct.command_execute(script, shell="powershell", cwd=str(work), mode="workspace_write",
                             approval_id=pending["approval_id"])
    assert out["state"] == "exited" and out["exit_code"] == 7
    assert "ps-marker" in out["stdout"] and SENT_OUT not in out["stdout"] and "token=***" in out["stdout"]

    pending = ct.command_execute("echo cmd-marker & exit /b 5", shell="cmd", cwd=str(work), mode="workspace_write")
    assert pending["status"] == "APPROVAL_REQUIRED"
    common.grant_approval(pending["approval_id"])
    out = ct.command_execute("echo cmd-marker & exit /b 5", shell="cmd", cwd=str(work), mode="workspace_write",
                             approval_id=pending["approval_id"])
    assert out["exit_code"] == 5 and "cmd-marker" in out["stdout"]


def test_elevated_mode_requires_a_fresh_approval_per_call(work, isolated_state):
    kwargs = dict(shell="exec", argv=["whoami.exe"], cwd=str(work), mode="elevated")
    pending = ct.command_execute(**kwargs)
    assert pending["status"] == "APPROVAL_REQUIRED" and pending["mode"] == "elevated"
    common.grant_approval(pending["approval_id"])
    assert ct.command_execute(**kwargs, approval_id=pending["approval_id"])["exit_code"] == 0
    again = ct.command_execute(**kwargs)
    assert again["status"] == "APPROVAL_REQUIRED" and again["approval_id"] != pending["approval_id"]


# ---------------------------- git --output / --no-index never reaches a launch (F01)
GIT_ATTACKS = [["log", "--output={target}"], ["log", "--out={target}"], ["log", "--ou={target}"],
               ["diff", "-o{target}"], ["diff", "--no-index", "a", "b"]]


@pytest.mark.parametrize("template", GIT_ATTACKS, ids=lambda t: " ".join(t)[:30])
def test_git_output_option_is_denied_on_every_launch_path_and_target_is_untouched(work, isolated_state, template):
    target = work / "victim.cfg"
    target.write_bytes(b"ORIGINAL-CONFIG")
    args = [a.format(target=target) for a in template]
    with pytest.raises(PolicyError, match="GIT_OUTPUT_OR_NOINDEX_OPTION_NOT_ALLOWED"):
        pt.process_start("git.exe", args, cwd=str(work))
    with pytest.raises(PolicyError, match="GIT_OUTPUT_OR_NOINDEX_OPTION_NOT_ALLOWED"):
        ct.command_execute(shell="exec", argv=["git.exe", *args], cwd=str(work), mode="workspace_write")
    with pytest.raises(PolicyError, match="GIT_OUTPUT_OR_NOINDEX_OPTION_NOT_ALLOWED"):
        ct.command_start(shell="exec", argv=["git.exe", *args], cwd=str(work), mode="workspace_write")
    assert target.read_bytes() == b"ORIGINAL-CONFIG"
    assert not _started(isolated_state)                              # nothing was launched, no approval requested
    assert not list((isolated_state / "approvals").glob("req-*.json"))


def test_git_output_option_denied_even_with_a_pre_existing_git_config_hash_unchanged(work):
    import hashlib
    cfg = work / ".gitconfig-like"
    cfg.write_bytes(b"[core]\n")
    before = hashlib.sha256(cfg.read_bytes()).hexdigest()
    with pytest.raises(PolicyError):
        pt.process_start("git.exe", ["log", f"--output={cfg}"], cwd=str(work))
    assert hashlib.sha256(cfg.read_bytes()).hexdigest() == before


def test_python_still_requires_approval_next_to_the_git_guard(work):
    assert _exec(work)["status"] == "APPROVAL_REQUIRED"
    assert pt.process_start(PY, ["-c", "pass"], cwd=str(work))["status"] == "APPROVAL_REQUIRED"
