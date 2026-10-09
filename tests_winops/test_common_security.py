"""Approvals, audit chain, redaction and path safety."""
from __future__ import annotations

import json
import subprocess

import pytest
from personal_dc.policy import PolicyError

from dc_v2.winops import common


def test_redaction_masks_values_and_keys():
    text = common.redact_text('Srvr="s";Usr="admin";Pwd="hunter2"; token=abc123 Authorization: Bearer abcdefghijkl')
    assert "hunter2" not in text and "abc123" not in text and "abcdefghijkl" not in text
    assert common.redact({"api_key": "x", "nested": {"password": "y"}, "ok": "fine"}) == {
        "api_key": "***REDACTED***", "nested": {"password": "***REDACTED***"}, "ok": "fine"}


def test_audit_chain_detects_tampering(isolated_state):
    for i in range(3):
        common.audit("test.event", "OK", index=i, password="secret")
    assert common.audit_verify()["ok"] is True
    path = isolated_state / "audit" / "native-audit.jsonl"
    assert "secret" not in path.read_text(encoding="utf-8")
    lines = path.read_text(encoding="utf-8").splitlines()
    event = json.loads(lines[1])
    event["status"] = "FORGED"
    lines[1] = json.dumps(event)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert common.audit_verify()["ok"] is False


def test_approval_required_then_granted_once(approvals_ready):
    params = {"service": "Foo", "action": "restart"}
    payload = common.approval_or_response("service.restart", params, None)
    assert payload["status"] == "APPROVAL_REQUIRED"
    rid = payload["approval_id"]
    with pytest.raises(PolicyError, match="APPROVAL_NOT_GRANTED"):
        common.require_approval("service.restart", params, rid)
    common.grant_approval(rid, 120)
    assert common.approval_or_response("service.restart", params, rid) is None
    with pytest.raises(PolicyError, match="APPROVAL_ALREADY_USED"):
        common.require_approval("service.restart", params, rid)


def test_approval_bound_to_exact_params(approvals_ready):
    rid = common.approval_or_response("service.stop", {"service": "A", "action": "stop"}, None)["approval_id"]
    common.grant_approval(rid)
    with pytest.raises(PolicyError, match="APPROVAL_DIGEST_MISMATCH"):
        common.require_approval("service.stop", {"service": "B", "action": "stop"}, rid)


def test_forged_grant_rejected(approvals_ready, isolated_state):
    params = {"x": 1}
    rid = common.approval_or_response("exec.elevated", params, None)["approval_id"]
    forged = {"id": rid, "action": "exec.elevated", "digest": common.digest_of("exec.elevated", params),
              "granted_at": common.iso(), "expires_at": "2999-01-01T00:00:00+00:00", "grantor": "x", "sig": "00" * 32}
    (isolated_state / "approvals" / (rid + ".grant.json")).write_text(json.dumps(forged), encoding="utf-8")
    with pytest.raises(PolicyError, match="APPROVAL_SIGNATURE_INVALID"):
        common.require_approval("exec.elevated", params, rid)


def test_no_approval_key_fails_closed(isolated_state):
    params = {"x": 1}
    rid = common.approval_or_response("exec.elevated", params, None)["approval_id"]
    (isolated_state / "approvals" / (rid + ".grant.json")).write_text(json.dumps({"sig": "a"}), encoding="utf-8")
    with pytest.raises(PolicyError, match="APPROVAL_KEY_NOT_PROVISIONED"):
        common.require_approval("exec.elevated", params, rid)


def test_denied_request_cannot_be_used(approvals_ready, isolated_state):
    params = {"x": 2}
    rid = common.approval_or_response("exec.elevated", params, None)["approval_id"]
    common.grant_approval(rid)
    (isolated_state / "approvals" / (rid + ".denied")).write_text("x", encoding="utf-8")
    with pytest.raises(PolicyError, match="APPROVAL_DENIED_BY_OPERATOR"):
        common.require_approval("exec.elevated", params, rid)


def test_safe_path_blocks_outside_and_junction(work, tmp_path):
    inside = work / "a.txt"
    assert common.safe_path(str(inside), write=True) == inside.resolve()
    with pytest.raises(PolicyError):
        common.safe_path(str(tmp_path / "elsewhere.txt"))
    target = tmp_path / "outside_dir"
    target.mkdir()
    junction = work / "link"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(target)], check=True, capture_output=True)
    with pytest.raises(PolicyError):
        common.safe_path(str(junction / "file.txt"), write=True)


def test_state_directory_is_protected(work, isolated_state):
    with pytest.raises(PolicyError):
        common.safe_path(str(isolated_state / "approvals" / "x.json"))
