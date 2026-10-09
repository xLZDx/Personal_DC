"""v1 ``git_push`` / ``run_project_tests`` are wrapped with an operator approval in the v2 process.

The wrapper must return APPROVAL_REQUIRED (and never call the v1 function) until an exact, unused, unexpired,
granted approval is presented; afterwards it delegates unchanged to the v1 function.
"""
from __future__ import annotations

import asyncio

import pytest
from personal_dc.policy import PolicyError

from dc_v2.winops import common, v1_gate

pytestmark = pytest.mark.usefixtures("approvals_ready")


@pytest.fixture()
def v1_calls(monkeypatch):
    calls = []
    monkeypatch.setattr(v1_gate.v1, "git_push",
                        lambda project, remote, branch: calls.append(("git_push", project, remote, branch)) or {"v1": "push"})
    monkeypatch.setattr(v1_gate.v1, "run_project_tests",
                        lambda project, runner, timeout: calls.append(("tests", project, runner, timeout)) or {"v1": "tests"})
    return calls


def test_git_push_requires_approval_and_never_calls_v1_without_it(v1_calls):
    out = v1_gate.git_push("proj")
    assert out["status"] == "APPROVAL_REQUIRED" and out["action"] == "v1.git_push" and v1_calls == []
    rid = out["approval_id"]
    with pytest.raises(PolicyError, match="APPROVAL_NOT_GRANTED"):
        v1_gate.git_push("proj", approval_id=rid)
    with pytest.raises(PolicyError, match="INVALID_APPROVAL_ID"):
        v1_gate.git_push("proj", approval_id="nope")
    assert v1_calls == []


def test_git_push_approval_is_exact_single_use_and_delegates_unchanged(v1_calls):
    rid = v1_gate.git_push("proj", "origin", "main")["approval_id"]
    common.grant_approval(rid)
    for kwargs in (dict(project="other"), dict(remote="upstream"), dict(branch="dev")):
        args = dict(project="proj", remote="origin", branch="main", approval_id=rid)
        args.update(kwargs)
        with pytest.raises(PolicyError, match="APPROVAL_DIGEST_MISMATCH"):
            v1_gate.git_push(**args)
    assert v1_calls == []
    assert v1_gate.git_push("proj", "origin", "main", approval_id=rid) == {"v1": "push"}
    assert v1_calls == [("git_push", "proj", "origin", "main")]
    with pytest.raises(PolicyError, match="APPROVAL_ALREADY_USED"):
        v1_gate.git_push("proj", "origin", "main", approval_id=rid)
    assert len(v1_calls) == 1


def test_run_project_tests_requires_approval_and_never_calls_v1_without_it(v1_calls):
    out = v1_gate.run_project_tests("proj")
    assert out["status"] == "APPROVAL_REQUIRED" and out["action"] == "v1.run_project_tests" and v1_calls == []
    with pytest.raises(PolicyError, match="APPROVAL_NOT_GRANTED"):
        v1_gate.run_project_tests("proj", approval_id=out["approval_id"])
    assert v1_calls == []


def test_run_project_tests_approval_binds_runner_and_timeout(v1_calls):
    rid = v1_gate.run_project_tests("proj", "pytest", 600)["approval_id"]
    common.grant_approval(rid)
    for kwargs in (dict(runner="npm_test"), dict(timeout=9999), dict(project="x")):
        args = dict(project="proj", runner="pytest", timeout=600, approval_id=rid)
        args.update(kwargs)
        with pytest.raises(PolicyError, match="APPROVAL_DIGEST_MISMATCH"):
            v1_gate.run_project_tests(**args)
    assert v1_calls == []
    assert v1_gate.run_project_tests("proj", "pytest", 600, approval_id=rid) == {"v1": "tests"}
    assert v1_calls == [("tests", "proj", "pytest", 600)]
    with pytest.raises(PolicyError, match="APPROVAL_ALREADY_USED"):
        v1_gate.run_project_tests("proj", "pytest", 600, approval_id=rid)


def test_denied_gate_approval_never_reaches_v1(v1_calls):
    rid = v1_gate.git_push("proj")["approval_id"]
    common.grant_approval(rid)
    common.deny_approval(rid)
    with pytest.raises(PolicyError, match="APPROVAL_DENIED_BY_OPERATOR"):
        v1_gate.git_push("proj", approval_id=rid)
    assert v1_calls == []


def test_approved_run_is_audited_and_a_git_push_approval_is_not_a_tests_approval(v1_calls, isolated_state):
    rid = v1_gate.git_push("proj")["approval_id"]
    common.grant_approval(rid)
    with pytest.raises(PolicyError, match="APPROVAL_DIGEST_MISMATCH"):
        v1_gate.run_project_tests("proj", approval_id=rid)
    v1_gate.git_push("proj", approval_id=rid)
    text = (isolated_state / "audit" / "native-audit.jsonl").read_text(encoding="utf-8")
    assert '"action": "v1.git_push"' in text and '"status": "APPROVED_RUN"' in text
    assert common.audit_verify()["ok"] is True


def test_apply_v1_gate_replaces_both_tools_with_async_wrappers(v1_calls):
    class FakeServer:
        def __init__(self):
            self.removed, self.registered = [], {}

        def remove_tool(self, name):
            self.removed.append(name)

        def tool(self, annotations=None):
            def decorator(fn):
                self.registered[fn.__name__] = (fn, annotations)
                return fn
            return decorator
    server = FakeServer()
    v1_gate.apply_v1_gate(server)
    assert server.removed == ["git_push", "run_project_tests"]
    assert set(server.registered) == {"git_push", "run_project_tests"}
    push, annotations = server.registered["git_push"]
    assert asyncio.iscoroutinefunction(push) and annotations.openWorldHint is True
    result = asyncio.run(push("proj"))
    assert result["status"] == "APPROVAL_REQUIRED" and v1_calls == []
    tests, _ = server.registered["run_project_tests"]
    assert asyncio.run(tests("proj"))["status"] == "APPROVAL_REQUIRED" and v1_calls == []
