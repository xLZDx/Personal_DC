"""Ledger-gated synthetic Docker lifecycle, no external approval device."""
from __future__ import annotations

import hmac
from dataclasses import replace
import pytest

from dc_v2.approved_execution import ApprovedExecution
from dc_v2.contracts import Denied
from dc_v2.ledger import Ledger
from test_execution import harness


class TestVerifier:
    def sign(self, message: bytes) -> bytes:
        return hmac.digest(b"TEST_ONLY_NOT_A_REAL_APPROVER", message, "sha256")

    def verify(self, key_id: str, message: bytes, signature: bytes) -> bool:
        return key_id == "fixture" and hmac.compare_digest(signature, self.sign(message))


def test_approval_requires_verified_one_time_challenge(harness):
    pool, work, runner, principal, manifest, grant = harness
    signer = TestVerifier()
    ledger = Ledger(runner.control/"approved-test.db", verifier=signer)
    wrapper = ApprovedExecution(runner, ledger)
    challenge = wrapper.propose(manifest, grant, principal, work.workspace_id)
    assert runner.commands == []
    with pytest.raises(Denied, match="APPROVAL_REQUIRED"):
        wrapper.start_once(manifest, grant, principal, work.workspace_id,
                           challenge["challenge_id"], "once")
    assert runner.commands == []
    message = ledger.approval_message(challenge["challenge_id"])
    ledger.receive_approval(challenge["challenge_id"], "fixture", signer.sign(message))
    first = wrapper.start_once(manifest, grant, principal, work.workspace_id,
                               challenge["challenge_id"], "once")
    assert first["status"] == "STARTED"
    assert first["host_execution"] is False
    assert len([x for x in runner.commands if x[0] == "run"]) == 1
    again = wrapper.start_once(manifest, grant, principal, work.workspace_id,
                               challenge["challenge_id"], "once")
    assert again["status"] == "ALREADY_RESERVED"
    assert again["started_another_process"] is False
    assert len([x for x in runner.commands if x[0] == "run"]) == 1


def test_replay_with_different_idempotency_key_is_denied(harness):
    _, work, runner, principal, manifest, grant = harness
    signer = TestVerifier()
    ledger = Ledger(runner.control/"approved-test.db", verifier=signer)
    wrapper = ApprovedExecution(runner, ledger)
    challenge = wrapper.propose(manifest, grant, principal, work.workspace_id)
    ledger.receive_approval(challenge["challenge_id"], "fixture",
                            signer.sign(ledger.approval_message(challenge["challenge_id"])))
    wrapper.start_once(manifest, grant, principal, work.workspace_id,
                       challenge["challenge_id"], "first")
    with pytest.raises(Denied, match="APPROVAL_REQUIRED"):
        wrapper.start_once(manifest, grant, principal, work.workspace_id,
                           challenge["challenge_id"], "second")
    assert len([x for x in runner.commands if x[0] == "run"]) == 1


def test_unsigned_or_forged_identity_does_not_run(harness):
    _, work, runner, principal, manifest, grant = harness
    ledger = Ledger(runner.control/"rejectall.db")
    wrapper = ApprovedExecution(runner, ledger)
    challenge = wrapper.propose(manifest, grant, principal, work.workspace_id)
    with pytest.raises(Denied, match="APPROVAL_INVALID"):
        ledger.receive_approval(challenge["challenge_id"], "attacker", b"approved=true")
    with pytest.raises(Denied, match="ACCESS_DENIED"):
        wrapper.start_once(manifest, grant,
                           replace(principal, client_id="unauthorized"),
                           work.workspace_id, challenge["challenge_id"], "wrong")
    assert not runner.commands


def test_execution_error_after_reservation_is_not_replayed(harness):
    _, work, runner, principal, manifest, grant = harness
    signer = TestVerifier()
    ledger = Ledger(runner.control/"approved-test.db", verifier=signer)
    wrapper = ApprovedExecution(runner, ledger)
    challenge = wrapper.propose(manifest, grant, principal, work.workspace_id)
    ledger.receive_approval(challenge["challenge_id"], "fixture",
                            signer.sign(ledger.approval_message(challenge["challenge_id"])))
    def docker_fails(*args, **kwargs):
        raise Denied("ENVIRONMENT_UNAVAILABLE")
    runner._docker = docker_fails
    with pytest.raises(Denied, match="ENVIRONMENT_UNAVAILABLE"):
        wrapper.start_once(manifest, grant, principal, work.workspace_id,
                           challenge["challenge_id"], "one-attempt")
    result = wrapper.start_once(manifest, grant, principal, work.workspace_id,
                                challenge["challenge_id"], "one-attempt")
    assert result["status"] == "ALREADY_RESERVED"
    assert result["started_another_process"] is False
