from __future__ import annotations

import pytest
from dc_v2.contracts import Denied
from dc_v2.release_gate import assess_release, GATES

HEAD = "a" * 40


def candidate():
    return {g: {"status": "HOLD"} for g in GATES}


def test_all_hold_is_never_release_ready():
    result = assess_release(HEAD, candidate())
    assert not result["all_pass"]
    assert result["release_decision"] == "HOLD"
    assert result["automatic_activation"] is False


def test_missing_gate_fails_closed():
    gates = candidate()
    del gates["G13"]
    with pytest.raises(Denied, match="GATE_INCOMPLETE"):
        assess_release(HEAD, gates)


def test_claimed_pass_without_evidence_is_denied():
    gates = candidate()
    gates["G01"] = {"status": "PASS"}
    with pytest.raises(Denied, match="GATE_EVIDENCE_MISSING"):
        assess_release(HEAD, gates)


@pytest.mark.parametrize("mutation", ["wrong_head", "bad_hash", "not_independent", "not_system"])
def test_insufficient_pass_evidence_is_denied(mutation):
    evidence = {"head": HEAD, "sha256": "f" * 64,
                "independent": True, "system_test": True}
    if mutation == "wrong_head": evidence["head"] = "b" * 40
    if mutation == "bad_hash": evidence["sha256"] = "not-a-hash"
    if mutation == "not_independent": evidence["independent"] = False
    if mutation == "not_system": evidence["system_test"] = False
    gates = candidate()
    gates["G01"] = {"status": "PASS", "evidence": evidence}
    with pytest.raises(Denied, match="GATE_EVIDENCE_MISSING"):
        assess_release(HEAD, gates)


def test_full_evidence_only_allows_review_not_activation():
    gates = {g: {"status": "PASS", "evidence": {
        "head": HEAD, "sha256": "f" * 64, "independent": True,
        "system_test": True}} for g in GATES}
    with pytest.raises(Denied, match="TRUSTED_ATTESTOR_UNAVAILABLE"):
        assess_release(HEAD, gates)
    result = assess_release(HEAD, gates, verifier=lambda gate, head, evidence: True)
    assert result["release_decision"] == "REVIEW_ELIGIBLE"
    assert result["automatic_activation"] is False
    assert result["operator_cutover_required"] is True

def test_independent_attestor_can_reject_an_apparently_complete_gate():
    gates = {g: {"status": "PASS", "evidence": {
        "head": HEAD, "sha256": "f" * 64,
        "independent": True, "system_test": True}} for g in GATES}
    with pytest.raises(Denied, match="GATE_ATTESTATION_INVALID"):
        assess_release(HEAD, gates, verifier=lambda gate, head, ev: False)
