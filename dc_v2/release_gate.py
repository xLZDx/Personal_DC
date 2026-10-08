"""Fail-closed release gate assessment. Local review aid, never release authority.

No score or passing unit tests can certify deployment. A gate receives PASS
only after independent system evidence bound to the exact reviewed git HEAD.
"""
from __future__ import annotations

import re
from typing import Mapping

from .contracts import Denied, require

GATES = tuple(f"G{i:02d}" for i in range(1, 14))
SHA = re.compile(r"[0-9a-f]{40}\Z")
EVIDENCE_SHA = re.compile(r"[0-9a-f]{64}\Z")


def assess_release(head: str, gates: Mapping[str, dict]) -> dict:
    require(type(head) is str and SHA.fullmatch(head) is not None,
            "INVALID_REQUEST")
    require(type(gates) is dict and set(gates) == set(GATES), "GATE_INCOMPLETE")
    status = {}
    for gate in GATES:
        item = gates[gate]
        require(type(item) is dict, "GATE_INCOMPLETE")
        state = item.get("status")
        require(state in ("PASS", "FAIL", "PARTIAL", "HOLD", "NOT_RUN",
                          "BLOCKED", "NOT_APPLICABLE"), "GATE_INCOMPLETE")
        evidence = item.get("evidence")
        if state == "PASS":
            require(type(evidence) is dict and evidence.get("head") == head
                    and type(evidence.get("sha256")) is str
                    and EVIDENCE_SHA.fullmatch(evidence["sha256"]) is not None
                    and evidence.get("independent") is True
                    and evidence.get("system_test") is True,
                    "GATE_EVIDENCE_MISSING")
        status[gate] = state
    ready = all(x == "PASS" for x in status.values())
    return {"head": head, "gate_status": status, "all_pass": ready,
            "release_decision": "REVIEW_ELIGIBLE" if ready else "HOLD",
            "automatic_activation": False, "operator_cutover_required": True}
