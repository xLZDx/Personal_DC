"""Synthetic protected-directory promotion; HMAC fixture is NOT a deploy signer."""
from __future__ import annotations

import hmac
import time
from dataclasses import replace

import pytest

from dc_v2.contracts import Denied, Manifest, Principal
from dc_v2.execution import WorkspacePool
from dc_v2.ledger import Ledger
from dc_v2.phase03_audit import AuditJournal
from dc_v2.policy import TaskGrant
from dc_v2.promotion import Promoter

class FixtureVerifier:
    def sign(self, data: bytes) -> bytes:
        return hmac.digest(b"ONLY-TEST-SIGNATURE", data, "sha256")
    def verify(self, key_id: str, data: bytes, signature: bytes) -> bool:
        return key_id == "fixture" and hmac.compare_digest(signature, self.sign(data))

@pytest.fixture
def promotion(tmp_path):
    pool_dir, target_dir, control = (tmp_path/x for x in ("work", "target", "control"))
    for root in (pool_dir, target_dir, control):
        root.mkdir()
    (target_dir/"app.py").write_bytes(b"print('old')\n")
    pool = WorkspacePool(pool_dir, (target_dir,control))
    work = pool.create({"app.py":b"print('new')\n"})
    signer = FixtureVerifier()
    ledger = Ledger(control/"approvals.db", verifier=signer)
    audit = AuditJournal(control/"promotion-audit.jsonl")
    p = Promoter(pool,target_dir,"synthetic-target",{"app":"app.py"},
                 (tmp_path/"protected-main",),ledger,audit)
    plan = p.prepare(work.workspace_id,"demo",("app",))
    princ = Principal("owner","client","recipient",frozenset(("changes.propose","project:demo")))
    manifest = Manifest(princ.binding,"demo","changes.propose",work.snapshot_digest,
        "a"*64,"b"*64,"synthetic-target","recipient",
        (plan.digest,),(),("promotion",),60,8192)
    grant = TaskGrant(princ.binding,"demo",work.snapshot_digest,"a"*64,"b"*64,
        "synthetic-target","recipient",frozenset(("changes.propose",)),
        frozenset(("promotion",)),int(time.time())+300,60,8192)
    return p,plan,manifest,grant,princ,signer,ledger,target_dir


def approve(p,plan,manifest,grant,princ,signer,ledger):
    challenge = p.propose(plan,manifest,grant,princ,int(time.time()))
    message=ledger.approval_message(challenge["challenge_id"])
    ledger.receive_approval(challenge["challenge_id"],"fixture",signer.sign(message))
    return challenge["challenge_id"]


def test_promotion_signed_once_and_no_execution(promotion):
    p,plan,manifest,grant,princ,signer,ledger,target = promotion
    cid=approve(p,plan,manifest,grant,princ,signer,ledger)
    result=p.apply(plan,manifest,grant,princ,cid,"once",int(time.time()))
    assert result["status"]=="APPLIED"
    assert result["automatic_execution"] is False
    assert (target/"app.py").read_bytes()==b"print('new')\n"
    assert p.apply(plan,manifest,grant,princ,cid,"once",int(time.time()))["status"]=="ALREADY_RESERVED"
    assert ledger.verify_outbox()[0]>=3
    assert p.audit.verify()[0]>=2


def test_promotion_no_approval_does_not_write(promotion):
    p,plan,manifest,grant,princ,_,_,target = promotion
    challenge=p.propose(plan,manifest,grant,princ,int(time.time()))["challenge_id"]
    with pytest.raises(Denied, match="APPROVAL_REQUIRED"):
        p.apply(plan,manifest,grant,princ,challenge,"unapproved",int(time.time()))
    assert (target/"app.py").read_bytes()==b"print('old')\n"


def test_promotion_rejects_target_concurrent_change(promotion):
    p,plan,manifest,grant,princ,signer,ledger,target = promotion
    cid=approve(p,plan,manifest,grant,princ,signer,ledger)
    (target/"app.py").write_bytes(b"print('other')\n")
    with pytest.raises(Denied, match="MANIFEST_CHANGED"):
        p.apply(plan,manifest,grant,princ,cid,"changed",int(time.time()))
    assert (target/"app.py").read_bytes()==b"print('other')\n"


def test_promotion_rejects_forged_content_and_identity(promotion):
    p,plan,manifest,grant,princ,signer,ledger,target = promotion
    cid=approve(p,plan,manifest,grant,princ,signer,ledger)
    forged=replace(plan,updated=(b"print('attacker')\n",))
    with pytest.raises(Denied, match="MANIFEST_CHANGED"):
        p.apply(forged,manifest,grant,princ,cid,"forged",int(time.time()))
    with pytest.raises(Denied):
        p.apply(plan,manifest,grant,replace(princ,client_id="attacker"),
                cid,"cross",int(time.time()))
    assert (target/"app.py").read_bytes()==b"print('old')\n"


def test_promotion_approver_default_rejectall(tmp_path,promotion):
    p,plan,manifest,grant,princ,_,_,target=promotion
    deny=Ledger(tmp_path/"no-approval.db")
    p.ledger=deny
    cid=p.propose(plan,manifest,grant,princ,int(time.time()))["challenge_id"]
    with pytest.raises(Denied, match="APPROVAL_INVALID"):
        deny.receive_approval(cid,"any",b"approved=true")
    with pytest.raises(Denied, match="APPROVAL_REQUIRED"):
        p.apply(plan,manifest,grant,princ,cid,"nope",int(time.time()))
    assert (target/"app.py").read_bytes()==b"print('old')\n"


def test_promotion_target_overlap_forbidden(tmp_path,promotion):
    p,plan,_,_,_,_,ledger,_=promotion
    with pytest.raises(Denied, match="INVALID_CONFIGURATION"):
        Promoter(p.pool,p.root,"another",{"app":"app.py"},(p.root,),
                 ledger,p.audit)
