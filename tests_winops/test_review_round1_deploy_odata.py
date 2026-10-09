"""GPT review round 1: F05 (OData verdict), F06 (deployment apply race), F07 (rollback ownership),
F08 (staging failure), F10 (autostart updater script contract)."""
from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from personal_dc.policy import PolicyError

from dc_v2.winops import common, deploy_tools, onec_tools

PRODUCT = "{11111111-2222-3333-4444-555555555555}"
SHA = "a" * 64


# ----------------------------------------------------------------- F05
@pytest.mark.parametrize("probe, verdict", [
    ({"reachable": False}, "UNREACHABLE"),
    ({"reachable": True, "status": 401}, "AUTH_REQUIRED"),
    ({"reachable": True, "status": 403}, "AUTH_REQUIRED"),
    ({"reachable": True, "status": 404}, "PUBLICATION_NOT_FOUND"),
    ({"reachable": True, "status": 503}, "SERVER_ERROR"),
    ({"reachable": True, "status": 200}, "MALFORMED_OR_UNEXPECTED"),
    ({"reachable": True, "status": 200, "metadata": {"error": "XML_INVALID"}}, "MALFORMED_OR_UNEXPECTED"),
    ({"reachable": True, "status": 302}, "MALFORMED_OR_UNEXPECTED"),
    ({"reachable": True, "status": 200, "metadata": {"entity_types": 1, "entity_sets": 2}}, "HEALTHY"),
])
def test_odata_verdict_only_healthy_for_2xx_with_valid_metadata(probe, verdict):
    assert onec_tools._odata_verdict(probe) == verdict


# ------------------------------------------------------- deployment fixtures
@pytest.fixture()
def plan_env(isolated_state, monkeypatch, tmp_path):
    common.init_approval_key()
    installer = tmp_path / "setup.msi"
    installer.write_bytes(b"MZ-fake")
    launches = []

    def fake_launch(**kwargs):
        launches.append(kwargs)
        time.sleep(0.3)                                    # widen the race window
        return SimpleNamespace(meta={"id": "prc-fake0000000000"})

    monkeypatch.setattr(deploy_tools.pt, "launch", fake_launch)
    monkeypatch.setattr(deploy_tools.pt, "wait_done", lambda *a, **k: None)
    monkeypatch.setattr(deploy_tools, "_installer_path", lambda raw: Path(raw))
    monkeypatch.setattr(deploy_tools, "_sha256_file", lambda path: SHA)
    monkeypatch.setattr(deploy_tools, "ps_json", lambda *a, **k: {"thumbprint": "TP"})
    monkeypatch.setattr(deploy_tools, "_trust", lambda sig, sha: (True, "TEST"))
    monkeypatch.setattr(deploy_tools, "_reboot_pending", lambda: False)

    def make_plan(**override):
        plan = {"id": common.new_id("dpl"), "created_at": datetime.now(timezone.utc).isoformat(), "state": "planned",
                "installer": str(installer), "sha256": SHA, "profile": "msi", "install_dir": "",
                "msi": {"product_code": PRODUCT}, "signature": {"status": "Valid", "subject": "CN=T", "thumbprint": "TP"},
                "inventory_before": [], "product_preexisting": False, "log": None, "history": []}
        plan.update(override)
        plan["digest"] = common.digest_of("deployment.apply", deploy_tools._bound(plan))
        deploy_tools._save_plan(plan)
        return plan

    return SimpleNamespace(make_plan=make_plan, launches=launches, installer=installer)


def _approved(plan_id):
    pending = deploy_tools.deployment_apply(plan_id)
    assert pending["status"] == "APPROVAL_REQUIRED"
    common.grant_approval(pending["approval_id"])
    return pending["approval_id"]


# ----------------------------------------------------------------- F06
def test_concurrent_apply_launches_exactly_one_installer(plan_env):
    plan = plan_env.make_plan()
    rid = _approved(plan["id"])
    results, errors = [], []

    def call():
        try:
            results.append(deploy_tools.deployment_apply(plan["id"], approval_id=rid))
        except PolicyError as exc:
            errors.append(str(exc))

    threads = [threading.Thread(target=call) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert len(plan_env.launches) == 1
    assert len(results) == 1 and results[0]["state"] in ("running", "applying")
    assert len(errors) == 1 and "PLAN_NOT_APPLICABLE_IN_STATE:applying" in errors[0]


def test_second_apply_after_start_is_refused_before_consuming_its_approval(plan_env):
    plan = plan_env.make_plan()
    deploy_tools.deployment_apply(plan["id"], approval_id=_approved(plan["id"]))
    with pytest.raises(PolicyError, match="PLAN_NOT_APPLICABLE_IN_STATE"):
        deploy_tools.deployment_apply(plan["id"])          # state check precedes any approval request
    assert len(plan_env.launches) == 1


# ----------------------------------------------------------------- F08
def test_staging_failure_is_failed_retryable_and_launches_nothing(plan_env, monkeypatch, isolated_state):
    plan = plan_env.make_plan()
    rid = _approved(plan["id"])
    real_copy = deploy_tools.shutil.copy2

    def broken(*args, **kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(deploy_tools.shutil, "copy2", broken)
    out = deploy_tools.deployment_apply(plan["id"], approval_id=rid)
    assert out["state"] == "failed" and out["reason"].startswith("STAGING_FAILED")
    assert plan_env.launches == []
    assert not (isolated_state / "staging" / plan["id"]).exists()          # partial artifacts removed
    saved = deploy_tools._load_plan(plan["id"])
    assert saved["state"] == "failed" and saved["history"][-1]["event"] == "staging_failed"
    monkeypatch.setattr(deploy_tools.shutil, "copy2", real_copy)
    rid2 = _approved(plan["id"])                                           # fresh approval, retry succeeds
    assert rid2 != rid
    retry = deploy_tools.deployment_apply(plan["id"], approval_id=rid2)
    assert retry["state"] in ("running", "applying") and len(plan_env.launches) == 1


# ----------------------------------------------------------------- F07
def _settled(plan_env, **override):
    plan = plan_env.make_plan(**override)
    return plan


def test_rollback_refuses_failed_or_unowned_installs(plan_env, monkeypatch):
    monkeypatch.setattr(deploy_tools, "_settle", lambda plan: None)
    failed = _settled(plan_env, state="failed", new_software_keys=[f"HKLM:{PRODUCT}"])
    out = deploy_tools.deployment_rollback(failed["id"])
    assert out["status"] == "NOT_SUPPORTED" and out["reason"] == "INSTALLATION_OWNERSHIP_NOT_PROVEN"
    # installed, but the ProductCode did not appear during this plan (independent installation later)
    unowned = _settled(plan_env, state="installed", new_software_keys=["HKLM:{99999999-0000-0000-0000-000000000000}"])
    out = deploy_tools.deployment_rollback(unowned["id"])
    assert out["status"] == "NOT_SUPPORTED" and out["reason"] == "INSTALLATION_OWNERSHIP_NOT_PROVEN"
    assert plan_env.launches == []


def test_rollback_of_an_owned_install_asks_for_approval(plan_env, monkeypatch):
    monkeypatch.setattr(deploy_tools, "_settle", lambda plan: None)
    owned = _settled(plan_env, state="installed", new_software_keys=[f"HKLM:{PRODUCT.lower()}"])
    out = deploy_tools.deployment_rollback(owned["id"])
    assert out["status"] == "APPROVAL_REQUIRED" and plan_env.launches == []


# ----------------------------------------------------------------- F10
SCRIPT = Path(__file__).resolve().parents[1] / "scripts_v2" / "update_v2_native_autostart.ps1"


def test_autostart_updater_rollback_contract():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "[switch]$Previous" in text
    rollback = text[text.index("if ($Rollback)"):text.index("$user = ")]
    assert "task-$Task-ORIGINAL.xml" in rollback                           # default rollback = immutable original
    assert 'notlike "*start_v2_native_supervisor.ps1*"' in rollback        # -Previous never picks a native snapshot
    assert '-notlike "*-ORIGINAL.xml"' in rollback
    update = text[text.index("$stamp = "):]
    assert "if (-not (Test-Path -LiteralPath $orig))" in update            # ORIGINAL is written once, never replaced
    snapshot = update[update.index("ALREADY_NATIVE_SUPERVISOR"):]
    assert snapshot.index("ALREADY_NATIVE_SUPERVISOR") < snapshot.index("task-$Task-$stamp.xml")
    assert "else { Set-Content" in snapshot                                # no snapshot of an already-native task


# ----------------------------------------------------------------- F04
def test_recovery_and_rollback_apply_the_same_vrd_path_policy_as_repair(tmp_path, monkeypatch, native_overlay, isolated_state):
    from tests_winops.test_services_onec_deploy import VRD, _write_conf
    common.init_approval_key()
    root = tmp_path / "Apache24"
    (root / "bin").mkdir(parents=True)
    (root / "bin" / "httpd.exe").write_bytes(b"MZ")
    (root / "conf").mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    outside = elsewhere / "default.vrd"
    outside.write_bytes(VRD.encode("utf-8"))
    _write_conf(root, [("/acc", elsewhere, outside)])
    native_overlay(apache_roots=[str(root)])
    monkeypatch.setattr(onec_tools, "ps_json", lambda *a, **k: [])
    monkeypatch.setattr(onec_tools, "_configtest", lambda install: {"ok": True, "exit_code": 0, "output": "Syntax OK"})
    before = outside.read_bytes()
    with pytest.raises(PolicyError, match="VRD_OUTSIDE_PUBLICATION_ROOTS"):
        onec_tools.onec_publication_repair("acc")
    plan = onec_tools.odata_recovery("acc")                                   # recovery refuses to even plan a step
    assert plan["plan"]["blocked"] is True and plan["plan"]["steps"] == []
    assert any("path policy" in note for note in plan["plan"]["notes"])
    # the write helper itself re-validates immediately before writing (defence in depth for recovery/rollback)
    install = onec_tools._pick_apache("")
    step = {"operation": "enable_standard_odata", "vrd": str(outside), "old_sha256": "0" * 64,
            "new_sha256": "1" * 64, "publication": "acc"}
    with pytest.raises(PolicyError, match="VRD_OUTSIDE_PUBLICATION_ROOTS"):
        onec_tools._apply_vrd_change(install, step, b"x")
    assert outside.read_bytes() == before
    assert not (isolated_state / "backups").exists() or not list((isolated_state / "backups").iterdir())                  # no backup was created
