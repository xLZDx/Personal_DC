"""Service policy, 1C/Apache parsing and repair planning, deployment gating (no real system mutation)."""
from __future__ import annotations

import hashlib

import pytest
from personal_dc.policy import PolicyError

from dc_v2.winops import common, deploy_tools, onec_tools, service_tools


@pytest.mark.parametrize("name", ["", "a*", "Spool?er", "x y", "a;b", "A" * 101, "..\\x", "%PATH%"])
def test_service_names_validated(name):
    with pytest.raises(PolicyError):
        service_tools._check_name(name)


def test_protected_service_never_controllable(monkeypatch):
    monkeypatch.setattr(service_tools, "_allow_entry", lambda n: {"name": n, "actions": ["stop"]})
    with pytest.raises(PolicyError, match="SERVICE_PROTECTED"):
        service_tools.service_stop("WinDefend")


def test_not_allowlisted_service_denied():
    with pytest.raises(PolicyError, match="SERVICE_ACTION_NOT_ALLOWLISTED"):
        service_tools.service_restart("SomeService")


def test_allowlisted_service_needs_approval(monkeypatch, approvals_ready):
    monkeypatch.setattr(service_tools, "_allow_entry", lambda n: {"name": n, "actions": ["restart"]})
    out = service_tools.service_restart("MyApp")
    assert out["status"] == "APPROVAL_REQUIRED" and out["action"] == "service.restart"


def test_conn_string_redaction():
    red = onec_tools._redact_conn('File="C:\\base";Usr="admin";Pwd="s3cret";')
    assert "s3cret" not in red and "admin" not in red and "C:\\base" in red
    assert onec_tools._parse_ib('Srvr="srv:1541";Ref="acc";')["ref"] == "acc"


def test_xml_dtd_rejected():
    with pytest.raises(PolicyError):
        onec_tools._parse_xml_safe(b'<!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>')


VRD = ('<?xml version="1.0" encoding="UTF-8"?>\r\n<point xmlns="http://v8.1c.ru/8.2/virtual-resource-system" '
       'base="/acc" ib="File=&quot;C:\\db&quot;;Usr=&quot;u&quot;;Pwd=&quot;p&quot;;">\r\n'
       '\t<standardOdata enable="false" reuseSessions="autouse"/>\r\n</point>\r\n')


def test_enable_odata_modifies_only_flag_and_stays_valid():
    new = onec_tools._enable_odata_text(VRD)
    assert 'enable="true"' in new and new.replace('enable="true"', 'enable="false"') == VRD
    onec_tools._parse_xml_safe(new.encode())


def test_enable_odata_inserts_when_missing():
    text = '<point xmlns="x" base="/a" ib="File=&quot;C:\\d&quot;;">\n</point>\n'
    new = onec_tools._enable_odata_text(text)
    assert "<standardOdata enable=\"true\"" in new
    onec_tools._parse_xml_safe(new.encode())


def test_vrd_details_redacts_credentials(tmp_path):
    path = tmp_path / "default.vrd"
    path.write_text(VRD, encoding="utf-8")
    info = onec_tools._vrd_details(path)
    assert info["odata"]["enabled"] is False and "p&" not in str(info) and "Pwd=***" in info["ib"]
    assert info["sha256"] == hashlib.sha256(VRD.encode()).hexdigest()


def test_collect_conf_finds_publication_module_and_listen(tmp_path):
    root = tmp_path / "Apache24"
    (root / "conf" / "extra").mkdir(parents=True)
    pub = tmp_path / "pubs" / "acc"
    pub.mkdir(parents=True)
    (pub / "default.vrd").write_text(VRD, encoding="utf-8")
    (root / "conf" / "httpd.conf").write_text(
        'Listen 8080\nLoadModule _1cws_module "C:/Program Files/1cv8/8.3.24.1/bin/wsap24.dll"\n'
        'Include conf/extra/*.conf\n', encoding="utf-8")
    (root / "conf" / "extra" / "1c.conf").write_text(
        f'Alias "/acc" "{pub.as_posix()}"\n<Directory "{pub.as_posix()}">\n'
        f'  SetHandler 1c-application\n  ManagedApplicationDescriptor "{(pub / "default.vrd").as_posix()}"\n</Directory>\n',
        encoding="utf-8")
    install = {"server_root": str(root), "conf": str(root / "conf" / "httpd.conf")}
    conf = onec_tools._collect_conf(install)
    assert conf["listen"] == ["8080"] and "_1cws_module" in conf["modules"]
    assert conf["publications"][0]["name"] == "acc"


def test_odata_probe_rejects_foreign_hosts_and_bad_paths():
    with pytest.raises(PolicyError, match="ODATA_HOST_NOT_ALLOWED"):
        onec_tools.odata_probe(url="http://evil.example/acc/odata/standard.odata")
    with pytest.raises(PolicyError):
        onec_tools.odata_probe(url="http://127.0.0.1/acc/odata", path="../../x")


def test_repair_apply_requires_approval_and_matches_hash(monkeypatch, tmp_path, approvals_ready):
    vrd = tmp_path / "default.vrd"
    vrd.write_text(VRD, encoding="utf-8")
    monkeypatch.setattr(onec_tools, "_locate_vrd", lambda p, r: (
        {"exe_exists": False, "conf_exists": False}, {"vrd": str(vrd)}))
    plan = onec_tools.onec_publication_repair("acc")
    assert plan["status"] == "PLAN" and plan["plan"]["old_sha256"] == hashlib.sha256(VRD.encode()).hexdigest()
    pending = onec_tools.onec_publication_repair("acc", apply=True)
    assert pending["status"] == "APPROVAL_REQUIRED" and vrd.read_text(encoding="utf-8") == VRD
    common.grant_approval(pending["approval_id"])
    applied = onec_tools.onec_publication_repair("acc", apply=True, approval_id=pending["approval_id"])
    assert applied["status"] == "APPLIED" and 'enable="true"' in vrd.read_text(encoding="utf-8")
    back = onec_tools.onec_publication_repair("acc", "rollback", backup_id=applied["backup_id"])
    assert back["status"] == "PLAN"


def test_installer_must_be_in_roots_and_known_type(tmp_path):
    bad = tmp_path / "x.bat"
    bad.write_text("echo", encoding="utf-8")
    with pytest.raises(PolicyError):
        deploy_tools.installer_verify(str(bad))


def test_deployment_plan_requires_pinned_hash(tmp_path):
    with pytest.raises(PolicyError, match="EXPECTED_SHA256_REQUIRED"):
        deploy_tools.deployment_plan(str(tmp_path / "a.msi"), "")
    with pytest.raises(PolicyError, match="UNSUPPORTED_INSTALLER_PROFILE"):
        deploy_tools.deployment_plan(str(tmp_path / "a.msi"), "a" * 64, profile="custom")


def test_trust_decision_matrix(monkeypatch):
    cfg = common.native_config()
    cfg.update(trusted_publishers=["Contoso"], trusted_thumbprints=["AB12"], trusted_installer_sha256=[])
    monkeypatch.setattr(deploy_tools, "native_config", lambda: cfg)
    assert deploy_tools._trust({"status": "Valid", "subject": "CN=Contoso Ltd", "thumbprint": "x"}, "h")[0]
    assert not deploy_tools._trust({"status": "NotSigned"}, "h")[0]
    assert not deploy_tools._trust({"status": "Valid", "subject": "CN=Evil", "thumbprint": "x"}, "h")[0]
    assert not deploy_tools._trust({"status": "HashMismatch", "subject": "CN=Contoso"}, "h")[0]


def test_install_dir_confined_to_approved_roots(monkeypatch, tmp_path):
    cfg = common.native_config()
    cfg["install_roots"] = [str(tmp_path / "apps")]
    monkeypatch.setattr(deploy_tools, "native_config", lambda: cfg)
    assert deploy_tools._install_dir(str(tmp_path / "apps" / "x"))
    with pytest.raises(PolicyError):
        deploy_tools._install_dir(str(tmp_path / "other"))
    with pytest.raises(PolicyError):
        deploy_tools._install_dir(str(tmp_path / "apps" / "a&b"))
