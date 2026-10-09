"""Service policy, 1C/Apache/OData parsing, reversible repair and deployment gating (no real system mutation).

Real services, real Apache and real 1C are never touched: the SCM handle class and ``_configtest`` are replaced
where a test would otherwise mutate the machine, and OData probing talks only to a loopback server started by
the test itself.
"""
from __future__ import annotations

import base64
import hashlib
import json
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest
from personal_dc.policy import PolicyError

from dc_v2.winops import common, deploy_tools, onec_tools, service_tools

SENT_USER = "SENTUSER-4417"
SENT_PW = "SENTPW-4417"
SENT_ODATA_PW = "SENT-ODATA-PW-9921"


def _vrd(enabled: str = "false", user: str = SENT_USER, pw: str = SENT_PW, newline: str = "\r\n") -> str:
    return ('<?xml version="1.0" encoding="UTF-8"?>' + newline
            + '<point xmlns="http://v8.1c.ru/8.2/virtual-resource-system" base="/acc" '
            + f'ib="File=&quot;C:\\db&quot;;Usr=&quot;{user}&quot;;Pwd=&quot;{pw}&quot;;">' + newline
            + f'\t<standardOdata enable="{enabled}" reuseSessions="autouse"/>' + newline + '</point>' + newline)


VRD = _vrd()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _approval_files(state):
    base = state / "approvals"
    return [p for p in base.glob("req-*.json") if not p.name.endswith(".grant.json")] if base.is_dir() else []


# ===================================================================== services
@pytest.mark.parametrize("name", ["", "a*", "Spool?er", "x y", "a;b", "A" * 101, "..\\x", "%PATH%", "a[b]", None, 5])
def test_service_names_validated(name):
    with pytest.raises(PolicyError, match="INVALID_SERVICE_NAME|SERVICE_WILDCARDS_NOT_ALLOWED"):
        service_tools._check_name(name)


@pytest.mark.parametrize("name", ["Spooler", "My.App_1", "svc$x", "a-b"])
def test_valid_service_names_pass(name):
    assert service_tools._check_name(name) == name


class _FakeSvc:
    """Stands in for an open service handle: no SCM, no real service."""

    def __init__(self, name, access):
        self.name = name

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def status(self):
        return {"state": "running", "pid": 1, "win32_exit_code": 0, "controls_accepted": 1, "accepts_stop": True}


@pytest.fixture()
def fake_scm(monkeypatch):
    calls = []
    monkeypatch.setattr(service_tools, "_Svc", _FakeSvc)
    monkeypatch.setattr(service_tools, "_do_stop", lambda name, timeout: (calls.append(("stop", name)), "stopped")[1])
    monkeypatch.setattr(service_tools, "_do_start", lambda name, timeout: (calls.append(("start", name)), "running")[1])
    return calls


def test_protected_service_never_controllable_even_if_allowlisted(native_overlay):
    native_overlay(service_allowlist=[{"name": "WinDefend", "actions": ["stop", "start", "restart"]}])
    for name in ("WinDefend", "windefend", "WINDEFEND"):
        with pytest.raises(PolicyError, match="SERVICE_PROTECTED"):
            service_tools.service_stop(name)
    with pytest.raises(PolicyError, match="SERVICE_PROTECTED"):
        service_tools.service_restart("EventLog")


def test_operator_denylist_extra_beats_allowlist(native_overlay):
    native_overlay(service_allowlist=[{"name": "MyApp", "actions": ["restart"]}], service_denylist_extra=["myapp"])
    with pytest.raises(PolicyError, match="SERVICE_PROTECTED"):
        service_tools.service_restart("MyApp")


def test_not_allowlisted_service_denied(native_overlay, isolated_state):
    with pytest.raises(PolicyError, match="SERVICE_ACTION_NOT_ALLOWLISTED"):
        service_tools.service_restart("SomeService")
    native_overlay(service_allowlist=[{"name": "MyApp", "actions": ["stop"]}])
    with pytest.raises(PolicyError, match="SERVICE_ACTION_NOT_ALLOWLISTED"):      # listed service, unlisted action
        service_tools.service_restart("MyApp")
    assert '"status": "DENIED"' in (isolated_state / "audit" / "native-audit.jsonl").read_text(encoding="utf-8")


def test_allowlisted_service_needs_approval_then_acts_once(native_overlay, approvals_ready, isolated_state, fake_scm):
    native_overlay(service_allowlist=[{"name": "MyApp", "actions": ["restart", "stop", "start"]},
                                      {"name": "OtherApp", "actions": ["restart"]}])
    out = service_tools.service_restart("MyApp")
    assert out["status"] == "APPROVAL_REQUIRED" and out["action"] == "service.restart" and fake_scm == []
    rid = out["approval_id"]
    common.grant_approval(rid)
    with pytest.raises(PolicyError, match="APPROVAL_DIGEST_MISMATCH"):
        service_tools.service_stop("MyApp", approval_id=rid)                       # restart approval is not a stop approval
    with pytest.raises(PolicyError, match="APPROVAL_DIGEST_MISMATCH"):
        service_tools.service_restart("OtherApp", approval_id=rid)
    assert fake_scm == []
    result = service_tools.service_restart("MyApp", approval_id=rid)
    assert result["confirmed"] is True and result["prior_state"] == "running"
    assert fake_scm == [("stop", "MyApp"), ("start", "MyApp")]
    assert list((isolated_state / "rollback").glob("svr-*.json"))                  # rollback record written
    with pytest.raises(PolicyError, match="APPROVAL_ALREADY_USED"):
        service_tools.service_restart("MyApp", approval_id=rid)
    assert len(fake_scm) == 2


def test_approval_free_action_runs_without_approval_but_others_do_not(native_overlay, approvals_ready, fake_scm):
    native_overlay(service_allowlist=[{"name": "Free", "actions": ["start", "stop"], "approval_free": ["start"]}])
    assert service_tools.service_start("Free")["confirmed"] is True
    assert fake_scm == [("start", "Free")]
    assert service_tools.service_stop("Free")["status"] == "APPROVAL_REQUIRED"
    assert fake_scm == [("start", "Free")]


def test_pre_approved_step_still_obeys_the_allowlist(native_overlay, fake_scm):
    native_overlay(service_allowlist=[{"name": "MyApp", "actions": ["start"]}])
    assert service_tools._mutate("MyApp", "start", 5, None, pre_approved=True)["confirmed"] is True
    with pytest.raises(PolicyError, match="SERVICE_ACTION_NOT_ALLOWLISTED"):
        service_tools._mutate("MyApp", "stop", 5, None, pre_approved=True)
    with pytest.raises(PolicyError, match="SERVICE_PROTECTED"):
        service_tools._mutate("WinDefend", "stop", 5, None, pre_approved=True)


def test_missing_service_fails_before_any_approval_is_requested(native_overlay, approvals_ready, isolated_state):
    native_overlay(service_allowlist=[{"name": "PdcNoSuchService12345", "actions": ["restart"]}])
    with pytest.raises(PolicyError, match="SERVICE_NOT_FOUND"):
        service_tools.service_restart("PdcNoSuchService12345")
    assert _approval_files(isolated_state) == []


def test_service_inputs_validated_before_any_powershell_runs():
    with pytest.raises(PolicyError, match="INVALID_STATE_FILTER"):
        service_tools.service_list(state="Bogus")
    with pytest.raises(PolicyError, match="INVALID_FILTER"):
        service_tools.service_list(name_contains="a;b")
    with pytest.raises(PolicyError, match="INVALID_SERVICE_NAME"):
        service_tools.service_inspect("a;b")
    with pytest.raises(PolicyError, match="INVALID_TARGET_STATE"):
        service_tools.service_wait("Spooler", state="exploded")


# ============================================================ redaction/parsing
def test_conn_string_redaction():
    red = onec_tools._redact_conn('File="C:\\base";Usr="admin";Pwd="s3cret";')
    assert "s3cret" not in red and "admin" not in red and "C:\\base" in red
    assert onec_tools._parse_ib('Srvr="srv:1541";Ref="acc";')["ref"] == "acc"


@pytest.mark.parametrize("conn, leaked", [
    ('Srvr="s";Pwd="a""b";Ref="r"', ("a\"\"b", "b\"")),
    ('Srvr="s";Usr="x""y";Ref="r"', ("x\"\"y",)),
    ("File=&quot;C:\\db&quot;;Pwd=&quot;ent-secret&quot;;", ("ent-secret",)),
    ("Srvr=s;pwd=plainsecret;Ref=r", ("plainsecret",)),
    ("Srvr=s;PASSWORD=Upper1;USER=Bob", ("Upper1", "Bob")),
])
def test_conn_redaction_handles_doubled_quotes_entities_and_unquoted(conn, leaked):
    red = onec_tools._redact_conn(conn)
    for secret in leaked:
        assert secret not in red
    assert "***" in red and ("Srvr" in red or "File" in red)


def test_parse_ib_variants():
    assert onec_tools._parse_ib('File="C:\\a""b"')["file"] == 'C:\\a"b'
    assert onec_tools._parse_ib("Srvr=srv:1541;Ref=acc")["srvr"] == "srv:1541"
    assert onec_tools._parse_ib("nothing here") == {}


def test_xml_dtd_rejected_anywhere():
    for payload in (b'<!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>',
                    b'<!doctype x><x/>',
                    b'<x><!-- <!DOCTYPE hidden> --></x>',
                    b'<x>' + b' ' * 70000 + b'<!DOCTYPE x [<!ENTITY a "b">]></x>',      # beyond any 64 KiB prefix scan
                    b'<x><![CDATA[ ok ]]></x><!ENTITY a "b">'):
        with pytest.raises(PolicyError, match="XML_DTD_NOT_ALLOWED"):
            onec_tools._parse_xml_safe(payload)


def test_xml_utf16_rejected_even_when_it_hides_a_doctype():
    hidden = '<!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>'
    for payload in (hidden.encode("utf-16"), hidden.encode("utf-16-le"), hidden.encode("utf-16-be"),
                    "<x/>".encode("utf-16"), b"<\x00x\x00/\x00>\x00"):
        with pytest.raises(PolicyError, match="XML_ENCODING_NOT_ALLOWED"):
            onec_tools._parse_xml_safe(payload)


def test_xml_valid_and_malformed():
    assert onec_tools._parse_xml_safe(VRD.encode("utf-8")).attrib["base"] == "/acc"
    assert onec_tools._parse_xml_safe(b"\xef\xbb\xbf" + VRD.encode("utf-8")).attrib["base"] == "/acc"
    with pytest.raises(PolicyError, match="XML_INVALID"):
        onec_tools._parse_xml_safe(b"<a><b></a>")


def test_enable_odata_modifies_only_flag_and_stays_valid():
    new = onec_tools._enable_odata_text(VRD)
    assert 'enable="true"' in new and new.replace('enable="true"', 'enable="false"') == VRD
    onec_tools._parse_xml_safe(new.encode())


def test_enable_odata_preserves_crlf_exactly_on_both_paths():
    replaced = onec_tools._enable_odata_text(VRD)
    assert replaced.count("\r\n") == VRD.count("\r\n") and "\r\r\n" not in replaced
    bare = '<point xmlns="x" base="/a" ib="File=&quot;C:\\d&quot;;">\r\n</point>\r\n'
    inserted = onec_tools._enable_odata_text(bare)
    assert "<standardOdata enable=\"true\"" in inserted
    assert inserted.count("\n") == inserted.count("\r\n") and "\r\r\n" not in inserted
    unix = onec_tools._enable_odata_text('<point xmlns="x" base="/a" ib="File=&quot;C:\\d&quot;;">\n</point>\n')
    assert "\r" not in unix and "<standardOdata enable=\"true\"" in unix
    onec_tools._parse_xml_safe(inserted.encode())


def test_enable_odata_inserts_when_missing():
    text = '<point xmlns="x" base="/a" ib="File=&quot;C:\\d&quot;;">\n</point>\n'
    new = onec_tools._enable_odata_text(text)
    assert "<standardOdata enable=\"true\"" in new
    onec_tools._parse_xml_safe(new.encode())


def test_enable_odata_ignores_commented_out_element_and_single_quotes():
    commented = ('<point xmlns="x" base="/a" ib="">\n<!-- <standardOdata enable="false"/> -->\n'
                 '<standardOdata enable=\'false\' poolSize="3"/>\n</point>\n')
    new = onec_tools._enable_odata_text(commented)
    assert '<!-- <standardOdata enable="false"/> -->' in new          # the comment is untouched
    assert 'enable="true" poolSize="3"' in new and "enable='false'" not in new
    only_comment = '<point xmlns="x" base="/a" ib="">\n<!-- <standardOdata enable="false"/> -->\n</point>\n'
    inserted = onec_tools._enable_odata_text(only_comment)
    assert inserted.count("standardOdata") == 2 and 'enable="true"' in inserted
    no_attr = onec_tools._enable_odata_text('<point xmlns="x" ib="">\n<standardOdata poolSize="3"/>\n</point>\n')
    assert '<standardOdata enable="true" poolSize="3"/>' in no_attr


def test_enable_odata_unsupported_structure_and_non_utf8():
    with pytest.raises(PolicyError, match="VRD_STRUCTURE_UNSUPPORTED"):
        onec_tools._enable_odata_text("<other/>")
    with pytest.raises(PolicyError, match="VRD_NOT_UTF8"):
        onec_tools._decode_vrd(b"\xff\xfe<\x00")
    assert onec_tools._decode_vrd(b"\xef\xbb\xbf<a/>") == ("<a/>", b"\xef\xbb\xbf")


def test_vrd_details_redacts_credentials(tmp_path):
    path = tmp_path / "default.vrd"
    path.write_bytes(VRD.encode("utf-8"))                                # bytes: no newline translation on Windows
    info = onec_tools._vrd_details(path)
    assert info["odata"]["enabled"] is False and info["odata"]["element_present"] is True
    assert SENT_USER not in json.dumps(info) and SENT_PW not in json.dumps(info)
    assert "Pwd=***" in info["ib"] and "Usr=***" in info["ib"] and info["ib_parts"] == {"file": "C:\\db"}
    assert info["sha256"] == _sha(path.read_bytes()) == _sha(VRD.encode("utf-8"))


def test_vrd_details_rejects_utf16_oversize_and_dtd(tmp_path):
    path = tmp_path / "default.vrd"
    path.write_bytes(VRD.encode("utf-16"))
    with pytest.raises(PolicyError, match="XML_ENCODING_NOT_ALLOWED"):
        onec_tools._vrd_details(path)
    path.write_bytes(b"<point>" + b" " * (onec_tools.MAX_VRD_BYTES + 1) + b"</point>")
    with pytest.raises(PolicyError, match="FILE_TOO_LARGE"):
        onec_tools._vrd_details(path)
    path.write_bytes(b'<!DOCTYPE point [<!ENTITY a "b">]><point/>')
    with pytest.raises(PolicyError, match="XML_DTD_NOT_ALLOWED"):
        onec_tools._vrd_details(path)
    assert onec_tools._vrd_details(tmp_path / "missing.vrd")["exists"] is False


def test_collect_conf_finds_publication_module_and_listen(tmp_path):
    root = tmp_path / "Apache24"
    (root / "conf" / "extra").mkdir(parents=True)
    pub = tmp_path / "pubs" / "acc"
    pub.mkdir(parents=True)
    (pub / "default.vrd").write_bytes(VRD.encode("utf-8"))
    (root / "conf" / "httpd.conf").write_bytes(
        b'Listen 8080\nLoadModule _1cws_module "C:/Program Files/1cv8/8.3.24.1/bin/wsap24.dll"\n'
        b'Include conf/extra/*.conf\n')
    (root / "conf" / "extra" / "1c.conf").write_bytes(
        (f'Alias "/acc" "{pub.as_posix()}"\n<Directory "{pub.as_posix()}">\n'
         f'  SetHandler 1c-application\n  ManagedApplicationDescriptor "{(pub / "default.vrd").as_posix()}"\n</Directory>\n'
         ).encode("utf-8"))
    install = {"server_root": str(root), "conf": str(root / "conf" / "httpd.conf")}
    conf = onec_tools._collect_conf(install)
    assert conf["listen"] == ["8080"] and "_1cws_module" in conf["modules"]
    assert conf["publications"][0]["name"] == "acc" and conf["errors"] == [] and conf["truncated"] is False


def test_collect_conf_refuses_includes_outside_apache_roots_and_caps_the_tree(tmp_path):
    root = tmp_path / "Apache24"
    (root / "conf").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "x.conf").write_bytes(b"Listen 9999\n")
    for sub in "abc":
        (root / "conf" / sub).mkdir()
        for i in range(30):
            (root / "conf" / sub / f"{i:02}.conf").write_bytes(b"# empty\n")
    (root / "conf" / "httpd.conf").write_bytes(
        (f'Include "{outside.as_posix()}/x.conf"\nInclude conf/a/*.conf\nInclude conf/b/*.conf\n'
         'Include conf/c/*.conf\n').encode("utf-8"))
    conf = onec_tools._collect_conf({"server_root": str(root), "conf": str(root / "conf" / "httpd.conf")})
    assert any(e["error"] == "OUTSIDE_APACHE_ROOTS" for e in conf["errors"])
    assert 9999 not in [int(p) for p in conf["listen"] if p.isdigit()]       # the outside file was NOT read
    assert conf["truncated"] is True and len(conf["files"]) <= 50


def test_collect_conf_expands_srvroot_and_resolves_relative_module(tmp_path):
    root = tmp_path / "Apache24"
    (root / "conf" / "extra").mkdir(parents=True)
    (root / "conf" / "extra" / "m.conf").write_bytes(b'LoadModule x_module modules/mod_x.so\nListen 127.0.0.1:81\n')
    (root / "conf" / "httpd.conf").write_bytes(b'Include ${SRVROOT}/conf/extra/m.conf\n')
    conf = onec_tools._collect_conf({"server_root": str(root), "conf": str(root / "conf" / "httpd.conf")})
    assert conf["modules"]["x_module"] == str(root / "modules" / "mod_x.so")
    assert conf["listen"] == ["127.0.0.1:81"]


@pytest.mark.parametrize("listen, expected", [
    ("8080", ("127.0.0.1", 8080)), ("0.0.0.0:80", ("127.0.0.1", 80)), ("*:81", ("127.0.0.1", 81)),
    ("[::1]:8080", ("::1", 8080)), ("127.0.0.1:82 https", ("127.0.0.1", 82)), ("bad", None), ("host:port", None),
])
def test_listen_endpoint_parsing(listen, expected):
    assert onec_tools._listen_endpoint(listen) == expected


def test_tcp_check_never_connects_to_non_allowlisted_hosts():
    assert onec_tools._tcp_check("evil.example", 80) == {
        "host": "evil.example", "port": 80, "checked": False, "reason": "HOST_NOT_ALLOWED_FOR_PROBE"}


# ================================================================ Apache fixture
def _write_conf(root: Path, pubs: list[tuple[str, Path, Path]]) -> Path:
    """pubs: (alias, directory, vrd file). Everything is written as bytes (no EOL translation)."""
    lines = ["Listen 8080", f'LoadModule _1cws_module "{root.as_posix()}/modules/wsap24.dll"']
    for alias, directory, vrd in pubs:
        lines += [f'Alias "{alias}" "{directory.as_posix()}"', f'<Directory "{directory.as_posix()}">',
                  "  SetHandler 1c-application", f'  ManagedApplicationDescriptor "{vrd.as_posix()}"', "</Directory>"]
    conf = root / "conf" / "httpd.conf"
    conf.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    return conf


@pytest.fixture()
def apache(tmp_path, monkeypatch, native_overlay):
    root = tmp_path / "Apache24"
    (root / "bin").mkdir(parents=True)
    (root / "bin" / "httpd.exe").write_bytes(b"MZ")
    (root / "conf").mkdir()
    pub = root / "htdocs" / "acc"
    pub.mkdir(parents=True)
    vrd = pub / "default.vrd"
    vrd.write_bytes(VRD.encode("utf-8"))
    conf = _write_conf(root, [("/acc", pub, vrd)])
    native_overlay(apache_roots=[str(root)])
    monkeypatch.setattr(onec_tools, "ps_json", lambda *a, **k: [])       # no real Windows service query
    monkeypatch.setattr(onec_tools, "_configtest", lambda install: {"ok": True, "exit_code": 0, "output": "Syntax OK"})
    return SimpleNamespace(root=root, pub=pub, vrd=vrd, conf=conf, original=VRD.encode("utf-8"))


def _grant(pending):
    common.grant_approval(pending["approval_id"])
    return pending["approval_id"]


def test_discover_apache_returns_installs_and_degraded_flag(apache, monkeypatch):
    installs, degraded = onec_tools.discover_apache()
    assert degraded is False and len(installs) == 1
    assert installs[0]["server_root"] == str(apache.root) and installs[0]["exe_exists"] and installs[0]["conf_exists"]
    assert installs[0]["service"] is None

    def failing(*a, **k):
        raise PolicyError("POWERSHELL_FAILED")
    monkeypatch.setattr(onec_tools, "ps_json", failing)
    installs, degraded = onec_tools.discover_apache()
    assert degraded is True and len(installs) == 1                     # file-based discovery still works

    monkeypatch.setattr(onec_tools, "ps_json", lambda *a, **k: {
        "Name": "Apache2.4", "State": "Running", "StartMode": "Auto",
        "PathName": '"C:\\Apache24\\bin\\httpd.exe" -k runservice'})
    installs, degraded = onec_tools.discover_apache()
    service = [i for i in installs if i["service"]]
    assert degraded is False and service and service[0]["service"]["name"] == "Apache2.4"
    assert service[0]["httpd_exe"] == "C:\\Apache24\\bin\\httpd.exe" and service[0]["server_root"] == "C:\\Apache24"
    assert service[0]["service"]["state"] == "Running"


def test_pick_apache_selection_rules(tmp_path, monkeypatch, native_overlay):
    monkeypatch.setattr(onec_tools, "ps_json", lambda *a, **k: [])
    base = tmp_path / "apaches"
    for name in ("A", "B"):
        (base / name / "bin").mkdir(parents=True)
        (base / name / "bin" / "httpd.exe").write_bytes(b"MZ")
    native_overlay(apache_roots=[str(tmp_path / "nothing-here")])
    with pytest.raises(PolicyError, match="APACHE_NOT_FOUND"):
        onec_tools._pick_apache()
    native_overlay(apache_roots=[str(base)])
    with pytest.raises(PolicyError, match="MULTIPLE_APACHE_INSTALLS_SPECIFY_server_root"):
        onec_tools._pick_apache()
    assert onec_tools._pick_apache(str(base / "A"))["server_root"] == str(base / "A")
    with pytest.raises(PolicyError, match="APACHE_ROOT_NOT_DISCOVERED"):
        onec_tools._pick_apache(str(base / "C"))


def test_apache_diagnostics_reports_findings_without_leaking_credentials(apache, isolated_state):
    report = onec_tools.apache_diagnostics()
    ids = {f["id"] for f in report["findings"]}
    assert {"ODATA_DISABLED", "ONEC_MODULE_FILE_MISSING"} <= ids
    assert report["discovery_degraded"] is False and report["installs"][0]["publications"][0]["name"] == "acc"
    onec_tools.onec_publication_inspect("acc")
    onec_tools.onec_connection_check("acc")
    everything = json.dumps(report) + (isolated_state / "audit" / "native-audit.jsonl").read_text(encoding="utf-8")
    assert SENT_USER not in everything and SENT_PW not in everything


def test_apache_diagnostics_fails_closed_when_service_discovery_failed(apache, monkeypatch):
    def failing(*a, **k):
        raise PolicyError("POWERSHELL_FAILED")
    monkeypatch.setattr(onec_tools, "ps_json", failing)
    report = onec_tools.apache_diagnostics()
    assert report["discovery_degraded"] is True
    assert "SERVICE_DISCOVERY_FAILED" in {f["id"] for f in report["findings"]}


def test_inspect_and_connection_check_error_contract(apache):
    with pytest.raises(PolicyError, match="PUBLICATION_NOT_FOUND"):
        onec_tools.onec_publication_inspect("nope")
    with pytest.raises(PolicyError, match="NO_MATCHING_PUBLICATION"):
        onec_tools.onec_connection_check("nope")
    apache.vrd.write_bytes(VRD.encode("utf-16"))
    pub = onec_tools.onec_publication_inspect("acc")["publications"][0]
    assert pub["error"] == "XML_ENCODING_NOT_ALLOWED"                  # reported, not parsed, not crashing the listing


# ===================================================================== repair
def test_repair_plan_is_read_only_and_redacted(apache):
    plan = onec_tools.onec_publication_repair("acc")
    assert plan["status"] == "PLAN" and plan["plan"]["old_sha256"] == _sha(apache.original)
    assert plan["plan"]["new_sha256"] == _sha(onec_tools._enable_odata_text(VRD).encode("utf-8"))
    assert apache.vrd.read_bytes() == apache.original
    assert any('ib="***"' in line for line in plan["diff"])            # positive control: the ib line IS in the diff
    assert SENT_USER not in json.dumps(plan) and SENT_PW not in json.dumps(plan)


def test_repair_apply_requires_approval_and_matches_hash(apache, approvals_ready, isolated_state):
    plan = onec_tools.onec_publication_repair("acc")["plan"]
    pending = onec_tools.onec_publication_repair("acc", apply=True)
    assert pending["status"] == "APPROVAL_REQUIRED" and apache.vrd.read_bytes() == apache.original
    assert SENT_USER not in json.dumps(pending) and SENT_PW not in json.dumps(pending)
    rid = _grant(pending)
    applied = onec_tools.onec_publication_repair("acc", apply=True, approval_id=rid)
    assert applied["status"] == "APPLIED" and applied["new_sha256"] == plan["new_sha256"]
    written = apache.vrd.read_bytes()
    assert written == onec_tools._enable_odata_text(VRD).encode("utf-8") and _sha(written) == plan["new_sha256"]
    assert written.count(b"\r\n") == apache.original.count(b"\r\n") and b"\r\r\n" not in written
    backup = isolated_state / "backups" / applied["backup_id"]
    assert (backup / "default.vrd").read_bytes() == apache.original
    manifest = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["sha256"] == _sha(apache.original) and manifest["applied_sha256"] == plan["new_sha256"]
    assert onec_tools.onec_publication_repair("acc", apply=True, approval_id=rid)["status"] == "NO_CHANGE_NEEDED"
    apache.vrd.write_bytes(apache.original)                              # same plan again: the approval is spent
    with pytest.raises(PolicyError, match="APPROVAL_ALREADY_USED"):
        onec_tools.onec_publication_repair("acc", apply=True, approval_id=rid)
    assert apache.vrd.read_bytes() == apache.original


def test_repair_keeps_utf8_bom(apache, approvals_ready):
    apache.vrd.write_bytes(b"\xef\xbb\xbf" + apache.original)
    pending = onec_tools.onec_publication_repair("acc", apply=True)
    rid = _grant(pending)
    assert onec_tools.onec_publication_repair("acc", apply=True, approval_id=rid)["status"] == "APPLIED"
    assert apache.vrd.read_bytes().startswith(b"\xef\xbb\xbf<?xml") and b'enable="true"' in apache.vrd.read_bytes()


def test_repair_rollback_restores_exact_bytes(apache, approvals_ready, isolated_state):
    pending = onec_tools.onec_publication_repair("acc", apply=True)
    applied = onec_tools.onec_publication_repair("acc", apply=True, approval_id=_grant(pending))
    new_bytes = apache.vrd.read_bytes()
    plan = onec_tools.onec_publication_repair("acc", "rollback", backup_id=applied["backup_id"])
    assert plan["status"] == "PLAN" and plan["plan"]["restore_sha256"] == _sha(apache.original)
    assert plan["plan"]["current_sha256"] == _sha(new_bytes) and apache.vrd.read_bytes() == new_bytes
    pending = onec_tools.onec_publication_repair("acc", "rollback", apply=True, backup_id=applied["backup_id"])
    assert pending["status"] == "APPROVAL_REQUIRED"
    rolled = onec_tools.onec_publication_repair("acc", "rollback", apply=True, backup_id=applied["backup_id"],
                                                approval_id=_grant(pending))
    assert rolled["status"] == "ROLLED_BACK" and apache.vrd.read_bytes() == apache.original
    safety = isolated_state / "backups" / rolled["pre_rollback_backup_id"] / "default.vrd"
    assert safety.read_bytes() == new_bytes                            # the state we rolled away from is kept too


def test_rollback_validates_the_backup(apache, approvals_ready, isolated_state):
    with pytest.raises(PolicyError, match="INVALID_BACKUP_ID"):
        onec_tools.onec_publication_repair("acc", "rollback", backup_id="../x")
    with pytest.raises(PolicyError, match="INVALID_BACKUP_ID"):
        onec_tools.onec_publication_repair("acc", "rollback", backup_id="req-" + "0" * 12)
    with pytest.raises(PolicyError, match="BACKUP_NOT_FOUND"):
        onec_tools.onec_publication_repair("acc", "rollback", backup_id="bak-" + "0" * 12)
    with pytest.raises(PolicyError, match="UNSUPPORTED_REPAIR_OPERATION"):
        onec_tools.onec_publication_repair("acc", "delete_everything")
    applied = onec_tools.onec_publication_repair("acc", apply=True, approval_id=_grant(
        onec_tools.onec_publication_repair("acc", apply=True)))
    folder = isolated_state / "backups" / applied["backup_id"]
    manifest_path = folder / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_path.write_text(json.dumps(dict(manifest, original=str(apache.vrd.with_suffix(".txt")))), encoding="utf-8")
    with pytest.raises(PolicyError, match="BACKUP_MANIFEST_INVALID"):
        onec_tools.onec_publication_repair("acc", "rollback", backup_id=applied["backup_id"])
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    (folder / "default.vrd").write_bytes(b"tampered backup")
    with pytest.raises(PolicyError, match="BACKUP_INTEGRITY_FAILED"):
        onec_tools.onec_publication_repair("acc", "rollback", backup_id=applied["backup_id"])


def test_repair_post_check_failure_restores_original(apache, approvals_ready, monkeypatch, isolated_state):
    monkeypatch.setattr(onec_tools, "_configtest", lambda install: {
        "ok": b'enable="true"' not in apache.vrd.read_bytes(), "output": "Syntax error"})
    rid = _grant(onec_tools.onec_publication_repair("acc", apply=True))
    result = onec_tools.onec_publication_repair("acc", apply=True, approval_id=rid)
    assert result["status"] == "FAILED_ROLLED_BACK" and "POST_CHECK_FAILED_CONFIGTEST" in result["reason"]
    assert result["restored_verified"] is True and apache.vrd.read_bytes() == apache.original
    assert '"status": "ROLLED_BACK"' in (isolated_state / "audit" / "native-audit.jsonl").read_text(encoding="utf-8")


def test_repair_does_not_blame_the_change_for_an_already_broken_config(apache, approvals_ready, monkeypatch):
    monkeypatch.setattr(onec_tools, "_configtest", lambda install: {"ok": False, "output": "already broken"})
    rid = _grant(onec_tools.onec_publication_repair("acc", apply=True))
    result = onec_tools.onec_publication_repair("acc", apply=True, approval_id=rid)
    assert result["status"] == "APPLIED" and result["baseline_configtest_ok"] is False


def test_repair_write_verification_failure_restores_original(apache, approvals_ready, monkeypatch):
    real, state = onec_tools.atomic_write_bytes, {"corrupted": False}

    def flaky(path, data):
        if Path(path) == apache.vrd and not state["corrupted"]:
            state["corrupted"] = True
            return real(path, b"corrupted by a failing disk")
        return real(path, data)
    monkeypatch.setattr(onec_tools, "atomic_write_bytes", flaky)
    rid = _grant(onec_tools.onec_publication_repair("acc", apply=True))
    result = onec_tools.onec_publication_repair("acc", apply=True, approval_id=rid)
    assert result["status"] == "FAILED_ROLLED_BACK" and "WRITE_VERIFY_FAILED" in result["reason"]
    assert apache.vrd.read_bytes() == apache.original


def test_repair_refuses_when_the_file_changed_after_the_plan_was_approved(apache, approvals_ready, monkeypatch):
    rid = _grant(onec_tools.onec_publication_repair("acc", apply=True))
    real = onec_tools.approval_or_response

    def tamper_after_approval(*args, **kwargs):
        result = real(*args, **kwargs)
        if result is None:
            apache.vrd.write_bytes(apache.vrd.read_bytes() + b"<!-- edited by someone else -->\r\n")
        return result
    monkeypatch.setattr(onec_tools, "approval_or_response", tamper_after_approval)
    with pytest.raises(PolicyError, match="PUBLICATION_CHANGED_SINCE_PLAN"):
        onec_tools.onec_publication_repair("acc", apply=True, approval_id=rid)
    assert b"edited by someone else" in apache.vrd.read_bytes() and b'enable="true"' not in apache.vrd.read_bytes()


def test_repair_approval_does_not_survive_a_content_change(apache, approvals_ready):
    rid = _grant(onec_tools.onec_publication_repair("acc", apply=True))
    apache.vrd.write_bytes(apache.original.replace(b'reuseSessions="autouse"', b'reuseSessions="dontuse"'))
    with pytest.raises(PolicyError, match="APPROVAL_DIGEST_MISMATCH"):
        onec_tools.onec_publication_repair("acc", apply=True, approval_id=rid)


def test_repair_no_change_needed_when_already_enabled(apache, approvals_ready, isolated_state):
    apache.vrd.write_bytes(_vrd("true").encode("utf-8"))
    assert onec_tools.onec_publication_repair("acc", apply=True)["status"] == "NO_CHANGE_NEEDED"
    assert _approval_files(isolated_state) == []


def test_repair_rejects_utf16_descriptor_without_touching_it(apache, approvals_ready):
    apache.vrd.write_bytes(VRD.encode("utf-16"))
    before = apache.vrd.read_bytes()
    with pytest.raises(PolicyError, match="VRD_NOT_UTF8"):
        onec_tools.onec_publication_repair("acc", apply=True)
    assert apache.vrd.read_bytes() == before


def test_repair_descriptor_must_live_in_publication_roots(apache, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    outside = elsewhere / "default.vrd"
    outside.write_bytes(apache.original)
    _write_conf(apache.root, [("/acc", elsewhere, outside)])
    with pytest.raises(PolicyError, match="VRD_OUTSIDE_PUBLICATION_ROOTS"):
        onec_tools.onec_publication_repair("acc")


def test_repair_rejects_descriptor_reached_through_an_in_root_junction(apache, make_junction):
    link = make_junction(apache.root / "htdocs" / "link", apache.pub)
    _write_conf(apache.root, [("/acc", link, link / "default.vrd")])
    with pytest.raises(PolicyError, match="REPARSE_POINT_IN_PATH"):
        onec_tools.onec_publication_repair("acc")


def test_repair_refuses_ambiguous_publication_names(apache):
    second = apache.root / "htdocs" / "acc2"
    second.mkdir()
    (second / "default.vrd").write_bytes(apache.original)
    _write_conf(apache.root, [("/acc", apache.pub, apache.vrd), ("/acc", second, second / "default.vrd")])
    with pytest.raises(PolicyError, match="PUBLICATION_AMBIGUOUS"):
        onec_tools.onec_publication_repair("acc")


# ================================================================== recovery
@pytest.fixture()
def probe_result(monkeypatch):
    holder = {"value": {"reachable": True, "status": 200}, "calls": 0}

    def fake(*args, **kwargs):
        holder["calls"] += 1
        return holder["value"]
    monkeypatch.setattr(onec_tools, "odata_probe", fake)
    return holder


def test_recovery_plan_does_not_leak_internal_state(apache, approvals_ready, isolated_state):
    out = onec_tools.odata_recovery("acc")
    assert out["status"] == "PLAN" and out["plan"]["steps"][0]["step"] == "enable_standard_odata"
    assert "_new_bytes" not in out["plan"] and "_install" not in out["plan"] and out["plan_digest"]
    assert apache.vrd.read_bytes() == apache.original and _approval_files(isolated_state) == []


def test_recovery_apply_needs_approval_bound_to_the_steps(apache, approvals_ready, probe_result):
    pending = onec_tools.odata_recovery("acc", apply=True)
    assert pending["status"] == "APPROVAL_REQUIRED" and apache.vrd.read_bytes() == apache.original
    rid = _grant(pending)
    result = onec_tools.odata_recovery("acc", apply=True, approval_id=rid)
    assert result["status"] == "APPLIED" and result["results"][0]["ok"] is True
    assert b'enable="true"' in apache.vrd.read_bytes() and probe_result["calls"] == 1
    assert onec_tools.odata_recovery("acc", apply=True)["status"] == "NOTHING_TO_DO"


def test_recovery_reports_unhealthy_endpoint_after_applying(apache, approvals_ready, probe_result):
    probe_result["value"] = {"reachable": False, "error": "ConnectionRefusedError"}
    rid = _grant(onec_tools.odata_recovery("acc", apply=True))
    assert onec_tools.odata_recovery("acc", apply=True, approval_id=rid)["status"] == "APPLIED_BUT_ENDPOINT_NOT_HEALTHY"


def test_recovery_stops_at_first_failed_step_and_restores(apache, approvals_ready, probe_result, monkeypatch):
    monkeypatch.setattr(onec_tools, "_configtest", lambda install: {
        "ok": b'enable="true"' not in apache.vrd.read_bytes(), "output": "Syntax error"})
    rid = _grant(onec_tools.odata_recovery("acc", apply=True))
    result = onec_tools.odata_recovery("acc", apply=True, approval_id=rid)
    assert result["status"] == "STOPPED_AT_FAILED_STEP" and result["results"][0]["ok"] is False
    assert result["results"][0]["result"]["status"] == "FAILED_ROLLED_BACK"
    assert apache.vrd.read_bytes() == apache.original


def test_recovery_refuses_to_plan_when_config_is_invalid(apache, approvals_ready, isolated_state, monkeypatch):
    monkeypatch.setattr(onec_tools, "_configtest", lambda install: {"ok": False, "output": "Syntax error on line 3"})
    out = onec_tools.odata_recovery("acc", apply=True)
    assert out["status"] == "NOTHING_TO_DO" and out["plan"]["blocked"] is True
    assert _approval_files(isolated_state) == [] and apache.vrd.read_bytes() == apache.original


def test_recovery_fails_closed_when_service_discovery_is_degraded(apache, approvals_ready, isolated_state, monkeypatch):
    def failing(*a, **k):
        raise PolicyError("POWERSHELL_FAILED")
    monkeypatch.setattr(onec_tools, "ps_json", failing)
    out = onec_tools.odata_recovery("acc", apply=True)
    assert out["status"] == "NOTHING_TO_DO" and out["plan"]["blocked"] is True
    assert "fail closed" in " ".join(out["plan"]["notes"])
    assert _approval_files(isolated_state) == [] and apache.vrd.read_bytes() == apache.original


def test_recovery_requires_an_unambiguous_publication(apache, approvals_ready):
    out = onec_tools.odata_recovery("does-not-exist", apply=True)
    assert out["status"] == "NOTHING_TO_DO" and out["plan"]["blocked"] is True


# ====================================================================== OData
BASE = "http://127.0.0.1:8080/acc/odata/standard.odata"
EDMX = (b'<edmx:Edmx xmlns:edmx="http://schemas.microsoft.com/ado/2007/06/edmx"><edmx:DataServices>'
        b'<Schema xmlns="http://schemas.microsoft.com/ado/2009/11/edm"><EntityType Name="A"/>'
        b'<EntityContainer Name="C"><EntitySet Name="S1" EntityType="A"/><EntitySet Name="S2" EntityType="A"/>'
        b'</EntityContainer></Schema></edmx:DataServices></edmx:Edmx>')


@pytest.mark.parametrize("url, code", [
    ("http://evil.example/acc/odata/standard.odata", "ODATA_HOST_NOT_ALLOWED"),
    ("http://127.0.0.1.evil.example/acc/odata/standard.odata", "ODATA_HOST_NOT_ALLOWED"),
    ("http://localhost.evil.com/acc/odata/standard.odata", "ODATA_HOST_NOT_ALLOWED"),
    ("http://127.0.0.1@evil.example/acc/odata/standard.odata", "ODATA_HOST_NOT_ALLOWED"),
    ("ftp://127.0.0.1/acc/odata/standard.odata", "ODATA_HOST_NOT_ALLOWED"),
    ("file:///C:/Windows/win.ini", "ODATA_HOST_NOT_ALLOWED"),
    ("//127.0.0.1/acc/odata/standard.odata", "ODATA_HOST_NOT_ALLOWED"),
    ("http:///acc/odata/standard.odata", "ODATA_HOST_NOT_ALLOWED"),
    ("http://user:pw@127.0.0.1/acc/odata/standard.odata", "ODATA_URL_USERINFO_QUERY_FRAGMENT_NOT_ALLOWED"),
    ("http://user@127.0.0.1/acc/odata/standard.odata", "ODATA_URL_USERINFO_QUERY_FRAGMENT_NOT_ALLOWED"),
    ("http://:pw@127.0.0.1/acc/odata/standard.odata", "ODATA_URL_USERINFO_QUERY_FRAGMENT_NOT_ALLOWED"),
    ("http://127.0.0.1/acc/odata/standard.odata#fragment", "ODATA_URL_USERINFO_QUERY_FRAGMENT_NOT_ALLOWED"),
    ("http://127.0.0.1/acc/odata/standard.odata?x=1", "ODATA_URL_USERINFO_QUERY_FRAGMENT_NOT_ALLOWED"),
    ("http://127.0.0.1/acc/other", "ODATA_URL_MUST_TARGET_STANDARD_ODATA"),
    ("http://127.0.0.1/", "ODATA_URL_MUST_TARGET_STANDARD_ODATA"),
    ("http://127.0.0.1/acc/odata/standard.odata/../../secret", "ODATA_URL_MUST_TARGET_STANDARD_ODATA"),
    ("http://127.0.0.1/acc/odata/standard.odata/%2e%2e/x", "ODATA_URL_MUST_TARGET_STANDARD_ODATA"),
])
def test_odata_url_validation_rejects(url, code):
    with pytest.raises(PolicyError, match=code):
        onec_tools._odata_url("", url, "$metadata", "", False)
    with pytest.raises(PolicyError, match=code):
        onec_tools.odata_probe(url=url)                            # and the public tool refuses it before any network


def test_odata_url_host_rules_follow_the_operator_allowlist(native_overlay):
    host = socket.gethostname()
    assert onec_tools._odata_url("", f"http://{host}/acc/odata/standard.odata", "$metadata", "", False)
    assert onec_tools._odata_url("", "HTTP://LOCALHOST/Acc/OData/Standard.OData", "", "", False).endswith("/")
    native_overlay(odata_allowed_hosts=["127.0.0.1"])
    with pytest.raises(PolicyError, match="ODATA_HOST_NOT_ALLOWED"):
        onec_tools._odata_url("", "http://localhost/acc/odata/standard.odata", "", "", False)


@pytest.mark.parametrize("path", ["../../x", "..\\x", "%2e%2e/x", "%252e%252e/x", "a b", "a;b", "a\\b", "x" * 301,
                                  "a|b", "a`b", "a\nb", "a<b"])
def test_odata_path_validation_rejects(path):
    with pytest.raises(PolicyError, match="ODATA_PATH_INVALID"):
        onec_tools._odata_url("", BASE, path, "", False)


def test_odata_url_building():
    build = lambda path, credential=False: onec_tools._odata_url("", BASE, path, "", credential)   # noqa: E731
    assert build("$metadata") == BASE + "/$metadata" and build("") == BASE + "/"
    assert build("Catalog_X") == BASE + "/Catalog_X?$top=1&$format=json"
    assert build("Catalog_X?$select=Ref_Key") == BASE + "/Catalog_X?$select=Ref_Key&$top=1"
    assert build("Catalog_X?$top=5") == BASE + "/Catalog_X?$top=5"
    assert onec_tools._odata_url("", BASE + "/", "$metadata", "", False) == BASE + "/$metadata"
    cyrillic = build("Catalog_Номенклатура")
    assert "%D0%9D" in cyrillic and "Номенклатура" not in cyrillic


def test_credentialed_probe_is_limited_to_metadata_or_root_and_checks_before_network(isolated_state):
    for path in ("Catalog_X", "Catalog_X?$top=1", "Document_Y", "$metadata/../x"):
        with pytest.raises(PolicyError, match="CREDENTIALED_PROBE_ALLOWS_ONLY_METADATA_OR_ROOT|ODATA_PATH_INVALID"):
            onec_tools._odata_url("", BASE, path, "", True)
        with pytest.raises(PolicyError, match="CREDENTIALED_PROBE_ALLOWS_ONLY_METADATA_OR_ROOT|ODATA_PATH_INVALID"):
            onec_tools.odata_probe(url=BASE, path=path, credential_ref="ref1")
    assert onec_tools._odata_url("", BASE, "$metadata", "", True).endswith("/$metadata")
    assert onec_tools._odata_url("", BASE, "", "", True).endswith("/")
    with pytest.raises(PolicyError, match="ODATA_HOST_NOT_ALLOWED"):   # a credential is never sent to a foreign host
        onec_tools.odata_probe(url="http://evil.example/acc/odata/standard.odata", credential_ref="ref1")


def test_odata_publication_mode_builds_url_from_apache_listen(apache):
    url = onec_tools._odata_url("acc", "", "$metadata", "", False)
    assert url == "http://127.0.0.1:8080/acc/odata/standard.odata/$metadata"
    for bad in ("", "a/b", "a b", "a?b"):
        with pytest.raises(PolicyError, match="PUBLICATION_REQUIRED"):
            onec_tools._odata_url(bad, "", "$metadata", "", False)


def test_odata_probe_never_uses_proxies_or_follows_redirects(monkeypatch):
    captured = {}

    class _Opener:
        def open(self, *args, **kwargs):
            raise urllib.error.URLError(ConnectionRefusedError("refused"))

    def fake_build_opener(*handlers):
        captured["handlers"] = handlers
        return _Opener()
    monkeypatch.setattr(urllib.request, "build_opener", fake_build_opener)
    result = onec_tools.odata_probe(url=BASE)
    assert result["reachable"] is False and result["error"] == "ConnectionRefusedError"
    assert any(isinstance(h, urllib.request.ProxyHandler) and h.proxies == {} for h in captured["handlers"])
    assert onec_tools._NoRedirect in captured["handlers"]


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture()
def odata_server():
    seen, routes = [], {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            seen.append((self.path, dict(self.headers)))
            status, headers, body = routes.get(self.path.split("?")[0], (404, {}, b""))
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}/acc/odata/standard.odata"
    yield SimpleNamespace(base=base, routes=routes, seen=seen, path=lambda suffix: "/acc/odata/standard.odata/" + suffix)
    server.shutdown()
    server.server_close()


def test_odata_probe_metadata_end_to_end(odata_server, monkeypatch, isolated_state):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    odata_server.routes[odata_server.path("$metadata")] = (200, {"Content-Type": "application/xml"}, EDMX)
    result = onec_tools.odata_probe(url=odata_server.base)
    assert result["reachable"] is True and result["status"] == 200
    assert result["metadata"] == {"entity_types": 1, "entity_sets": 2, "sample_sets": ["S1", "S2"]}
    assert "Authorization" not in odata_server.seen[0][1]
    assert '"action": "odata.probe"' in (isolated_state / "audit" / "native-audit.jsonl").read_text(encoding="utf-8")


def test_odata_probe_does_not_follow_redirects(odata_server):
    odata_server.routes[odata_server.path("$metadata")] = (302, {"Location": "/evil"}, b"")
    odata_server.routes["/evil"] = (200, {}, b"EVIL")
    result = onec_tools.odata_probe(url=odata_server.base)
    assert result["reachable"] is True and result["status"] == 302
    assert [p for p, _ in odata_server.seen] == [odata_server.path("$metadata")]      # /evil was never requested


def test_odata_probe_reports_auth_challenge(odata_server):
    odata_server.routes[odata_server.path("$metadata")] = (401, {"WWW-Authenticate": 'Basic realm="1c"'}, b"")
    result = onec_tools.odata_probe(url=odata_server.base)
    assert result["status"] == 401 and result["auth_required"] == "Basic"


@pytest.mark.parametrize("body, error", [
    (b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>', "XML_DTD_NOT_ALLOWED"),
    (b"<a>" + b" " * 70000 + b"<!DOCTYPE x></a>", "XML_DTD_NOT_ALLOWED"),
    ("<a/>".encode("utf-16"), "XML_ENCODING_NOT_ALLOWED"),
    (b"<a><b></a>", "XML_INVALID"),
], ids=["entity", "late-doctype", "utf16", "malformed"])
def test_odata_probe_refuses_hostile_metadata(odata_server, body, error):
    odata_server.routes[odata_server.path("$metadata")] = (200, {"Content-Type": "application/xml"}, body)
    assert onec_tools.odata_probe(url=odata_server.base)["metadata"] == {"error": error}


def test_odata_probe_returns_counts_never_records(odata_server, isolated_state):
    payload = json.dumps({"value": [{"Description": "RECORD-CONTENT-SENT"}, {"Description": "second"}]}).encode()
    odata_server.routes[odata_server.path("Catalog_X")] = (200, {"Content-Type": "application/json"}, payload)
    result = onec_tools.odata_probe(url=odata_server.base, path="Catalog_X")
    assert result["records_returned"] == 2 and result["status"] == 200
    assert "RECORD-CONTENT-SENT" not in json.dumps(result)
    assert "RECORD-CONTENT-SENT" not in (isolated_state / "audit" / "native-audit.jsonl").read_text(encoding="utf-8")
    assert odata_server.seen[-1][0].endswith("/Catalog_X?$top=1&$format=json")
    odata_server.routes[odata_server.path("Catalog_%D0%9D")] = (200, {"Content-Type": "application/json"}, b"{}")
    onec_tools.odata_probe(url=odata_server.base, path="Catalog_Н")
    assert odata_server.seen[-1][0].startswith("/acc/odata/standard.odata/Catalog_%D0%9D")


def test_odata_probe_credential_is_sent_but_never_stored_or_returned(odata_server, isolated_state):
    path = common.secret_path("odata-ref1")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(common.dpapi_protect(("odatauser:" + SENT_ODATA_PW).encode("utf-8")))
    odata_server.routes[odata_server.path("$metadata")] = (200, {"Content-Type": "application/xml"}, EDMX)
    result = onec_tools.odata_probe(url=odata_server.base, credential_ref="ref1")
    header = odata_server.seen[0][1]["Authorization"]
    assert header == "Basic " + base64.b64encode(("odatauser:" + SENT_ODATA_PW).encode()).decode()   # it WAS sent
    persisted = json.dumps(result) + "\n".join(
        p.read_text(encoding="utf-8", errors="replace") for p in isolated_state.rglob("*")
        if p.is_file() and p.suffix in (".json", ".jsonl"))
    assert SENT_ODATA_PW not in persisted and header.split()[1] not in persisted
    assert result["credential_ref"] == "ref1"


def test_odata_probe_credential_reference_errors_send_nothing(odata_server):
    odata_server.routes[odata_server.path("$metadata")] = (200, {}, EDMX)
    with pytest.raises(PolicyError, match="INVALID_CREDENTIAL_REF"):
        onec_tools.odata_probe(url=odata_server.base, credential_ref="../x")
    with pytest.raises(PolicyError, match="CREDENTIAL_REF_NOT_PROVISIONED"):
        onec_tools.odata_probe(url=odata_server.base, credential_ref="missing")
    path = common.secret_path("odata-nocolon")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(common.dpapi_protect(b"nocolonhere"))
    with pytest.raises(PolicyError, match="CREDENTIAL_REF_MALFORMED"):
        onec_tools.odata_probe(url=odata_server.base, credential_ref="nocolon")
    assert odata_server.seen == []


def test_odata_probe_unreachable_is_reported_and_audited(isolated_state):
    port = _free_port()
    result = onec_tools.odata_probe(url=f"http://127.0.0.1:{port}/acc/odata/standard.odata", timeout_s=2)
    assert result["reachable"] is False and result["error"]
    assert '"status": "UNREACHABLE"' in (isolated_state / "audit" / "native-audit.jsonl").read_text(encoding="utf-8")
    assert onec_tools._tcp_check("127.0.0.1", port, 1.0)["open"] is False


# ================================================================== deployment
def test_installer_must_be_in_roots_and_known_type(tmp_path, native_overlay):
    roots = tmp_path / "inst"
    roots.mkdir()
    native_overlay(installer_roots=[str(roots)])
    bad = roots / "x.bat"
    bad.write_bytes(b"echo")
    with pytest.raises(PolicyError, match="INSTALLER_MUST_BE_EXISTING_MSI_OR_EXE"):
        deploy_tools.installer_verify(str(bad))
    with pytest.raises(PolicyError, match="INSTALLER_MUST_BE_EXISTING_MSI_OR_EXE"):
        deploy_tools.installer_verify(str(roots / "missing.msi"))
    outside = tmp_path / "x.msi"
    outside.write_bytes(b"MZ")
    with pytest.raises(PolicyError, match="outside allowed roots"):
        deploy_tools.installer_verify(str(outside))


def test_installer_hash_mismatch_is_rejected_before_any_signature_check(tmp_path, native_overlay):
    roots = tmp_path / "inst"
    roots.mkdir()
    native_overlay(installer_roots=[str(roots)])
    installer = roots / "a.msi"
    installer.write_bytes(b"not really an installer")
    result = deploy_tools.installer_verify(str(installer), "0" * 64)
    assert result["verdict"] == "REJECT_HASH_MISMATCH" and result["trusted"] is False
    assert result["sha256"] == _sha(b"not really an installer")
    with pytest.raises(PolicyError, match="INSTALLER_REJECTED:REJECT_HASH_MISMATCH"):
        deploy_tools.deployment_plan(str(installer), "0" * 64)


def test_deployment_plan_requires_pinned_hash(tmp_path):
    for bad in ("", "a" * 63, "g" * 64, "a" * 65):
        with pytest.raises(PolicyError, match="EXPECTED_SHA256_REQUIRED"):
            deploy_tools.deployment_plan(str(tmp_path / "a.msi"), bad)
    with pytest.raises(PolicyError, match="UNSUPPORTED_INSTALLER_PROFILE"):
        deploy_tools.deployment_plan(str(tmp_path / "a.msi"), "a" * 64, profile="custom")


def test_trust_decision_matrix(native_overlay):
    native_overlay(trusted_publishers=["Contoso"], trusted_thumbprints=["AB 12 cd"], trusted_installer_sha256=["F" * 64])
    trust = deploy_tools._trust
    assert trust({"status": "Valid", "subject": "CN=Contoso, O=Contoso Ltd", "thumbprint": "x"}, "h") == (True, "TRUSTED_PUBLISHER")
    assert trust({"status": "Valid", "subject": 'CN="Contoso", L=Oslo', "thumbprint": "x"}, "h")[0]
    assert trust({"status": "Valid", "subject": "CN=Other", "thumbprint": "ab12CD"}, "h") == (True, "TRUSTED_THUMBPRINT")
    assert trust({"status": "NotSigned"}, "f" * 64) == (True, "TRUSTED_HASH")             # hash pin overrides signature
    assert not trust({"status": "NotSigned"}, "h")[0]
    assert not trust({"status": "Valid", "subject": "CN=Evil", "thumbprint": "x"}, "h")[0]
    assert not trust({"status": "HashMismatch", "subject": "CN=Contoso", "thumbprint": "AB12CD"}, "h")[0]
    # exact RDN equality: look-alikes and substrings are not the publisher
    for spoof in ("CN=Contoso Evil Corp", "CN=NotContoso", "CN=Contoso.evil.example", "O=Evil, OU=Contoso",
                  "CN=evil, E=Contoso@evil.example"):
        assert not trust({"status": "Valid", "subject": spoof, "thumbprint": "x"}, "h")[0], spoof


def test_short_publisher_names_never_match(native_overlay):
    native_overlay(trusted_publishers=["Co", ""], trusted_thumbprints=[], trusted_installer_sha256=[])
    assert not deploy_tools._trust({"status": "Valid", "subject": "CN=Co", "thumbprint": "x"}, "h")[0]


def test_install_dir_confined_to_approved_roots(native_overlay, tmp_path):
    native_overlay(install_roots=[str(tmp_path / "apps")])
    assert deploy_tools._install_dir("") == ""
    assert deploy_tools._install_dir(str(tmp_path / "apps" / "x")) == str((tmp_path / "apps" / "x").resolve())
    with pytest.raises(PolicyError, match="INSTALL_DIR_OUTSIDE_APPROVED_ROOTS"):
        deploy_tools._install_dir(str(tmp_path / "other"))
    with pytest.raises(PolicyError, match="INSTALL_DIR_OUTSIDE_APPROVED_ROOTS"):
        deploy_tools._install_dir(str(tmp_path / "apps" / ".." / "other"))
    with pytest.raises(PolicyError, match="INSTALL_DIR_OUTSIDE_APPROVED_ROOTS"):
        deploy_tools._install_dir(str(tmp_path / "apps2"))                       # sibling sharing the prefix
    for name in ("a&b", "a^b", "a%b"):
        with pytest.raises(PolicyError, match="INSTALL_DIR_INVALID"):
            deploy_tools._install_dir(str(tmp_path / "apps" / name))


def test_install_dir_rejects_protected_locations_and_in_root_junctions(native_overlay, tmp_path, make_junction):
    native_overlay(install_roots=["C:\\Windows\\Temp\\pdc-test-root", str(tmp_path / "apps")])
    with pytest.raises(PolicyError, match="INSTALL_DIR_PROTECTED_LOCATION"):
        deploy_tools._install_dir("C:\\Windows\\Temp\\pdc-test-root\\app")
    real = tmp_path / "apps" / "real"
    real.mkdir(parents=True)
    link = make_junction(tmp_path / "apps" / "lnk", real)
    with pytest.raises(PolicyError, match="REPARSE_POINT_IN_PATH"):
        deploy_tools._install_dir(str(link / "x"))
