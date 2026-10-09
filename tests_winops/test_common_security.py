"""Approvals, audit chain, redaction and path safety."""
from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import pytest
from personal_dc.policy import PolicyError

from dc_v2.winops import common, registry

SENTINEL_PW = "Zq9-SENTINEL-pw-7731"
SENTINEL_TOKEN = "tokSENTINEL8842abcd"


# ---------------------------------------------------------------- redaction
def test_redaction_masks_values_and_keys():
    text = common.redact_text('Srvr="s";Usr="admin";Pwd="hunter2"; token=abc123 Authorization: Bearer abcdefghijkl')
    assert "hunter2" not in text and "abc123" not in text and "abcdefghijkl" not in text and "admin" not in text
    assert 'Srvr="s"' in text           # non-secret context survives (the redactor is not a blanket eraser)
    assert common.redact({"api_key": "x", "nested": {"password": "y"}, "ok": "fine"}) == {
        "api_key": "***REDACTED***", "nested": {"password": "***REDACTED***"}, "ok": "fine"}


@pytest.mark.parametrize("secret_text, leaked", [
    ("Authorization: Bearer abcdefghijkl", "abcdefghijkl"),
    ("curl -H 'Authorization: Bearer abcdefghijkl'", "abcdefghijkl"),
    ("Bearer abcdefghijkl", "abcdefghijkl"),
    ("bearer abcdefghijkl", "abcdefghijkl"),
    ("Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA"),
    ("api_key=ABCDEF123456", "ABCDEF123456"),
    ("PASSWORD: 'p@ss word'", "p@ss"),
])
def test_redact_text_removes_bearer_and_assignment_secrets(secret_text, leaked):
    out = common.redact_text(secret_text)
    assert leaked not in out
    assert "***" in out                  # something was actually masked, not merely dropped


def test_redaction_doubled_quotes_and_quot_entities():
    # 1C connection strings escape a quote inside a quoted value by doubling it.
    doubled = common.redact_text('Srvr="s";Pwd="Zq9""Xw7";Ref="acc"')
    assert "Zq9" not in doubled and "Xw7" not in doubled and 'Ref="acc"' in doubled
    entity = common.redact_text("File=&quot;C:\\db&quot;;Pwd=&quot;Zq9secret&quot;;")
    assert "Zq9secret" not in entity and "File=&quot;C:\\db&quot;" in entity


def test_redaction_ib_attribute_whole_value_including_entities():
    xml = '<point base="/a" ib="File=&quot;C:\\db&quot;;Usr=&quot;SENTUSER&quot;;Pwd=&quot;SENTPW&quot;;">'
    out = common.redact_text(xml)
    assert "SENTUSER" not in out and "SENTPW" not in out and "C:\\db" not in out
    assert 'ib="***"' in out and 'base="/a"' in out
    single = common.redact_text("<point ib='Srvr=\"s\";Pwd=\"SENTPW\"'>")
    assert "SENTPW" not in single


def test_redact_argv_secret_flag_value_is_masked_but_other_args_survive():
    argv = ["tool.exe", "--password", SENTINEL_PW, "--verbose", "--token", SENTINEL_TOKEN, "file.txt"]
    out = common.redact(argv)
    assert SENTINEL_PW not in out and SENTINEL_TOKEN not in out
    assert out[0] == "tool.exe" and "--verbose" in out and out[-1] == "file.txt"


def test_audit_never_writes_secrets_but_keeps_context(isolated_state):
    common.audit("test.leak", "OK", marker="visible-marker",
                 password=SENTINEL_PW, argv=["x.exe", "--password", SENTINEL_PW],
                 headers={"Authorization": "Bearer " + SENTINEL_TOKEN},
                 conn='Srvr="s";Pwd="' + SENTINEL_PW + '"',
                 text="note token=" + SENTINEL_TOKEN)
    raw = (isolated_state / "audit" / "native-audit.jsonl").read_text(encoding="utf-8")
    assert "visible-marker" in raw          # positive control: the event really is in the file we scanned
    assert SENTINEL_PW not in raw and SENTINEL_TOKEN not in raw
    tail = json.dumps(registry.native_audit_tail(10))
    assert "visible-marker" in tail and SENTINEL_PW not in tail and SENTINEL_TOKEN not in tail


def test_audit_clips_huge_fields_with_digest(isolated_state):
    common.audit("test.big", "OK", blob="x" * 50_000)
    raw = (isolated_state / "audit" / "native-audit.jsonl").read_text(encoding="utf-8")
    assert len(raw) < 10_000 and "chars sha256:" in raw


def test_audit_chain_detects_tampering(isolated_state):
    for i in range(3):
        common.audit("test.event", "OK", index=i, password="secret")
    assert common.audit_verify()["ok"] is True
    path = isolated_state / "audit" / "native-audit.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3 and "secret" not in "\n".join(lines).replace("***REDACTED***", "")
    event = json.loads(lines[1])
    event["status"] = "FORGED"
    lines[1] = json.dumps(event)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    verdict = common.audit_verify()
    assert verdict["ok"] is False and verdict["errors"][0]["line"] in (2, 3)


def test_audit_torn_last_line_is_flagged_and_chain_continues(isolated_state):
    common.audit("test.a", "OK")
    path = isolated_state / "audit" / "native-audit.jsonl"
    with path.open("ab") as handle:
        handle.write(b'{"seq": 2, "partial')           # crash mid-write: no newline
    common.audit("test.b", "OK")                         # must not glue onto the partial line
    verdict = common.audit_verify()
    assert verdict["ok"] is False and any(e["error"] == "UNPARSEABLE" for e in verdict["errors"])


def test_audit_concurrent_writers_keep_chain_intact(isolated_state):
    def write(i):
        common.audit("test.concurrent", "OK", index=i)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(write, range(40)))
    verdict = common.audit_verify()
    assert verdict["ok"] is True and verdict["events"] == 40


# ---------------------------------------------------------------- approvals
def _request(action="service.restart", params=None):
    params = params if params is not None else {"service": "Foo", "action": "restart"}
    payload = common.approval_or_response(action, params, None)
    assert payload["status"] == "APPROVAL_REQUIRED"
    return params, payload["approval_id"], payload


def test_approval_required_then_granted_once(approvals_ready):
    params, rid, payload = _request()
    assert payload["digest"] == common.digest_of("service.restart", params)
    with pytest.raises(PolicyError, match="APPROVAL_NOT_GRANTED"):
        common.require_approval("service.restart", params, rid)
    common.grant_approval(rid, 120)
    assert common.approval_or_response("service.restart", params, rid) is None
    with pytest.raises(PolicyError, match="APPROVAL_ALREADY_USED"):
        common.require_approval("service.restart", params, rid)


def test_pending_request_is_deduplicated_until_used(approvals_ready):
    params, rid, _ = _request()
    assert common.approval_or_response("service.restart", params, None)["approval_id"] == rid
    common.grant_approval(rid)
    common.require_approval("service.restart", params, rid)
    fresh = common.approval_or_response("service.restart", params, None)
    assert fresh["status"] == "APPROVAL_REQUIRED" and fresh["approval_id"] != rid


def test_approval_bound_to_exact_params(approvals_ready):
    rid = common.approval_or_response("service.stop", {"service": "A", "action": "stop"}, None)["approval_id"]
    common.grant_approval(rid)
    with pytest.raises(PolicyError, match="APPROVAL_DIGEST_MISMATCH"):
        common.require_approval("service.stop", {"service": "B", "action": "stop"}, rid)
    with pytest.raises(PolicyError, match="APPROVAL_DIGEST_MISMATCH"):
        common.require_approval("service.start", {"service": "A", "action": "stop"}, rid)
    # a digest mismatch must NOT burn the approval: the exact action can still use it
    assert not (common.approvals_dir() / (rid + ".used")).exists()
    common.require_approval("service.stop", {"service": "A", "action": "stop"}, rid)


def test_forged_grant_rejected(approvals_ready, isolated_state):
    params = {"x": 1}
    rid = common.approval_or_response("exec.elevated", params, None)["approval_id"]
    forged = {"id": rid, "action": "exec.elevated", "digest": common.digest_of("exec.elevated", params),
              "granted_at": common.iso(), "expires_at": "2999-01-01T00:00:00+00:00", "grantor": "x", "sig": "00" * 32}
    (isolated_state / "approvals" / (rid + ".grant.json")).write_text(json.dumps(forged), encoding="utf-8")
    with pytest.raises(PolicyError, match="APPROVAL_SIGNATURE_INVALID"):
        common.require_approval("exec.elevated", params, rid)
    assert not (isolated_state / "approvals" / (rid + ".used")).exists()


def test_tampered_signed_grant_rejected(approvals_ready, isolated_state):
    params = {"x": 11}
    rid = common.approval_or_response("exec.elevated", params, None)["approval_id"]
    common.grant_approval(rid)
    path = isolated_state / "approvals" / (rid + ".grant.json")
    grant = json.loads(path.read_text(encoding="utf-8"))
    grant["expires_at"] = "2999-01-01T00:00:00+00:00"        # extend lifetime without re-signing
    path.write_text(json.dumps(grant), encoding="utf-8")
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
    common.deny_approval(rid)                                   # operator changes their mind after granting
    with pytest.raises(PolicyError, match="APPROVAL_DENIED_BY_OPERATOR"):
        common.require_approval("exec.elevated", params, rid)
    with pytest.raises(PolicyError, match="REQUEST_WAS_DENIED"):
        common.grant_approval(rid)
    # a denied request is not handed out again: a new request gets a new id
    assert common.approval_or_response("exec.elevated", params, None)["approval_id"] != rid


def test_denied_marker_wins_even_over_a_valid_grant(approvals_ready, isolated_state):
    params = {"x": 3}
    rid = common.approval_or_response("exec.elevated", params, None)["approval_id"]
    common.grant_approval(rid)
    (isolated_state / "approvals" / (rid + ".denied")).write_text("x", encoding="utf-8")
    with pytest.raises(PolicyError, match="APPROVAL_DENIED_BY_OPERATOR"):
        common.require_approval("exec.elevated", params, rid)


def _resign(rid, **changes):
    """Rewrite a grant with changed fields and a VALID signature (what a compromised signer could do)."""
    path = common.approvals_dir() / (rid + ".grant.json")
    grant = json.loads(path.read_text(encoding="utf-8"))
    grant.pop("sig")
    grant.update(changes)
    grant["sig"] = common._sign(common._approval_key(), grant)
    path.write_text(json.dumps(grant), encoding="utf-8")


def test_expired_grant_rejected(approvals_ready):
    params = {"x": 4}
    rid = common.approval_or_response("exec.elevated", params, None)["approval_id"]
    common.grant_approval(rid)
    _resign(rid, expires_at=common.iso(common.utcnow() - timedelta(seconds=5)))
    with pytest.raises(PolicyError, match="APPROVAL_EXPIRED"):
        common.require_approval("exec.elevated", params, rid)
    assert not (common.approvals_dir() / (rid + ".used")).exists()


def test_grant_ttl_is_clamped(approvals_ready):
    _, rid, _ = _request(params={"x": 5})
    short = common.grant_approval(rid, 1)
    span = datetime.fromisoformat(short["expires_at"]) - datetime.fromisoformat(short["granted_at"])
    assert span >= timedelta(seconds=29)
    _, rid2, _ = _request(params={"x": 6})
    long = common.grant_approval(rid2, 10 ** 9)
    span = datetime.fromisoformat(long["expires_at"]) - datetime.fromisoformat(long["granted_at"])
    assert span <= timedelta(seconds=common.APPROVAL_TTL_MAX_S + 2)


def test_grant_copied_to_another_request_is_rejected(approvals_ready, isolated_state):
    """A valid signed grant for request A must not authorize request B, even for the same action."""
    params_a, rid_a, _ = _request("exec.elevated", {"x": "A"})
    params_b, rid_b, _ = _request("exec.elevated", {"x": "B"})
    common.grant_approval(rid_a)
    base = isolated_state / "approvals"
    (base / (rid_b + ".grant.json")).write_bytes((base / (rid_a + ".grant.json")).read_bytes())
    with pytest.raises(PolicyError, match="APPROVAL_GRANT_ID_MISMATCH"):
        common.require_approval("exec.elevated", params_b, rid_b)
    # ... and the original is still usable exactly once for its own parameters
    common.require_approval("exec.elevated", params_a, rid_a)


def test_concurrent_use_of_one_approval_succeeds_exactly_once(approvals_ready):
    params, rid, _ = _request("exec.elevated", {"x": "race"})
    common.grant_approval(rid)
    barrier = threading.Barrier(8)

    def attempt(_):
        barrier.wait()
        try:
            common.require_approval("exec.elevated", params, rid)
            return "ok"
        except PolicyError as exc:
            return str(exc)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(8)))
    assert results.count("ok") == 1
    assert results.count("APPROVAL_ALREADY_USED") == 7
    assert common.audit_verify()["ok"] is True


@pytest.mark.parametrize("bad", ["x", "../x", "req-", "tok-0123456789ab", "req-ZZZZZZZZZZZZ", "req-0123456789ab/../x"])
def test_malformed_approval_ids_rejected(approvals_ready, bad):
    with pytest.raises(PolicyError, match="INVALID_APPROVAL_ID"):
        common.require_approval("exec.elevated", {"x": 1}, bad)
    with pytest.raises(PolicyError, match="INVALID_APPROVAL_ID"):
        common.grant_approval(bad)


def test_grant_unknown_request_rejected(approvals_ready):
    with pytest.raises(PolicyError, match="APPROVAL_REQUEST_NOT_FOUND"):
        common.grant_approval("req-" + "0" * 16)


def test_oversized_params_cannot_be_approved_blind(approvals_ready):
    with pytest.raises(PolicyError, match="PARAMS_TOO_LARGE_TO_REVIEW"):
        common.request_approval("exec.elevated", {"blob": "y" * 60_000})


def test_approval_request_display_is_redacted_but_digest_binds_real_values(approvals_ready, isolated_state):
    params = {"args": ["x.exe", "--password", SENTINEL_PW], "note": "token=" + SENTINEL_TOKEN, "visible": "v-marker"}
    payload = common.request_approval("exec.elevated", params)
    stored = (isolated_state / "approvals" / (payload["approval_id"] + ".json")).read_text(encoding="utf-8")
    assert "v-marker" in stored and SENTINEL_PW not in stored and SENTINEL_TOKEN not in stored
    assert SENTINEL_PW not in json.dumps(payload) and SENTINEL_TOKEN not in json.dumps(payload)
    assert payload["digest"] == common.digest_of("exec.elevated", params)
    other = dict(params, args=["x.exe", "--password", "different"])
    assert common.digest_of("exec.elevated", other) != payload["digest"]


def test_security_status_reports_key_state(isolated_state):
    assert registry.native_security_status()["approval_key_provisioned"] is False
    common.init_approval_key()
    status = registry.native_security_status()
    assert status["approval_key_provisioned"] is True and status["audit"]["ok"] is True


# ---------------------------------------------------------------- paths
def test_safe_path_blocks_outside_and_out_of_root_junction(work, tmp_path, make_junction):
    inside = work / "a.txt"
    assert common.safe_path(str(inside), write=True) == inside.resolve()
    with pytest.raises(PolicyError, match="outside allowed roots"):
        common.safe_path(str(tmp_path / "elsewhere.txt"))
    target = tmp_path / "outside_dir"
    target.mkdir()
    junction = make_junction(work / "link", target)
    with pytest.raises(PolicyError):
        common.safe_path(str(junction / "file.txt"), write=True)


def test_safe_path_rejects_junction_inside_root_that_points_inside_root(work, make_junction):
    """The target is perfectly legal, so only the reparse-chain check can reject this."""
    real = work / "real"
    real.mkdir()
    (real / "f.txt").write_text("x", encoding="utf-8")
    link = make_junction(work / "link", real)
    assert common.safe_path(str(real / "f.txt")) == (real / "f.txt").resolve()      # control: direct path is fine
    with pytest.raises(PolicyError, match="REPARSE_POINT_IN_PATH"):
        common.safe_path(str(link / "f.txt"))
    with pytest.raises(PolicyError, match="REPARSE_POINT_IN_PATH"):
        common.safe_path(str(link / "new.txt"), write=True)
    with pytest.raises(PolicyError, match="REPARSE_POINT_IN_PATH"):
        common.safe_path(str(link))


def test_is_reparse_detects_junction_and_not_plain_dirs(work, make_junction):
    plain = work / "plain"
    plain.mkdir()
    link = make_junction(work / "lnk", plain)
    assert common.is_reparse(link) is True and common.is_reparse(plain) is False
    assert common.is_reparse(work / "missing") is False


def test_state_directory_is_protected_even_when_state_is_under_an_allowed_root(tmp_path, isolated_state, set_policy):
    set_policy(tmp_path)                               # now <tmp>/state is INSIDE an allowed root
    sibling = tmp_path / "work" / "ok.txt"
    assert common.safe_path(str(sibling)) == sibling.resolve()          # control: root is genuinely allowed
    for name in ("approvals/x.json", "secrets/approval-key.dpapi", "audit/native-audit.jsonl", "config/native.json"):
        with pytest.raises(PolicyError) as info:
            common.safe_path(str(isolated_state / name))
        assert "PROTECTED_LOCATION" in str(info.value) or "Credential material" in str(info.value)
    with pytest.raises(PolicyError, match="PROTECTED_LOCATION"):
        common.safe_path(str(isolated_state / "procs" / "new.txt"), write=True)
    with pytest.raises(PolicyError, match="PROTECTED_LOCATION"):
        common.safe_path(str(isolated_state))


@pytest.mark.parametrize("raw, code", [
    ("\\\\server\\share\\x.txt", "UNC_OR_DEVICE_PATH_NOT_ALLOWED"),
    ("//server/share/x.txt", "UNC_OR_DEVICE_PATH_NOT_ALLOWED"),
    ("\\\\?\\C:\\Windows\\win.ini", "UNC_OR_DEVICE_PATH_NOT_ALLOWED"),
    ("\\\\.\\PhysicalDrive0", "UNC_OR_DEVICE_PATH_NOT_ALLOWED"),
    ("C:relative.txt", "DRIVE_RELATIVE_PATH_NOT_ALLOWED"),
    ("", "INVALID_PATH"),
])
def test_safe_path_rejects_unc_device_and_drive_relative_syntax(raw, code):
    with pytest.raises(PolicyError, match=code):
        common.safe_path(raw)


def test_safe_path_rejects_ads_dots_spaces_and_device_names(work):
    base = str(work)
    with pytest.raises(PolicyError, match="ALTERNATE_DATA_STREAM_NOT_ALLOWED"):
        common.safe_path(base + "\\a.txt:hidden")
    with pytest.raises(PolicyError, match="ALTERNATE_DATA_STREAM_NOT_ALLOWED"):
        common.safe_path(base + "\\a.txt::$DATA")
    with pytest.raises(PolicyError, match="TRAILING_DOT_OR_SPACE_NOT_ALLOWED"):
        common.safe_path(base + "\\a.txt.")
    with pytest.raises(PolicyError, match="TRAILING_DOT_OR_SPACE_NOT_ALLOWED"):
        common.safe_path(base + "\\dir \\a.txt")
    with pytest.raises(PolicyError, match="RESERVED_DEVICE_NAME_NOT_ALLOWED"):
        common.safe_path(base + "\\CON")
    with pytest.raises(PolicyError, match="RESERVED_DEVICE_NAME_NOT_ALLOWED"):
        common.safe_path(base + "\\nul.txt")


def test_safe_path_protects_credentials_and_git_internals(work):
    for name, fragment in ((".env", "Protected file"), (".env.local", "Protected file"), ("id_rsa", "Protected file"),
                           ("k.pem", "Credential material"), ("x.kdbx", "Credential material"),
                           (".git\\config", "Protected path component")):
        with pytest.raises(PolicyError, match=fragment):
            common.safe_path(str(work) + "\\" + name)


def test_safe_path_extra_roots_widen_containment_but_keep_protection(tmp_path, work):
    downloads = tmp_path / "dl"
    downloads.mkdir()
    ok = downloads / "f.bin"
    assert common.safe_path(str(ok), write=True, extra_roots=[str(downloads)]) == ok.resolve()
    with pytest.raises(PolicyError, match="outside allowed roots"):
        common.safe_path(str(ok), write=True)                                   # control: without the extra root
    with pytest.raises(PolicyError, match="outside allowed roots"):
        common.safe_path(str(tmp_path / "other" / "f.bin"), write=True, extra_roots=[str(downloads)])
    for name in (".env", "k.pem", "id_rsa", ".git\\x"):
        with pytest.raises(PolicyError, match="PROTECTED_PATH"):
            common.safe_path(str(downloads) + "\\" + name, extra_roots=[str(downloads)])
    with pytest.raises(PolicyError, match="ALTERNATE_DATA_STREAM_NOT_ALLOWED"):
        common.safe_path(str(downloads) + "\\f.bin:s", extra_roots=[str(downloads)])


def test_safe_path_extra_root_still_rejects_state_dir_and_reparse(tmp_path, isolated_state, make_junction):
    downloads = tmp_path / "dl"
    real = downloads / "real"
    real.mkdir(parents=True)
    link = make_junction(downloads / "lnk", real)
    with pytest.raises(PolicyError, match="REPARSE_POINT_IN_PATH"):
        common.safe_path(str(link / "f.bin"), write=True, extra_roots=[str(downloads)])
    with pytest.raises(PolicyError, match="PROTECTED_LOCATION"):
        common.safe_path(str(isolated_state / "x.bin"), write=True, extra_roots=[str(tmp_path)])


def test_state_dir_env_override_points_below_tmp(tmp_path):
    assert common.state_dir() == (tmp_path / "state").resolve()
    assert common.state_subdir("probe").parent == common.state_dir()


def test_native_config_overlay_rejects_unknown_keys_and_wrong_types(native_overlay):
    native_overlay(not_a_real_key=["x"])
    with pytest.raises(PolicyError, match="NATIVE_CONFIG_INVALID_KEY_OR_TYPE"):
        common.native_config()
    (common.state_dir() / "config" / "native.json").write_text(json.dumps({"dev_executables": "git.exe"}), encoding="utf-8")
    with pytest.raises(PolicyError, match="NATIVE_CONFIG_INVALID_KEY_OR_TYPE"):
        common.native_config()


def test_native_config_defaults_do_not_trust_interpreters():
    trusted = {n.casefold() for n in common.native_config()["dev_executables"]}
    assert trusted == {"git.exe"}
    assert not trusted & {"python.exe", "node.exe", "npm.cmd", "pip.exe", "dotnet.exe", "powershell.exe", "cmd.exe"}
