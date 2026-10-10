"""Binary transfer hardening and MCP tool registration.

Uploads stage under ``<state>/run/uploads`` (the per-test private state directory); nothing is redirected by
patching module constants, so the real staging-directory logic is what gets exercised.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import os
from pathlib import Path

import pytest
from personal_dc.policy import PolicyError

from dc_v2 import binary_transfer as bt
from dc_v2.winops import common


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _upload(path, data, chunk=1000):
    begin = bt.binary_upload_begin(str(path), len(data), _sha(data))
    uid, off = begin["upload_id"], 0
    while off < len(data):
        part = data[off:off + chunk]
        bt.binary_upload_chunk(uid, off, _b64(part))
        off += len(part)
    return uid


def _staging(state):
    return state / "run" / "uploads"


def _audit_text(state):
    return (state / "audit" / "native-audit.jsonl").read_text(encoding="utf-8")


# ---------------------------------------------------------------- upload flow
def test_roundtrip_upload_download_and_hash(work, isolated_state):
    data = bytes(range(256)) * 50
    dest = work / "a.bin"
    uid = _upload(dest, data)
    assert (_staging(isolated_state) / (uid + ".part")).is_file()          # staged under the private state dir
    assert not dest.exists()                                                # nothing published before finish
    done = bt.binary_upload_finish(uid)
    assert done["sha256"] == _sha(data) and done["bytes"] == len(data) and Path(done["path"]) == dest.resolve()
    assert dest.read_bytes() == data
    got, off = b"", 0
    for _ in range(500):
        chunk = bt.binary_download_chunk(str(dest), off, 4096)
        got += base64.b64decode(chunk["data_base64"])
        off = chunk["next_offset"]
        if chunk["eof"]:
            break
    else:
        pytest.fail("download did not reach EOF")
    assert got == data and chunk["sha256"] == _sha(data) and chunk["total_bytes"] == len(data)
    assert not list(work.glob("*.pdc-part")) and not list(_staging(isolated_state).glob("*"))
    assert bt.file_info(str(dest))["sha256"] == _sha(data)
    text = _audit_text(isolated_state)
    assert '"action": "binary.begin"' in text and '"action": "binary.finish"' in text
    assert common.audit_verify()["ok"] is True


def test_finish_is_idempotent_after_a_cleanup_failure(work, monkeypatch):
    data = b"idempotent" * 100
    dest = work / "i.bin"
    uid = _upload(dest, data)
    real_cleanup = bt._cleanup
    monkeypatch.setattr(bt, "_cleanup", lambda meta, part: None)         # simulate staging files that could not be removed
    first = bt.binary_upload_finish(uid)
    monkeypatch.setattr(bt, "_cleanup", real_cleanup)
    again = bt.binary_upload_finish(uid)
    assert again["already_published"] is True and again["sha256"] == first["sha256"] and dest.read_bytes() == data
    with pytest.raises(PolicyError, match="UPLOAD_NOT_FOUND"):
        bt.binary_upload_finish(uid)                                      # fully cleaned up now


def test_retry_after_publication_detects_a_changed_target(work, monkeypatch):
    data = b"original" * 10
    dest = work / "c.bin"
    uid = _upload(dest, data)
    monkeypatch.setattr(bt, "_cleanup", lambda meta, part: None)
    bt.binary_upload_finish(uid)
    dest.write_bytes(b"someone changed it afterwards, with a different size")
    with pytest.raises(PolicyError, match="PUBLISHED_TARGET_CHANGED"):
        bt.binary_upload_finish(uid)
    assert dest.read_bytes().startswith(b"someone changed")


def test_no_overwrite_even_if_target_appears_after_begin(work):
    data = b"x" * 10
    dest = work / "b.bin"
    uid = _upload(dest, data)
    dest.write_bytes(b"planted")
    with pytest.raises(FileExistsError):
        bt.binary_upload_finish(uid)
    assert dest.read_bytes() == b"planted"


def test_no_overwrite_when_target_appears_during_the_final_rename(work, monkeypatch):
    """The window between the exists() check and the rename: os.rename must refuse, never replace."""
    data = b"y" * 64
    dest = work / "race.bin"
    uid = _upload(dest, data)
    real_rename = os.rename

    def racing_rename(src, dst):
        Path(dst).write_bytes(b"planted by a racing writer")
        return real_rename(src, dst)                                      # Windows: raises FileExistsError
    monkeypatch.setattr(bt.os, "rename", racing_rename)
    with pytest.raises(FileExistsError, match="TARGET_EXISTS_NO_OVERWRITE"):
        bt.binary_upload_finish(uid)
    assert dest.read_bytes() == b"planted by a racing writer"
    assert not list(work.glob("*.pdc-part")) and not list(work.glob(".*pdc-part"))     # temp file removed
    assert bt.binary_upload_status(uid)["received_bytes"] == len(data)               # upload kept, still resumable


def test_begin_refuses_existing_target(work):
    (work / "e.bin").write_bytes(b"here")
    with pytest.raises(FileExistsError, match="TARGET_EXISTS_NO_OVERWRITE"):
        bt.binary_upload_begin(str(work / "e.bin"), 1, "0" * 64)


def test_resume_status_and_abort(work):
    data = b"y" * 3000
    begin = bt.binary_upload_begin(str(work / "c.bin"), len(data), _sha(data))
    bt.binary_upload_chunk(begin["upload_id"], 0, _b64(data[:1000]))
    assert bt.binary_upload_status(begin["upload_id"])["next_offset"] == 1000
    with pytest.raises(PolicyError, match="UPLOAD_OFFSET_MISMATCH"):
        bt.binary_upload_chunk(begin["upload_id"], 0, _b64(data[:10]))
    assert bt.binary_upload_abort(begin["upload_id"]) == {"ok": True, "aborted": True}
    assert bt.binary_upload_abort(begin["upload_id"]) == {"ok": True, "aborted": False}
    with pytest.raises(PolicyError, match="UPLOAD_NOT_FOUND"):
        bt.binary_upload_status(begin["upload_id"])


def test_status_trusts_bytes_on_disk_after_a_crash_between_write_and_metadata(work):
    data = b"z" * 2000
    begin = bt.binary_upload_begin(str(work / "crash.bin"), len(data), _sha(data))
    uid = begin["upload_id"]
    bt.binary_upload_chunk(uid, 0, _b64(data[:500]))
    _, part = bt._paths(uid)
    with part.open("ab") as handle:                                       # bytes landed, metadata update was lost
        handle.write(data[500:1200])
    status = bt.binary_upload_status(uid)
    assert status["next_offset"] == 1200 and status["remaining_bytes"] == 800
    bt.binary_upload_chunk(uid, 1200, _b64(data[1200:]))
    assert bt.binary_upload_finish(uid)["sha256"] == _sha(data)


def test_sha_mismatch_not_published(work):
    begin = bt.binary_upload_begin(str(work / "d.bin"), 4, "0" * 64)
    bt.binary_upload_chunk(begin["upload_id"], 0, _b64(b"abcd"))
    with pytest.raises(PolicyError, match="SHA256_MISMATCH"):
        bt.binary_upload_finish(begin["upload_id"])
    assert not (work / "d.bin").exists() and not list(work.glob("*.pdc-part"))


def test_staging_file_modified_after_upload_is_caught_by_the_copy_time_hash(work):
    """Same size, different bytes: only hashing the bytes that are actually copied can detect this."""
    good = b"abcd"
    begin = bt.binary_upload_begin(str(work / "t.bin"), 4, _sha(good))
    uid = begin["upload_id"]
    bt.binary_upload_chunk(uid, 0, _b64(good))
    _, part = bt._paths(uid)
    part.write_bytes(b"abXd")
    with pytest.raises(PolicyError, match="SHA256_MISMATCH"):
        bt.binary_upload_finish(uid)
    assert not (work / "t.bin").exists() and not list(work.glob(".*pdc-part")) and not list(work.glob("*.pdc-part"))


def test_incomplete_upload_cannot_be_finished(work):
    data = b"q" * 10
    begin = bt.binary_upload_begin(str(work / "inc.bin"), 10, _sha(data))
    bt.binary_upload_chunk(begin["upload_id"], 0, _b64(data[:5]))
    with pytest.raises(PolicyError, match="UPLOAD_INCOMPLETE"):
        bt.binary_upload_finish(begin["upload_id"])
    assert not (work / "inc.bin").exists()


@pytest.mark.parametrize("size", [0, -1, 25 * 1024 * 1024 + 1, True, "5", 1.5, None])
def test_invalid_upload_size_rejected(work, size):
    with pytest.raises(PolicyError, match="INVALID_UPLOAD_SIZE"):
        bt.binary_upload_begin(str(work / "s.bin"), size, "0" * 64)


@pytest.mark.parametrize("digest", ["", "xyz", "A" * 64, "a" * 63, "a" * 65, None, 5])
def test_invalid_sha_rejected(work, digest):
    with pytest.raises(PolicyError, match="INVALID_SHA256"):
        bt.binary_upload_begin(str(work / "s.bin"), 1, digest)


@pytest.mark.parametrize("name", ["x.exe", "x.bat", "x.dll", "x.ps1", "noextension", "x.bin.exe"])
def test_executable_and_unknown_extensions_rejected(work, name):
    with pytest.raises(PolicyError, match="BINARY_EXTENSION_NOT_ALLOWED"):
        bt.binary_upload_begin(str(work / name), 1, "0" * 64)


def test_extension_check_is_case_insensitive_and_target_syntax_is_validated(work):
    assert bt.binary_upload_begin(str(work / "UP.ZIP"), 1, "0" * 64)["upload_id"]
    for raw, code in (("", "INVALID_TARGET"), (None, "INVALID_TARGET"), ("a\x00b.bin", "INVALID_TARGET"),
                      (str(work) + "\\a.bin:stream", "ALTERNATE_DATA_STREAM_NOT_ALLOWED"),
                      ("\\\\server\\share\\a.bin", "UNC_OR_DEVICE_PATH_NOT_ALLOWED")):
        with pytest.raises(PolicyError, match=code):
            bt.binary_upload_begin(raw, 1, "0" * 64)


def test_chunk_validation(work):
    uid = bt.binary_upload_begin(str(work / "v.bin"), 3, "0" * 64)["upload_id"]
    with pytest.raises(PolicyError, match="INVALID_BASE64"):
        bt.binary_upload_chunk(uid, 0, "not base64!!")
    with pytest.raises(PolicyError, match="INVALID_CHUNK_SIZE"):
        bt.binary_upload_chunk(uid, 0, "")
    with pytest.raises(PolicyError, match="CHUNK_TOO_LARGE"):
        bt.binary_upload_chunk(uid, 0, "A" * 88001)
    with pytest.raises(PolicyError, match="INVALID_CHUNK_SIZE"):
        bt.binary_upload_chunk(uid, 0, _b64(b"x" * (64 * 1024 + 1)))
    with pytest.raises(PolicyError, match="UPLOAD_SIZE_OVERFLOW"):
        bt.binary_upload_chunk(uid, 0, _b64(b"abcd"))
    with pytest.raises(PolicyError, match="UPLOAD_OFFSET_MISMATCH"):
        bt.binary_upload_chunk(uid, "0", _b64(b"ab"))
    with pytest.raises(PolicyError, match="INVALID_UPLOAD_ID"):
        bt.binary_upload_chunk("../x", 0, _b64(b"ab"))
    with pytest.raises(PolicyError, match="UPLOAD_NOT_FOUND"):
        bt.binary_upload_chunk("a" * 32, 0, _b64(b"ab"))
    assert bt.binary_upload_status(uid)["received_bytes"] == 0           # none of the rejected chunks was appended


def test_open_upload_limit_and_stale_purge(work, isolated_state):
    ids = [bt.binary_upload_begin(str(work / f"u{i}.bin"), 1, "0" * 64)["upload_id"] for i in range(16)]
    with pytest.raises(PolicyError, match="TOO_MANY_OPEN_UPLOADS"):
        bt.binary_upload_begin(str(work / "u16.bin"), 1, "0" * 64)
    old_meta, old_part = bt._paths(ids[0])
    ancient = old_meta.stat().st_mtime - 25 * 3600
    for item in (old_meta, old_part):
        os.utime(item, (ancient, ancient))
    orphan_old = _staging(isolated_state) / ("b" * 32 + ".part")
    orphan_new = _staging(isolated_state) / ("c" * 32 + ".part")
    orphan_old.write_bytes(b"x")
    orphan_new.write_bytes(b"x")
    os.utime(orphan_old, (ancient, ancient))
    bt.binary_upload_begin(str(work / "after.bin"), 1, "0" * 64)         # purge makes room and removes stale files
    assert not old_meta.exists() and not old_part.exists() and not orphan_old.exists() and orphan_new.exists()


def test_upload_target_may_use_configured_extra_root_but_never_the_state_dir(tmp_path, monkeypatch, isolated_state):
    downloads = tmp_path / "dl"
    downloads.mkdir()
    monkeypatch.setattr(bt, "_EXTRA_ROOTS", [str(downloads)])
    data = b"extra-root"
    uid = _upload(downloads / "ok.bin", data)
    assert bt.binary_upload_finish(uid)["bytes"] == len(data) and (downloads / "ok.bin").read_bytes() == data
    with pytest.raises(PolicyError, match="outside allowed roots"):
        bt.binary_upload_begin(str(tmp_path / "elsewhere" / "x.bin"), 1, "0" * 64)
    monkeypatch.setattr(bt, "_EXTRA_ROOTS", [str(tmp_path)])
    with pytest.raises(PolicyError, match="PROTECTED_LOCATION"):
        bt.binary_upload_begin(str(isolated_state / "run" / "x.bin"), 1, "0" * 64)
    with pytest.raises(PolicyError, match="PROTECTED_PATH"):
        bt.binary_upload_begin(str(tmp_path / ".git" / "x.bin"), 1, "0" * 64)


# ------------------------------------------------------------------ junctions
def test_junction_target_rejected_outside_root(work, tmp_path, make_junction):
    outside = tmp_path / "outside"
    outside.mkdir()
    make_junction(work / "j", outside)
    with pytest.raises(PolicyError):
        bt.binary_upload_begin(str(work / "j" / "e.bin"), 1, "0" * 64)
    (outside / "secret.txt").write_text("s", encoding="utf-8")
    with pytest.raises(PolicyError):
        bt.binary_download_chunk(str(work / "j" / "secret.txt"))


def test_junction_inside_root_pointing_inside_root_is_rejected(work, make_junction):
    real = work / "real"
    real.mkdir()
    (real / "s.txt").write_text("s", encoding="utf-8")
    link = make_junction(work / "lnk", real)
    with pytest.raises(PolicyError, match="REPARSE_POINT_IN_PATH"):
        bt.binary_upload_begin(str(link / "e.bin"), 1, "0" * 64)
    with pytest.raises(PolicyError, match="REPARSE_POINT_IN_PATH"):
        bt.binary_download_chunk(str(link / "s.txt"))
    with pytest.raises(PolicyError, match="REPARSE_POINT_IN_PATH"):
        bt.file_info(str(link / "s.txt"))
    assert bt.file_info(str(real / "s.txt"))["size"] == 1                 # control: the same file is fine directly


def test_directory_swapped_for_a_junction_between_begin_and_finish_is_caught(work, make_junction):
    data = b"swap" * 10
    real = work / "real"
    real.mkdir()
    sub = work / "sub"
    sub.mkdir()
    uid = _upload(sub / "x.bin", data)
    os.rmdir(sub)                                                         # attacker replaces the (empty) directory ...
    make_junction(sub, real)                                              # ... with a junction to another place
    with pytest.raises(PolicyError, match="REPARSE_POINT_IN_PATH"):
        bt.binary_upload_finish(uid)
    assert not (real / "x.bin").exists() and not list(real.iterdir())


# ------------------------------------------------------------------ download
@pytest.mark.parametrize("name, message", [
    ("k.pem", "Credential material is blocked"), ("store.kdbx", "Credential material is blocked"),
    ("id_rsa", "Protected file"), (".env", "Protected file"), (".env.production", "Protected file"),
    (".git/config", "Protected path component"),
])
def test_credential_material_not_downloadable(work, name, message):
    target = work / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("key", encoding="utf-8")
    with pytest.raises(PolicyError, match=message):
        bt.binary_download_chunk(str(target))
    with pytest.raises(PolicyError, match=message):
        bt.file_info(str(target))


def test_state_directory_is_not_downloadable_even_under_an_allowed_root(tmp_path, isolated_state, set_policy):
    set_policy(tmp_path)
    common.audit("test.event", "OK")
    with pytest.raises(PolicyError, match="PROTECTED_LOCATION"):
        bt.binary_download_chunk(str(isolated_state / "audit" / "native-audit.jsonl"))


def test_download_error_contract(work, native_overlay):
    data = b"0123456789" * 40
    target = work / "d.bin"
    target.write_bytes(data)
    with pytest.raises(FileNotFoundError):
        bt.binary_download_chunk(str(work / "missing.bin"))
    with pytest.raises(FileNotFoundError):
        bt.binary_download_chunk(str(work))                               # a directory is not a file
    for bad in (-1, len(data) + 1, True, "0", 1.5):
        with pytest.raises(PolicyError, match="INVALID_OFFSET"):
            bt.binary_download_chunk(str(target), bad)
    assert bt.binary_download_chunk(str(target), len(data))["eof"] is True      # offset == size is a valid empty tail
    with pytest.raises(PolicyError, match="FILE_CHANGED_DURING_TRANSFER"):
        bt.binary_download_chunk(str(target), 0, 10, expected_sha256="0" * 64)
    assert bt.binary_download_chunk(str(target), 0, 10, expected_sha256=_sha(data).upper())["length"] == 10
    native_overlay(limits={"max_download_bytes": 10})
    with pytest.raises(PolicyError, match="FILE_TOO_LARGE_FOR_DOWNLOAD"):
        bt.binary_download_chunk(str(target))
    assert "sha256" not in bt.file_info(str(target))                      # info still works, but does not hash huge files


def test_download_chunk_is_clamped_and_detects_a_file_that_changes_between_chunks(work):
    data = os.urandom(300_000)
    target = work / "big.bin"
    target.write_bytes(data)
    first = bt.binary_download_chunk(str(target), 0, 10 ** 9)
    assert first["length"] == 192 * 1024 and first["eof"] is False and first["next_offset"] == 192 * 1024
    target.write_bytes(data + b"appended")
    with pytest.raises(PolicyError, match="FILE_CHANGED_DURING_TRANSFER"):
        bt.binary_download_chunk(str(target), first["next_offset"], 1000, expected_sha256=first["sha256"])


# --------------------------------------------------------------- registration
def test_all_native_tools_registered_and_no_unexpected_names():
    from dc_v2.native_personal_mcp import native_tools
    from dc_v2.winops.registry import TOOL_NAMES
    tools = asyncio.run(native_tools.list_tools())
    listed = [t.name for t in tools]
    names = set(listed)
    assert len(listed) == len(names)                                      # re-registration must replace, never duplicate
    assert set(TOOL_NAMES) <= names
    assert {"binary_upload_begin", "binary_download_chunk", "file_info", "write_text_file"} <= names
    forbidden = {"taskkill", "delete_file", "powershell_execute", "service_control", "approve", "grant_approval"}
    assert not (forbidden & names)


def test_v1_code_running_tools_expose_approval_id_in_the_v2_schema():
    from dc_v2.native_personal_mcp import native_tools
    schemas = {t.name: t.inputSchema for t in asyncio.run(native_tools.list_tools())}
    for name in ("git_push", "run_project_tests"):
        assert "approval_id" in schemas[name]["properties"], name
    assert "approval_id" not in schemas["read_text_file"]["properties"]   # other v1 tools are left untouched
