"""Binary transfer hardening and MCP tool registration."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import subprocess

import pytest
from personal_dc.policy import PolicyError

from dc_v2 import binary_transfer as bt


@pytest.fixture(autouse=True)
def upload_root(tmp_path, monkeypatch):
    monkeypatch.setattr(bt, "_ROOT", tmp_path / "uploads")


def _upload(path, data):
    begin = bt.binary_upload_begin(str(path), len(data), hashlib.sha256(data).hexdigest())
    uid, off = begin["upload_id"], 0
    while off < len(data):
        part = data[off:off + 1000]
        bt.binary_upload_chunk(uid, off, base64.b64encode(part).decode())
        off += len(part)
    return uid


def test_roundtrip_upload_download_and_hash(work):
    data = bytes(range(256)) * 50
    dest = work / "a.bin"
    uid = _upload(dest, data)
    assert bt.binary_upload_finish(uid)["sha256"] == hashlib.sha256(data).hexdigest()
    got, off = b"", 0
    while True:
        chunk = bt.binary_download_chunk(str(dest), off, 4096)
        got += base64.b64decode(chunk["data_base64"])
        off = chunk["next_offset"]
        if chunk["eof"]:
            break
    assert got == data and chunk["sha256"] == hashlib.sha256(data).hexdigest()
    assert not list(work.glob("*.pdc-part"))


def test_no_overwrite_even_if_target_appears_after_begin(work):
    data = b"x" * 10
    dest = work / "b.bin"
    uid = _upload(dest, data)
    dest.write_bytes(b"planted")
    with pytest.raises(FileExistsError):
        bt.binary_upload_finish(uid)
    assert dest.read_bytes() == b"planted"


def test_resume_status_and_abort(work):
    data = b"y" * 3000
    begin = bt.binary_upload_begin(str(work / "c.bin"), len(data), hashlib.sha256(data).hexdigest())
    bt.binary_upload_chunk(begin["upload_id"], 0, base64.b64encode(data[:1000]).decode())
    assert bt.binary_upload_status(begin["upload_id"])["next_offset"] == 1000
    with pytest.raises(PolicyError, match="UPLOAD_OFFSET_MISMATCH"):
        bt.binary_upload_chunk(begin["upload_id"], 0, base64.b64encode(data[:10]).decode())
    assert bt.binary_upload_abort(begin["upload_id"])["aborted"]


def test_sha_mismatch_not_published(work):
    begin = bt.binary_upload_begin(str(work / "d.bin"), 4, "0" * 64)
    bt.binary_upload_chunk(begin["upload_id"], 0, base64.b64encode(b"abcd").decode())
    with pytest.raises(PolicyError, match="SHA256_MISMATCH"):
        bt.binary_upload_finish(begin["upload_id"])
    assert not (work / "d.bin").exists()


def test_junction_target_rejected(work, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    subprocess.run(["cmd", "/c", "mklink", "/J", str(work / "j"), str(outside)], check=True, capture_output=True)
    with pytest.raises(PolicyError):
        bt.binary_upload_begin(str(work / "j" / "e.bin"), 1, "0" * 64)
    (outside / "secret.txt").write_text("s", encoding="utf-8")
    with pytest.raises(PolicyError):
        bt.binary_download_chunk(str(work / "j" / "secret.txt"))


def test_credential_material_not_downloadable(work):
    (work / "k.pem").write_text("key", encoding="utf-8")
    with pytest.raises(PolicyError, match="CREDENTIAL_MATERIAL_NOT_READABLE"):
        bt.binary_download_chunk(str(work / "k.pem"))


def test_all_native_tools_registered_and_no_unexpected_names():
    from dc_v2.native_personal_mcp import native_tools
    from dc_v2.winops.registry import TOOL_NAMES
    names = {t.name for t in asyncio.run(native_tools.list_tools())}
    assert set(TOOL_NAMES) <= names
    assert {"binary_upload_begin", "binary_download_chunk", "file_info", "write_text_file"} <= names
    forbidden = {"taskkill", "delete_file", "powershell_execute", "service_control", "approve", "grant_approval"}
    assert not (forbidden & names)
