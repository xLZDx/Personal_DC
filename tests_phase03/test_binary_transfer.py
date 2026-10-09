"""Binary transfer contract, integrity and bounded upload tests."""
from __future__ import annotations
import base64
import hashlib
from pathlib import Path

import pytest
from personal_dc.policy import PolicyError
from dc_v2 import binary_transfer as b


def _stage(monkeypatch, tmp_path):
    staging = tmp_path / "staging"
    staging.mkdir(exist_ok=True)
    monkeypatch.setattr(b, "_root", lambda: staging)


def test_chunked_roundtrip_and_sha256(monkeypatch, tmp_path):
    _stage(monkeypatch, tmp_path)
    destination = tmp_path / "fixture.zip"
    monkeypatch.setattr(b, "_target", lambda path: Path(path))
    raw = b"PK" + bytes(range(256)) * 600
    digest = hashlib.sha256(raw).hexdigest()
    session = b.binary_upload_begin(str(destination), len(raw), digest)
    uid = session["upload_id"]
    offset = 0
    while offset < len(raw):
        chunk = raw[offset:offset+32768]
        value = b.binary_upload_chunk(uid, offset, base64.b64encode(chunk).decode())
        offset += len(chunk)
        assert value["received_bytes"] == offset
    result = b.binary_upload_finish(uid)
    assert result["sha256"] == digest
    assert destination.read_bytes() == raw
    assert not list((tmp_path / "staging").iterdir())


def test_integrity_mismatch_refuses_publish(monkeypatch, tmp_path):
    _stage(monkeypatch, tmp_path)
    monkeypatch.setattr(b, "_target", lambda path: Path(path))
    dest = tmp_path / "bad.zip"
    u = b.binary_upload_begin(str(dest), 3, "0"*64)["upload_id"]
    b.binary_upload_chunk(u, 0, base64.b64encode(b"abc").decode())
    with pytest.raises(PolicyError, match="SHA256_MISMATCH"):
        b.binary_upload_finish(u)
    assert not dest.exists()


def test_invalid_chunk_and_offset(monkeypatch, tmp_path):
    _stage(monkeypatch, tmp_path)
    monkeypatch.setattr(b, "_target", lambda path: Path(path))
    u = b.binary_upload_begin(str(tmp_path / "x.zip"), 10, hashlib.sha256(b"x"*10).hexdigest())["upload_id"]
    with pytest.raises(PolicyError, match="INVALID_BASE64"):
        b.binary_upload_chunk(u, 0, "NOT@@BASE64")
    with pytest.raises(PolicyError, match="UPLOAD_OFFSET_MISMATCH"):
        b.binary_upload_chunk(u, 1, base64.b64encode(b"x").decode())
    with pytest.raises(PolicyError, match="UPLOAD_SIZE_OVERFLOW"):
        b.binary_upload_chunk(u, 0, base64.b64encode(b"x"*11).decode())


def test_path_and_size_fail_closed():
    with pytest.raises(PolicyError):
        b._target("C:/Windows/System32/malware.exe")
    with pytest.raises(PolicyError, match="INVALID_UPLOAD_SIZE"):
        b.binary_upload_begin("D:/Downloads/x.zip", 26*1024*1024, "0"*64)
    with pytest.raises(PolicyError, match="INVALID_UPLOAD_ID"):
        b.binary_upload_finish("../etc/passwd")


def test_existing_destination_not_overwritten(monkeypatch, tmp_path):
    _stage(monkeypatch, tmp_path)
    monkeypatch.setattr(b, "_target", lambda path: Path(path))
    dest = tmp_path / "x.zip"
    dest.write_bytes(b"original")
    with pytest.raises(FileExistsError):
        b.binary_upload_begin(str(dest), 3, hashlib.sha256(b"abc").hexdigest())
    assert dest.read_bytes() == b"original"
