"""Bounded, integrity-checked binary upload/download for the trusted personal v2 MCP.

Data travels in base64 chunks; only final SHA256-verified bytes are committed.
No extraction, execution, deletion, external URLs or arbitrary target paths.

Hardening (v2.1): every path goes through the reparse-point aware
``winops.common.safe_path`` (junction/symlink/mount-point components are refused),
publication is an atomic same-directory rename that can never overwrite, stale
uploads expire, uploads are resumable (``binary_upload_status``), and every
operation lands in the hash-chained audit log.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import threading
import time
from pathlib import Path
from typing import Any

from mcp.types import ToolAnnotations
from personal_dc.audit import record
from personal_dc.policy import PolicyError

from .winops.common import audit as chain_audit
from .winops.common import assert_no_reparse_chain, limit, safe_path

_WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=True,
                         idempotentHint=False, openWorldHint=False)
_READ = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
_LOCK = threading.RLock()
_ROOT = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "Personal_DC_V2" / "run" / "uploads"
_MAX_SIZE = 25 * 1024 * 1024
_MAX_CHUNK = 64 * 1024
_MAX_DOWNLOAD_CHUNK = 192 * 1024
_MAX_OPEN_UPLOADS = 16
_UPLOAD_TTL_S = 24 * 3600
_ALLOWED_EXT = {".zip", ".pdf", ".png", ".jpg", ".jpeg", ".webp", ".txt", ".md",
                ".json", ".csv", ".xlsx", ".docx", ".pptx", ".mp4", ".bin"}
_NEVER_READ_EXT = {".pem", ".key", ".pfx", ".p12", ".kdbx", ".dpapi", ".ppk"}
_HEX = re.compile(r"^[a-f0-9]{64}$")
_ID = re.compile(r"^[a-f0-9]{32}$")
_HASH_CACHE: dict[tuple[str, int, int], str] = {}


def _both_audits(action: str, status: str, **details: Any) -> None:
    record(action, status, **details)
    chain_audit(action, status, **details)


def _target(path: str) -> Path:
    if not isinstance(path, str) or not path or "\x00" in path:
        raise PolicyError("INVALID_TARGET")
    destination = Path(path).resolve(strict=False)
    # Exact intended receiving directory plus existing policy-allowed roots.
    downloads = Path("D:/Downloads").resolve(strict=False)
    if destination.parent == downloads and destination.suffix.lower() in _ALLOWED_EXT:
        assert_no_reparse_chain(destination.parent, [downloads])
        if destination.exists() and destination.is_symlink():
            raise PolicyError("REPARSE_POINT_IN_PATH")
        return destination
    safe = safe_path(path, write=True)
    if safe.suffix.lower() not in _ALLOWED_EXT:
        raise PolicyError("BINARY_EXTENSION_NOT_ALLOWED")
    return safe


def _paths(upload_id: str) -> tuple[Path, Path]:
    if not _ID.fullmatch(upload_id):
        raise PolicyError("INVALID_UPLOAD_ID")
    return _ROOT / (upload_id + ".json"), _ROOT / (upload_id + ".part")


def _purge_stale() -> None:
    now = time.time()
    for meta in _ROOT.glob("*.json"):
        try:
            if now - meta.stat().st_mtime > _UPLOAD_TTL_S:
                meta.with_suffix(".part").unlink(missing_ok=True)
                meta.unlink(missing_ok=True)
        except OSError:
            continue


def binary_upload_begin(path: str, total_bytes: int, sha256: str) -> dict[str, Any]:
    """Begin a bounded private file transfer; no data is published yet.

    Supports an inert .zip/.pdf/image or office file. Maximum 25 MiB.
    Use binary_upload_chunk and binary_upload_finish to complete.
    """
    dest = _target(path)
    if not isinstance(total_bytes, int) or type(total_bytes) is bool or not (1 <= total_bytes <= _MAX_SIZE):
        raise PolicyError("INVALID_UPLOAD_SIZE")
    if not isinstance(sha256, str) or not _HEX.fullmatch(sha256):
        raise PolicyError("INVALID_SHA256")
    with _LOCK:
        if dest.exists():
            raise FileExistsError("TARGET_EXISTS_NO_OVERWRITE")
        _ROOT.mkdir(parents=True, exist_ok=True)
        _purge_stale()
        if len(list(_ROOT.glob("*.json"))) >= _MAX_OPEN_UPLOADS:
            raise PolicyError("TOO_MANY_OPEN_UPLOADS")
        uid = secrets.token_hex(16)
        meta, part = _paths(uid)
        payload = {"dest": str(dest), "size": total_bytes, "sha256": sha256, "written": 0}
        with meta.open("x", encoding="utf-8") as f:
            json.dump(payload, f)
        with part.open("xb"):
            pass
        _both_audits("binary.begin", "OK", path=str(dest), size=total_bytes)
        return {"upload_id": uid, "max_chunk_bytes": _MAX_CHUNK,
                "remaining_bytes": total_bytes}


def binary_upload_chunk(upload_id: str, offset: int, data_base64: str) -> dict[str, Any]:
    """Append one base64 chunk, at most 64 KiB, with strict sequential offset."""
    if not isinstance(data_base64, str) or len(data_base64) > 88000:
        raise PolicyError("CHUNK_TOO_LARGE")
    try:
        chunk = base64.b64decode(data_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PolicyError("INVALID_BASE64") from exc
    if not chunk or len(chunk) > _MAX_CHUNK:
        raise PolicyError("INVALID_CHUNK_SIZE")
    with _LOCK:
        meta, part = _paths(upload_id)
        data = json.loads(meta.read_text(encoding="utf-8"))
        current = part.stat().st_size
        if type(offset) is not int or offset != current or offset != data["written"]:
            raise PolicyError("UPLOAD_OFFSET_MISMATCH")
        if current + len(chunk) > data["size"]:
            raise PolicyError("UPLOAD_SIZE_OVERFLOW")
        with part.open("ab") as f:
            f.write(chunk)
            f.flush()
            os.fsync(f.fileno())
        data["written"] = current + len(chunk)
        meta.write_text(json.dumps(data), encoding="utf-8")
        return {"upload_id": upload_id, "received_bytes": data["written"],
                "remaining_bytes": data["size"] - data["written"]}


def binary_upload_status(upload_id: str) -> dict[str, Any]:
    """Resume helper: how many verified-sequential bytes the server holds and the next offset to send."""
    with _LOCK:
        meta, part = _paths(upload_id)
        if not meta.is_file():
            raise PolicyError("UPLOAD_NOT_FOUND")
        data = json.loads(meta.read_text(encoding="utf-8"))
        size_on_disk = part.stat().st_size if part.exists() else 0
        if size_on_disk != data["written"]:
            # A crash between the chunk write and the metadata update: trust the bytes on disk.
            data["written"] = size_on_disk
            meta.write_text(json.dumps(data), encoding="utf-8")
        return {"upload_id": upload_id, "path": data["dest"], "total_bytes": data["size"],
                "received_bytes": data["written"], "next_offset": data["written"],
                "remaining_bytes": data["size"] - data["written"], "max_chunk_bytes": _MAX_CHUNK}


def binary_upload_abort(upload_id: str) -> dict[str, Any]:
    """Discard an unfinished upload (staging files only; never touches published files)."""
    with _LOCK:
        meta, part = _paths(upload_id)
        existed = meta.is_file()
        part.unlink(missing_ok=True)
        meta.unlink(missing_ok=True)
    _both_audits("binary.abort", "OK", upload_id=upload_id, existed=existed)
    return {"ok": True, "aborted": existed}


def binary_upload_finish(upload_id: str) -> dict[str, Any]:
    """Publish a completed file only when exact size and SHA256 match."""
    with _LOCK:
        meta, part = _paths(upload_id)
        data = json.loads(meta.read_text(encoding="utf-8"))
        dest = _target(data["dest"])
        if dest.exists():
            raise FileExistsError("TARGET_EXISTS_NO_OVERWRITE")
        if part.stat().st_size != data["size"] or data["written"] != data["size"]:
            raise PolicyError("UPLOAD_INCOMPLETE")
        digest = hashlib.sha256()
        with part.open("rb") as f:
            for block in iter(lambda: f.read(131072), b""):
                digest.update(block)
        if digest.hexdigest() != data["sha256"]:
            _both_audits("binary.finish", "DENIED", reason="SHA256_MISMATCH")
            raise PolicyError("SHA256_MISMATCH")
        dest.parent.mkdir(parents=True, exist_ok=True)
        # Re-check the parent chain immediately before publication (narrows the swap window).
        _target(str(dest))
        # Atomic publish: write a private temp file in the destination directory, fsync, then rename.
        # os.rename on Windows fails if the target exists, so an existing file is never replaced.
        tmp = dest.with_name("." + dest.name + "." + secrets.token_hex(4) + ".pdc-part")
        try:
            with tmp.open("xb") as out, part.open("rb") as inp:
                for block in iter(lambda: inp.read(131072), b""):
                    out.write(block)
                out.flush()
                os.fsync(out.fileno())
            os.rename(tmp, dest)
        except FileExistsError:
            tmp.unlink(missing_ok=True)
            raise FileExistsError("TARGET_EXISTS_NO_OVERWRITE") from None
        except OSError:
            tmp.unlink(missing_ok=True)
            raise
        part.unlink()
        meta.unlink()
        _both_audits("binary.finish", "OK", path=str(dest), size=data["size"], sha256=data["sha256"])
        return {"ok": True, "path": str(dest), "bytes": data["size"],
                "sha256": data["sha256"]}


def _file_sha256(path: Path, stat: os.stat_result) -> str:
    key = (str(path), stat.st_size, stat.st_mtime_ns)
    cached = _HASH_CACHE.get(key)
    if cached:
        return cached
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    if len(_HASH_CACHE) > 64:
        _HASH_CACHE.clear()
    _HASH_CACHE[key] = digest.hexdigest()
    return _HASH_CACHE[key]


def _readable(path: str) -> Path:
    safe = safe_path(path)
    if safe.suffix.lower() in _NEVER_READ_EXT:
        raise PolicyError("CREDENTIAL_MATERIAL_NOT_READABLE")
    if not safe.is_file():
        raise FileNotFoundError(str(safe))
    return safe


def file_info(path: str) -> dict[str, Any]:
    """Size, mtime and SHA-256 (files up to the download limit) of a file in an allowed root."""
    safe = _readable(path)
    st = safe.stat()
    out: dict[str, Any] = {"path": str(safe), "size": st.st_size, "mtime_ns": st.st_mtime_ns}
    if st.st_size <= limit("max_download_bytes"):
        out["sha256"] = _file_sha256(safe, st)
    return out


def binary_download_chunk(path: str, offset: int = 0, length: int = 65536) -> dict[str, Any]:
    """Read one base64 chunk (<=192 KiB) of a file; returns total size, full-file SHA-256 and EOF flag.

    The sha256 lets the client verify the reassembled file. Files above the configured download limit
    are refused. If the file changes mid-transfer the call fails with FILE_CHANGED_DURING_TRANSFER.
    """
    safe = _readable(path)
    st = safe.stat()
    if st.st_size > limit("max_download_bytes"):
        raise PolicyError("FILE_TOO_LARGE_FOR_DOWNLOAD")
    if type(offset) is not int or offset < 0 or offset > st.st_size:
        raise PolicyError("INVALID_OFFSET")
    length = max(1, min(int(length), _MAX_DOWNLOAD_CHUNK))
    sha = _file_sha256(safe, st)
    with safe.open("rb") as handle:
        after = os.fstat(handle.fileno())
        if after.st_size != st.st_size or after.st_mtime_ns != st.st_mtime_ns:
            raise PolicyError("FILE_CHANGED_DURING_TRANSFER")
        handle.seek(offset)
        data = handle.read(length)
    if offset == 0:
        _both_audits("binary.download", "OK", path=str(safe), size=st.st_size, sha256=sha)
    end = offset + len(data)
    return {"path": str(safe), "offset": offset, "length": len(data), "next_offset": end,
            "total_bytes": st.st_size, "sha256": sha, "eof": end >= st.st_size,
            "data_base64": base64.b64encode(data).decode("ascii")}


def register_binary_tools(server: Any) -> None:
    server.tool(annotations=_WRITE)(binary_upload_begin)
    server.tool(annotations=_WRITE)(binary_upload_chunk)
    server.tool(annotations=_WRITE)(binary_upload_finish)
    server.tool(annotations=_READ)(binary_upload_status)
    server.tool(annotations=_WRITE)(binary_upload_abort)
    server.tool(annotations=_READ)(binary_download_chunk)
    server.tool(annotations=_READ)(file_info)
