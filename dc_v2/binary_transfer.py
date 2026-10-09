"""Bounded, integrity-checked binary upload for the trusted personal v2 MCP.

Data travels in base64 chunks; only final SHA256-verified bytes are committed.
No extraction, execution, deletion, external URLs or arbitrary target paths.
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
from pathlib import Path
from typing import Any

from mcp.types import ToolAnnotations
from personal_dc.audit import record
from personal_dc.policy import Policy, PolicyError

_WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=True,
                         idempotentHint=False, openWorldHint=False)
_LOCK = threading.RLock()
_ROOT = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "Personal_DC_V2" / "run" / "uploads"
_MAX_SIZE = 25 * 1024 * 1024
_MAX_CHUNK = 64 * 1024
_ALLOWED_EXT = {".zip", ".pdf", ".png", ".jpg", ".jpeg", ".webp", ".txt", ".md",
                ".json", ".csv", ".xlsx", ".docx", ".pptx", ".mp4", ".bin"}
_HEX = re.compile(r"^[a-f0-9]{64}$")
_ID = re.compile(r"^[a-f0-9]{32}$")


def _target(path: str) -> Path:
    if not isinstance(path, str) or not path or "\\x00" in path:
        raise PolicyError("INVALID_TARGET")
    destination = Path(path).resolve(strict=False)
    # Exact intended receiving directory plus existing policy-allowed roots.
    downloads = Path("D:/Downloads").resolve(strict=False)
    if destination.parent == downloads and destination.suffix.lower() in _ALLOWED_EXT:
        return destination
    safe = Policy().resolve_path(path, write=True)
    if safe.suffix.lower() not in _ALLOWED_EXT:
        raise PolicyError("BINARY_EXTENSION_NOT_ALLOWED")
    return safe


def _paths(upload_id: str) -> tuple[Path, Path]:
    if not _ID.fullmatch(upload_id):
        raise PolicyError("INVALID_UPLOAD_ID")
    return _ROOT / (upload_id + ".json"), _ROOT / (upload_id + ".part")


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
        uid = secrets.token_hex(16)
        meta, part = _paths(uid)
        payload = {"dest": str(dest), "size": total_bytes, "sha256": sha256, "written": 0}
        with meta.open("x", encoding="utf-8") as f:
            json.dump(payload, f)
        with part.open("xb"):
            pass
        record("binary.begin", "OK", path=str(dest), size=total_bytes)
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
            record("binary.finish", "DENIED", reason="SHA256_MISMATCH")
            raise PolicyError("SHA256_MISMATCH")
        dest.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive creation: never replace an existing file.
        with dest.open("xb") as out, part.open("rb") as inp:
            for block in iter(lambda: inp.read(131072), b""):
                out.write(block)
            out.flush()
            os.fsync(out.fileno())
        part.unlink()
        meta.unlink()
        record("binary.finish", "OK", path=str(dest), size=data["size"], sha256=data["sha256"])
        return {"ok": True, "path": str(dest), "bytes": data["size"],
                "sha256": data["sha256"]}


def register_binary_tools(server: Any) -> None:
    server.tool(annotations=_WRITE)(binary_upload_begin)
    server.tool(annotations=_WRITE)(binary_upload_chunk)
    server.tool(annotations=_WRITE)(binary_upload_finish)
