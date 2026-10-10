"""Read-only structural assessment of Phase 03 transfer payloads.

Never executes or extracts payload code. Produces metadata only.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import zlib
from pathlib import Path, PurePosixPath

SOURCE = Path(r"D:\Temp\Personal_DC_v2_2_isolated")
OUTPUT = Path(__file__).resolve().parents[1] / "evidence" / "phase03" / "recovery-audit.json"
MAX_PAYLOAD = 15_000_000
FILES = ("phase03-source.b64", "execution-transfer-v1.b64")


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def safe_name(name: str) -> bool:
    if not isinstance(name, str) or not name or len(name) > 240:
        return False
    if "\\" in name or ":" in name or "\x00" in name:
        return False
    p = PurePosixPath(name)
    return not p.is_absolute() and all(s not in ("", ".", "..") for s in name.split("/"))


def examine(name: str) -> dict:
    path = SOURCE / name
    report = {"filename": name, "present": path.is_file()}
    if not path.is_file():
        return report
    raw = path.read_bytes()
    report.update(size_bytes=len(raw), file_sha256=sha(raw))
    if len(raw) > MAX_PAYLOAD * 2:
        report["error"] = "TRANSFER_TOO_LARGE"
        return report
    try:
        compact = re.sub(rb"\s+", b"", raw)
        decoded = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as error:
        report["error"] = "INVALID_BASE64"
        report["error_class"] = type(error).__name__
        return report
    report["decoded_size"] = len(decoded)
    report["decoded_sha256"] = sha(decoded)
    if len(decoded) > MAX_PAYLOAD:
        report["error"] = "DECODED_SIZE_LIMIT"
        return report
    try:
        inflater = zlib.decompressobj()
        data = inflater.decompress(decoded, MAX_PAYLOAD + 1)
        if len(data) > MAX_PAYLOAD or inflater.unconsumed_tail:
            report["error"] = "DECOMPRESSED_SIZE_LIMIT"
            return report
        data += inflater.flush(MAX_PAYLOAD + 1 - len(data))
        if not inflater.eof or inflater.unused_data:
            report["error"] = "INCOMPLETE_OR_TRAILING_COMPRESSED_DATA"
            return report
    except zlib.error as error:
        report["error"] = "INVALID_ZLIB"
        report["error_class"] = type(error).__name__
        return report
    report["decompressed_size"] = len(data)
    report["decompressed_sha256"] = sha(data)
    try:
        doc = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        report["error"] = "INVALID_JSON"
        report["error_class"] = type(error).__name__
        return report
    if type(doc) is not dict:
        report["error"] = "INVALID_DOCUMENT"
        return report
    report["keys"] = sorted(doc.keys())
    files = doc.get("files")
    if files is not None:
        if type(files) is not dict or len(files) > 1000:
            report["error"] = "INVALID_FILES_MAP"
            return report
        names = list(files.keys())
        report["file_count"] = len(names)
        report["unsafe_path_count"] = sum(not safe_name(x) for x in names)
        report["paths"] = sorted(str(x) for x in names if safe_name(x))[:100]
        if report["unsafe_path_count"]:
            report["error"] = "UNSAFE_ARCHIVE_PATH"
            return report
    report["valid_metadata"] = True
    return report


if __name__ == "__main__":
    result = {"mode": "metadata-only/no extraction/no execution",
              "source_root": str(SOURCE),
              "transfers": [examine(n) for n in FILES]}
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
