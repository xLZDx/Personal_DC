"""Phase 03 local fsynced hash-chain audit. NOT an independent immutable anchor."""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

from .contracts import Denied, canonical, digest, require


class AuditJournal:
    def __init__(self, path: Path):
        require(path.is_absolute() and path.parent.is_dir() and not path.is_symlink(),
                "INVALID_CONFIGURATION")
        self.path = path
        self.lock = threading.RLock()
        self.verify()

    def verify(self) -> tuple[int, str]:
        last = "0" * 64
        seq = 0
        try:
            if not self.path.exists():
                return seq, last
            require(self.path.stat().st_size <= 10_000_000, "AUDIT_INTEGRITY_ERROR")
            with self.path.open("rb") as stream:
                for raw in stream:
                    item = json.loads(raw)
                    require(type(item) is dict and
                            set(item) == {"seq", "kind", "binding", "object_id",
                                          "timestamp", "prev", "hash"} and
                            item["seq"] == seq+1 and item["prev"] == last,
                            "AUDIT_INTEGRITY_ERROR")
                    check = dict(item)
                    checksum = check.pop("hash")
                    require(digest(check) == checksum and
                            canonical(item) + b"\n" == raw,
                            "AUDIT_INTEGRITY_ERROR")
                    last = checksum
                    seq += 1
            return seq, last
        except Denied:
            raise
        except (OSError, ValueError, TypeError, KeyError):
            raise Denied("AUDIT_INTEGRITY_ERROR") from None

    def append(self, kind: str, binding: str, object_id: str) -> None:
        require(type(kind) is str and type(binding) is str and
                type(object_id) is str and len(kind) <= 64 and
                len(binding) <= 128 and len(object_id) <= 128, "INVALID_REQUEST")
        with self.lock:
            seq, prev = self.verify()
            event = {"seq":seq+1, "kind":kind, "binding":binding,
                     "object_id":object_id, "timestamp":int(time.time()), "prev":prev}
            event["hash"] = digest(event)
            try:
                with self.path.open("ab") as file:
                    file.write(canonical(event)+b"\n")
                    file.flush()
                    os.fsync(file.fileno())
            except OSError:
                raise Denied("AUDIT_UNAVAILABLE") from None
