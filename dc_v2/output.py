"""Bounded output with exact-literal redaction across chunk boundaries.

No claim to recognize arbitrary encoded or unknown secrets. Deny confidential
input at ingestion; this module is only a second layer for configured literals.
"""
from __future__ import annotations
from .contracts import require


class Redactor:
    def __init__(self, secrets: tuple[bytes, ...]):
        require(type(secrets) is tuple and len(secrets) <= 64 and
                all(type(s) is bytes and 1 <= len(s) <= 4096 for s in secrets), "INVALID_CONFIGURATION")
        self.secrets = tuple(sorted(set(secrets), key=len, reverse=True))
        self.lookahead = max((len(x) for x in secrets), default=1)
        self.pending = b""
        self.closed = False
        self.redactions = 0

    def feed(self, chunk: bytes, *, final: bool = False) -> bytes:
        require(not self.closed and type(chunk) is bytes and len(chunk) <= 65536, "INVALID_CHUNK")
        data = self.pending + chunk
        out = bytearray()
        pos = 0
        while pos < len(data) and (final or len(data) - pos >= self.lookahead):
            secret = next((s for s in self.secrets if data.startswith(s, pos)), None)
            if secret is not None:
                out.extend(b"[REDACTED]")
                pos += len(secret)
                self.redactions += 1
            else:
                out.append(data[pos])
                pos += 1
        self.pending = data[pos:]
        self.closed = final
        return bytes(out)


class OutputBuffer:
    def __init__(self, capacity: int, secrets: tuple[bytes, ...] = ()):
        require(type(capacity) is int and 128 <= capacity <= 1048576, "INVALID_CONFIGURATION")
        self.capacity = capacity
        self.redactor = Redactor(secrets)
        self.data = bytearray()
        self.total_bytes = 0
        self.input_bytes = 0
        self.dropped_bytes = 0

    def append(self, chunk: bytes, *, final: bool = False) -> None:
        filtered = self.redactor.feed(chunk, final=final)
        self.input_bytes += len(chunk)
        self.total_bytes += len(filtered)
        self.data.extend(filtered)
        excess = max(0, len(self.data) - self.capacity)
        if excess:
            del self.data[:excess]
            self.dropped_bytes += excess

    def read(self, cursor: int = 0, limit: int = 65536) -> dict:
        require(type(cursor) is int and 0 <= cursor <= self.total_bytes and
                type(limit) is int and 1 <= limit <= 65536, "INVALID_CURSOR")
        start = max(cursor, self.dropped_bytes)
        payload = bytes(self.data[start - self.dropped_bytes:start - self.dropped_bytes + limit])
        return {"data": payload, "next_cursor": start + len(payload), "available_from": self.dropped_bytes,
                "truncated": cursor < self.dropped_bytes, "dropped_bytes": self.dropped_bytes,
                "input_bytes": self.input_bytes, "redactions": self.redactor.redactions,
                "eof": self.redactor.closed and start + len(payload) == self.total_bytes}
