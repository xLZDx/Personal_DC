"""Bounded, immutable authority-bearing contracts. No client-provided identity."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, fields
from typing import Any


class Denied(Exception):
    """Only a stable code crosses the trust boundary; never raw exception text."""
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def require(condition: bool, code: str = "ACCESS_DENIED") -> None:
    if not condition:
        raise Denied(code)


def identifier(value: str) -> str:
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value) is not None,
            "INVALID_REQUEST")
    return value


def sha256_hex(value: str) -> str:
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None, "INVALID_REQUEST")
    return value


def canonical(value: Any) -> bytes:
    """Project-specific canonical JSON: ASCII keys, strings, ints, bools; no floats."""
    def validate(v: Any, depth: int = 0) -> None:
        require(depth <= 12, "INVALID_REQUEST")
        if v is None or type(v) in (str, int, bool):
            if isinstance(v, str):
                require(len(v) <= 65536, "INVALID_REQUEST")
            if type(v) is int:
                require(abs(v) <= 2**53 - 1, "INVALID_REQUEST")
            return
        if type(v) in (tuple, list):
            require(len(v) <= 256, "INVALID_REQUEST")
            for x in v:
                validate(x, depth + 1)
            return
        if type(v) is dict:
            require(len(v) <= 128 and all(isinstance(k, str) and k.isascii() for k in v), "INVALID_REQUEST")
            for x in v.values():
                validate(x, depth + 1)
            return
        raise Denied("INVALID_REQUEST")
    validate(value)
    result = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    require(len(result) <= 131072, "INVALID_REQUEST")
    return result


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


OPERATIONS = frozenset({"file.read", "tools.inspect", "task.propose", "task.start", "task.status",
                        "task.output", "task.cancel", "changes.propose", "external.propose"})


@dataclass(frozen=True)
class Request:
    version: str
    request_id: str
    project_id: str
    operation: str
    resource_id: str
    idempotency_key: str

    @classmethod
    def parse(cls, payload: dict) -> "Request":
        require(type(payload) is dict and set(payload) == {f.name for f in fields(cls)}, "INVALID_REQUEST")
        require(type(payload["version"]) is str and payload["version"] == "2.2" and
                type(payload["operation"]) is str and payload["operation"] in OPERATIONS, "INVALID_REQUEST")
        for name in ("request_id", "project_id", "resource_id", "idempotency_key"):
            identifier(payload[name])
        return cls(**payload)


@dataclass(frozen=True)
class Principal:
    """Created by the trusted identity adapter, NEVER by Request.parse()."""
    subject: str
    client_id: str
    recipient_id: str
    scopes: frozenset[str]

    def __post_init__(self) -> None:
        for value in (self.subject, self.client_id, self.recipient_id):
            identifier(value)
        require(type(self.scopes) is frozenset, "INVALID_CONFIGURATION")
        for value in self.scopes:
            identifier(value)

    @property
    def binding(self) -> str:
        return digest({"subject": self.subject, "client": self.client_id, "recipient": self.recipient_id})


@dataclass(frozen=True)
class Manifest:
    """Server-resolved immutable operation, not a raw command from a client."""
    principal_binding: str
    project_id: str
    operation: str
    snapshot_digest: str
    tool_digest: str
    policy_digest: str
    target_id: str
    recipient_id: str
    argv: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    capabilities: tuple[str, ...]
    timeout_s: int
    output_limit: int

    def __post_init__(self) -> None:
        for value in (self.principal_binding, self.snapshot_digest, self.tool_digest, self.policy_digest):
            sha256_hex(value)
        for value in (self.project_id, self.target_id, self.recipient_id):
            identifier(value)
        require(type(self.operation) is str and self.operation in OPERATIONS, "INVALID_REQUEST")
        require(type(self.argv) is tuple and len(self.argv) <= 128 and all(type(x) is str for x in self.argv), "INVALID_REQUEST")
        require(type(self.environment) is tuple and all(type(x) is tuple and len(x) == 2 and
                all(type(y) is str for y in x) for x in self.environment), "INVALID_REQUEST")
        require(len({x[0] for x in self.environment}) == len(self.environment), "INVALID_REQUEST")
        require(type(self.capabilities) is tuple and all(type(x) is str for x in self.capabilities) and
                len(set(self.capabilities)) == len(self.capabilities), "INVALID_REQUEST")
        for cap in self.capabilities:
            identifier(cap)
        require(type(self.timeout_s) is int and 1 <= self.timeout_s <= 1800, "INVALID_REQUEST")
        require(type(self.output_limit) is int and 1024 <= self.output_limit <= 1048576, "INVALID_REQUEST")
        canonical(asdict(self))

    @property
    def digest(self) -> str:
        return digest(asdict(self))
