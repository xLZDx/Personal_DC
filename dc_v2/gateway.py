"""Dependency-injected PEP facade. NO listener, shell, deployment or live token API.

Identity verification is mandatory and external; unverified claims are not parsed
as a Principal. Execution remains hard-disabled, regardless of purported consent.
"""
from __future__ import annotations

from dataclasses import asdict
import html
import json
from typing import Protocol

from .contracts import Denied, Manifest, Principal, Request, require
from .output import OutputBuffer
from .policy import ExportRegistry


class IdentityVerifier(Protocol):
    def authenticate(self, opaque_credential: str) -> Principal: ...


class DenyIdentity:
    def authenticate(self, opaque_credential: str) -> Principal:
        raise Denied("AUTH_REQUIRED")


class TransportGuard:
    def __init__(self, hosts: frozenset[str], origins: frozenset[str], native_clients: bool = False):
        require(bool(hosts) and type(hosts) is frozenset and type(origins) is frozenset, "INVALID_CONFIGURATION")
        self.hosts, self.origins, self.native_clients = hosts, origins, native_clients

    def check(self, host: str, origin: str | None, headers: dict[str, str]) -> None:
        require(host in self.hosts, "TRANSPORT_DENIED")
        require(origin in self.origins if origin is not None else self.native_clients, "TRANSPORT_DENIED")
        # No trusted reverse proxy is configured in the foundation profile.
        require(not any(k.casefold().startswith(("x-forwarded-", "x-auth-", "x-user-")) or
                        k.casefold() == 'forwarded' for k in headers), "TRANSPORT_DENIED")


LEGACY_READ_NAMES = frozenset({"health", "list_projects", "list_directory", "read_text_file",
    "project_git_status", "project_git_diff", "project_git_log", "recent_audit_log"})
LEGACY_WRITE_NAMES = frozenset({"write_text_file", "replace_text", "create_directory", "git_create_branch",
    "git_stage_paths", "git_commit", "git_push", "run_project_tests"})


def deny_legacy(tool_name: str) -> None:
    """Until migrated to object-level authorization, no legacy fallback is allowed."""
    if tool_name in LEGACY_READ_NAMES | LEGACY_WRITE_NAMES:
        raise Denied("LEGACY_MIGRATION_REQUIRED")
    raise Denied("UNSUPPORTED_OPERATION")


class Gateway:
    def __init__(self, projects: dict[str, ExportRegistry], identity: IdentityVerifier | None = None,
                 canaries: tuple[bytes, ...] = ()):
        self.projects = dict(projects)
        self.identity = identity or DenyIdentity()
        self.canaries = canaries

    def call(self, payload: dict, credential: str) -> dict:
        try:
            require(type(credential) is str and 0 < len(credential) <= 8192, "AUTH_REQUIRED")
            principal = self.identity.authenticate(credential)
            require(type(principal) is Principal, "AUTH_REQUIRED")
            request = Request.parse(payload)
            require(request.operation in principal.scopes, "ACCESS_DENIED")
            if request.operation == "file.read":
                # Project authorization is also required, not merely possession of an ID.
                require(f"project:{request.project_id}" in principal.scopes, "ACCESS_DENIED")
                registry = self.projects.get(request.project_id)
                require(registry is not None, "ACCESS_DENIED")
                data = registry.read(request.resource_id, principal)
                output = OutputBuffer(1048576, self.canaries)
                for offset in range(0, len(data), 65536):
                    output.append(data[offset:offset + 65536])
                output.append(b"", final=True)
                # Read all bounded bytes in pages, not only the first page.
                parts, cursor = [], 0
                while True:
                    part = output.read(cursor)
                    parts.append(part['data'])
                    cursor = part['next_cursor']
                    if part['eof']:
                        break
                return {"status": "OK", "content": b"".join(parts).decode("utf-8", errors="replace"),
                        "redactions": output.redactor.redactions, "truncated": output.dropped_bytes > 0,
                        "dropped_bytes": output.dropped_bytes, "data_trust": "UNTRUSTED"}
            if request.operation == "task.start":
                raise Denied("EXECUTION_HOLD")
            raise Denied("UNSUPPORTED_OPERATION")
        except Denied as exc:
            return {"status": "DENIED", "error_code": exc.code}
        except Exception:
            # No path, credential, exception or traceback crosses the boundary.
            return {"status": "DENIED", "error_code": "INTERNAL_DENIED"}


def approval_preview(manifest: Manifest) -> str:
    """Escaped deterministic PREVIEW only, not a trusted confirmation surface."""
    text = json.dumps(asdict(manifest), ensure_ascii=True, sort_keys=True, indent=2)
    return ("<!doctype html><html lang='en'><meta charset='utf-8'>"
            "<title>Personal DC — approval preview</title><body>"
            "<h1>PREVIEW ONLY — no approval can be issued here</h1>"
            "<p>Manifest SHA-256: " + manifest.digest + "</p><pre>" + html.escape(text) +
            "</pre><p>Execution: HOLD. Independent trusted display not provisioned.</p></body></html>")
