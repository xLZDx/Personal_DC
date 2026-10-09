"""Approval gate for the shared v1 tools that can run code or leave the machine.

v1 keeps its own behaviour untouched. In the v2 process only, ``git_push`` and ``run_project_tests``
(which executes the project's own test code) are re-registered as thin wrappers that require an
operator approval and then DELEGATE to the unchanged v1 function: there is no second implementation.
"""
from __future__ import annotations

from typing import Any

from mcp.types import ToolAnnotations
from personal_dc import server as v1

from .common import ELEVATED, approval_or_response, audit, threaded

_OPEN_WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True)
_LOCAL_WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False)


def git_push(project: str, remote: str = "origin", branch: str = "HEAD",
             approval_id: str | None = None) -> dict[str, Any]:
    """Perform a normal git push (no force). Requires an operator approval bound to project/remote/branch."""
    params = {"project": project, "remote": remote, "branch": branch}
    pending = approval_or_response("v1.git_push", params, approval_id, ELEVATED)
    if pending:
        return pending
    audit("v1.git_push", "APPROVED_RUN", **params)
    return v1.git_push(project, remote, branch)


def run_project_tests(project: str, runner: str = "pytest", timeout: int = 600,
                      approval_id: str | None = None) -> dict[str, Any]:
    """Run the project's predefined test command. Executes project code, so it requires operator approval."""
    params = {"project": project, "runner": runner, "timeout": timeout}
    pending = approval_or_response("v1.run_project_tests", params, approval_id, ELEVATED)
    if pending:
        return pending
    audit("v1.run_project_tests", "APPROVED_RUN", **params)
    return v1.run_project_tests(project, runner, timeout)


def apply_v1_gate(server: Any) -> None:
    for name, fn, ann in (("git_push", git_push, _OPEN_WRITE), ("run_project_tests", run_project_tests, _LOCAL_WRITE)):
        server.remove_tool(name)
        server.tool(annotations=ann)(threaded(fn))
