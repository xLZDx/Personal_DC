from __future__ import annotations

import os
import platform
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from . import __version__
from .audit import recent, record
from .executor import run
from .policy import Policy
from .projects import describe_projects, project_path

mcp = FastMCP(
    "Personal DC",
    instructions=(
        "Private Windows workstation gateway. Respect policy errors. "
        "Deletion is intentionally unavailable. Prefer read-only tools before write tools."
    ),
    host="127.0.0.1",
    port=int(os.environ.get("PERSONAL_DC_PORT", "18765")),
    stateless_http=True,
    json_response=True,
)

READ_ONLY = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
LOCAL_WRITE = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=False,
)
LOCAL_ADDITIVE = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=False,
)
OPEN_WORLD_WRITE = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=True,
)


def _bounded(value: str, limit: int, maximum: int = 100000) -> str:
    safe_limit = max(100, min(int(limit), maximum))
    return value[:safe_limit]


@mcp.tool(annotations=READ_ONLY)
def health() -> dict[str, Any]:
    """Return Personal DC health and version information."""
    return {
        "ok": True,
        "name": "Personal DC",
        "version": os.environ.get("PERSONAL_DC_PRODUCT_VERSION", __version__),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "deletion_tool_exposed": False,
    }


@mcp.tool(annotations=READ_ONLY)
def list_projects() -> list[dict[str, Any]]:
    """List configured project aliases and whether each project exists."""
    return describe_projects()


@mcp.tool(annotations=READ_ONLY)
def list_directory(path: str, limit: int = 250) -> list[dict[str, Any]]:
    """List a directory inside allowed roots. Protected paths are rejected."""
    policy = Policy()
    safe = policy.resolve_path(path)
    if not safe.is_dir():
        raise NotADirectoryError(str(safe))
    result: list[dict[str, Any]] = []
    for child in sorted(safe.iterdir(), key=lambda p: (not p.is_dir(), p.name.casefold())):
        if child.name.casefold() in policy.protected_components:
            continue
        result.append(
            {
                "name": child.name,
                "path": str(child),
                "type": "directory" if child.is_dir() else "file",
                "size": child.stat().st_size if child.is_file() else None,
            }
        )
        if len(result) >= max(1, min(int(limit), 1000)):
            break
    record("fs.list", "OK", path=str(safe), count=len(result))
    return result


@mcp.tool(annotations=READ_ONLY)
def read_text_file(path: str, max_chars: int = 30000) -> dict[str, Any]:
    """Read a UTF-8 text file inside allowed roots with a bounded response."""
    safe = Policy().resolve_path(path)
    if not safe.is_file():
        raise FileNotFoundError(str(safe))
    if safe.stat().st_size > 10 * 1024 * 1024:
        raise ValueError("File is larger than the 10 MiB read limit.")
    data = safe.read_text(encoding="utf-8", errors="replace")
    content = _bounded(data, max_chars)
    record("fs.read", "OK", path=str(safe), size=len(data))
    return {"path": str(safe), "content": content, "truncated": len(content) < len(data)}


@mcp.tool(annotations=READ_ONLY)
def project_git_status(project: str) -> dict[str, Any]:
    """Return git status for a configured project alias or allowed path."""
    return run("git", ["status", "--short", "--branch"], project_path(project), 30)


@mcp.tool(annotations=READ_ONLY)
def project_git_diff(project: str, staged: bool = False, max_chars: int = 40000) -> dict[str, Any]:
    """Return a bounded git diff for a configured project."""
    args = ["diff", "--cached"] if staged else ["diff"]
    result = run("git", args, project_path(project), 60)
    result["stdout"] = _bounded(result.get("stdout", ""), max_chars)
    result["stderr"] = _bounded(result.get("stderr", ""), 10000)
    return result


@mcp.tool(annotations=READ_ONLY)
def project_git_log(project: str, limit: int = 20) -> dict[str, Any]:
    """Return recent git history for a configured project."""
    count = max(1, min(int(limit), 100))
    return run(
        "git",
        ["log", f"-{count}", "--date=iso", "--pretty=format:%h%x09%ad%x09%an%x09%s"],
        project_path(project),
        30,
    )


@mcp.tool(annotations=READ_ONLY)
def recent_audit_log(limit: int = 50) -> list[dict[str, Any]]:
    """Read recent Personal DC audit events with secret-looking fields redacted."""
    return recent(limit)


@mcp.tool(annotations=LOCAL_WRITE)
def write_text_file(path: str, content: str, overwrite: bool = False) -> dict[str, Any]:
    """Create a text file, or replace one only when overwrite=true."""
    safe = Policy().resolve_path(path, write=True)
    if safe.exists() and not overwrite:
        raise FileExistsError("File exists; pass overwrite=true to replace it.")
    safe.parent.mkdir(parents=True, exist_ok=True)
    safe.write_text(content, encoding="utf-8")
    record("fs.write", "OK", path=str(safe), chars=len(content), overwrite=overwrite)
    return {"ok": True, "path": str(safe), "chars": len(content)}


@mcp.tool(annotations=LOCAL_WRITE)
def replace_text(path: str, old: str, new: str, expected_replacements: int = 1) -> dict[str, Any]:
    """Replace exact text in a UTF-8 file, only when the expected match count agrees."""
    if not old:
        raise ValueError("old must not be empty.")
    expected = max(1, min(int(expected_replacements), 1000))
    safe = Policy().resolve_path(path, write=True)
    if not safe.is_file():
        raise FileNotFoundError(str(safe))
    if safe.stat().st_size > 10 * 1024 * 1024:
        raise ValueError("File is larger than the 10 MiB edit limit.")
    data = safe.read_text(encoding="utf-8", errors="strict")
    actual = data.count(old)
    if actual != expected:
        raise ValueError(f"Expected {expected} matches, found {actual}.")
    updated = data.replace(old, new)
    safe.write_text(updated, encoding="utf-8")
    record("fs.replace", "OK", path=str(safe), replacements=actual)
    return {"ok": True, "path": str(safe), "replacements": actual}


@mcp.tool(annotations=LOCAL_ADDITIVE)
def create_directory(path: str) -> dict[str, Any]:
    """Create a directory inside allowed roots. Existing directories remain intact."""
    safe = Policy().resolve_path(path, write=True)
    safe.mkdir(parents=True, exist_ok=True)
    record("fs.mkdir", "OK", path=str(safe))
    return {"ok": True, "path": str(safe)}


@mcp.tool(annotations=LOCAL_ADDITIVE)
def git_create_branch(project: str, branch: str) -> dict[str, Any]:
    """Create and switch to a new git branch. No branch is deleted."""
    if not branch or any(ch in branch for ch in (" ", "..", "~", "^", ":", "?", "*", "[", "\\")):
        raise ValueError("Invalid branch name.")
    return run("git", ["switch", "-c", branch], project_path(project), 30)


@mcp.tool(annotations=LOCAL_ADDITIVE)
def git_stage_paths(project: str, paths: list[str]) -> dict[str, Any]:
    """Stage selected files inside a configured git project."""
    if not paths or len(paths) > 200:
        raise ValueError("Provide between 1 and 200 paths.")
    cwd = project_path(project)
    policy = Policy()
    relative_paths: list[str] = []
    for raw in paths:
        candidate = Path(raw) if Path(raw).is_absolute() else cwd / raw
        safe = policy.resolve_path(candidate, write=True)
        try:
            relative = safe.relative_to(cwd)
        except ValueError as exc:
            raise ValueError(f"Stage path must be inside project: {raw}") from exc
        relative_paths.append(str(relative))
    return run("git", ["add", "--", *relative_paths], cwd, 60)


@mcp.tool(annotations=LOCAL_ADDITIVE)
def git_commit(project: str, message: str) -> dict[str, Any]:
    """Commit changes that are already staged by the user or another approved workflow."""
    if not message.strip():
        raise ValueError("Commit message must not be empty.")
    return run("git", ["commit", "-m", message], project_path(project), 120)


@mcp.tool(annotations=OPEN_WORLD_WRITE)
def git_push(project: str, remote: str = "origin", branch: str = "HEAD") -> dict[str, Any]:
    """Perform a normal git push. This tool does not expose force options."""
    if remote.startswith("-") or branch.startswith("-"):
        raise ValueError("Invalid remote or branch.")
    return run("git", ["push", remote, branch], project_path(project), 300)


@mcp.tool(annotations=LOCAL_WRITE)
def run_project_tests(project: str, runner: str = "pytest", timeout: int = 600) -> dict[str, Any]:
    """Run a bounded predefined test command in a configured project."""
    cwd = project_path(project)
    if runner == "pytest":
        return run("python", ["-m", "pytest", "-q"], cwd, timeout)
    if runner == "npm_test":
        return run("npm.cmd", ["test"], cwd, timeout)
    raise ValueError("runner must be 'pytest' or 'npm_test'")


def main() -> None:
    transport = os.environ.get("PERSONAL_DC_TRANSPORT", "stdio").strip().lower()
    if transport not in {"stdio", "streamable-http", "sse"}:
        raise SystemExit(f"Unsupported PERSONAL_DC_TRANSPORT={transport!r}")
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
