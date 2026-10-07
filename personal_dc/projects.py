from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import projects_config
from .policy import Policy, PolicyError


def all_projects() -> dict[str, str]:
    cfg = projects_config()
    return {str(k): str(v) for k, v in cfg.get("projects", {}).items()}


def project_path(name_or_path: str) -> Path:
    projects = all_projects()
    wanted = name_or_path.casefold()
    for name, raw in projects.items():
        if name.casefold() == wanted:
            return Policy().resolve_path(raw)
    return Policy().resolve_path(name_or_path)


def describe_projects() -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for name, raw in all_projects().items():
        try:
            path = Policy().resolve_path(raw)
            result.append({"name": name, "path": str(path), "exists": path.exists()})
        except PolicyError as exc:
            result.append({"name": name, "path": raw, "exists": False, "policy_error": str(exc)})
    return result
