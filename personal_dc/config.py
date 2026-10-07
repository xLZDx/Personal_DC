from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def home() -> Path:
    override = os.environ.get("PERSONAL_DC_HOME")
    return Path(override).expanduser().resolve() if override else PROJECT_ROOT


def load_json(name: str) -> dict[str, Any]:
    path = home() / "config" / name
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def policy_config() -> dict[str, Any]:
    return load_json("policy.json")


def projects_config() -> dict[str, Any]:
    return load_json("projects.json")


def audit_path() -> Path:
    path = home() / "logs" / "audit.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path
