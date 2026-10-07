from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable

from .config import policy_config


class PolicyError(PermissionError):
    pass


class Policy:
    def __init__(self) -> None:
        cfg = policy_config()
        self.allowed_roots = [Path(p).expanduser().resolve() for p in cfg["allowed_roots"]]
        self.protected_components = {str(x).casefold() for x in cfg.get("protected_components", [])}
        self.protected_names = {str(x).casefold() for x in cfg.get("protected_names", [])}
        self.allowed_executables = {str(x).casefold() for x in cfg.get("allowed_executables", [])}
        self.blocked_command_patterns = [
            re.compile(str(x), re.IGNORECASE)
            for x in cfg.get("blocked_command_patterns", [])
        ]

    @staticmethod
    def _inside(candidate: Path, root: Path) -> bool:
        try:
            return os.path.commonpath([str(candidate), str(root)]).casefold() == str(root).casefold()
        except ValueError:
            return False

    def resolve_path(self, raw: str | Path, *, write: bool = False) -> Path:
        path = Path(raw).expanduser().resolve(strict=False)
        if not any(self._inside(path, root) for root in self.allowed_roots):
            raise PolicyError(f"Path is outside allowed roots: {path}")

        parts = {part.casefold() for part in path.parts}
        blocked = sorted(parts & self.protected_components)
        if blocked:
            raise PolicyError(f"Protected path component: {blocked[0]}")

        name = path.name.casefold()
        if name in self.protected_names or name.startswith(".env"):
            raise PolicyError(f"Protected file: {path.name}")

        if write and path.suffix.casefold() in {".pem", ".key", ".pfx", ".p12", ".kdbx"}:
            raise PolicyError(f"Writing credential material is blocked: {path.suffix}")
        return path

    def validate_command(self, executable: str, args: Iterable[str]) -> tuple[str, list[str]]:
        exe_name = Path(executable).name.casefold()
        args_list = [str(arg) for arg in args]
        if exe_name not in self.allowed_executables:
            raise PolicyError(f"Executable is not allowlisted: {executable}")
        command_text = " ".join([executable, *args_list])
        for pattern in self.blocked_command_patterns:
            if pattern.search(command_text):
                raise PolicyError(f"Command blocked by policy: {pattern.pattern}")
        return executable, args_list
