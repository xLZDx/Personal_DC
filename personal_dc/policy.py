from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable

from .config import home, policy_config


class PolicyError(PermissionError):
    pass


# Single shared path-safety implementation: v1 uses it directly, v2 (dc_v2.winops.common.safe_path)
# layers its own extra checks on top. Do not copy these rules elsewhere.
_DEVICE_NAME = re.compile(r"^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$", re.IGNORECASE)
CREDENTIAL_SUFFIXES = {".pem", ".key", ".pfx", ".p12", ".kdbx", ".ppk", ".dpapi", ".tfvars", ".tfstate"}
BUILTIN_PROTECTED_NAMES = {
    ".npmrc", ".pypirc", ".netrc", ".git-credentials", "id_ecdsa", "id_dsa", "id_rsa", "id_ed25519",
}


def syntactic_check(raw: str | Path) -> None:
    """Reject path syntax that reaches the network or hides data BEFORE any filesystem call."""
    text = str(raw)
    if not text or "\x00" in text:
        raise PolicyError("INVALID_PATH")
    norm = text.replace("/", "\\")
    if norm.startswith("\\\\"):
        raise PolicyError("UNC_OR_DEVICE_PATH_NOT_ALLOWED")
    drive = re.match(r"^[A-Za-z]:", norm)
    if drive and not norm[2:3] == "\\":
        raise PolicyError("DRIVE_RELATIVE_PATH_NOT_ALLOWED")
    rest = norm[2:] if drive else norm
    if ":" in rest:
        raise PolicyError("ALTERNATE_DATA_STREAM_NOT_ALLOWED")
    for part in norm.split("\\"):
        if not part or part in (".", ".."):
            continue
        if part != part.rstrip(" ."):
            raise PolicyError("TRAILING_DOT_OR_SPACE_NOT_ALLOWED")
        if _DEVICE_NAME.match(part):
            raise PolicyError("RESERVED_DEVICE_NAME_NOT_ALLOWED")


class Policy:
    def __init__(self) -> None:
        cfg = policy_config()
        self.allowed_roots = [Path(p).expanduser().resolve() for p in cfg["allowed_roots"]]
        self.protected_components = {str(x).casefold() for x in cfg.get("protected_components", [])}
        self.protected_names = {str(x).casefold() for x in cfg.get("protected_names", [])} | BUILTIN_PROTECTED_NAMES
        self.allowed_executables = {str(x).casefold() for x in cfg.get("allowed_executables", [])}
        self.blocked_command_patterns = [
            re.compile(str(x), re.IGNORECASE)
            for x in cfg.get("blocked_command_patterns", [])
        ]
        # The gateway's own control files are never writable through the model-facing file tools.
        base = home()
        self.write_protected = [(base / "config").resolve(strict=False), (base / "logs").resolve(strict=False)]

    @staticmethod
    def _inside(candidate: Path, root: Path) -> bool:
        try:
            return os.path.commonpath([str(candidate), str(root)]).casefold() == str(root).casefold()
        except ValueError:
            return False

    def resolve_path(self, raw: str | Path, *, write: bool = False) -> Path:
        syntactic_check(raw)
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

        if path.suffix.casefold() in CREDENTIAL_SUFFIXES:
            raise PolicyError(f"Credential material is blocked: {path.suffix}")
        if write and any(self._inside(path, root) for root in self.write_protected):
            raise PolicyError("GATEWAY_CONTROL_PATH_PROTECTED")
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
