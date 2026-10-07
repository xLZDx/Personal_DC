from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from typing import Any

from .config import audit_path

_LOCK = threading.Lock()
_SECRET_KEYS = (
    "password", "secret", "token", "api_key", "apikey",
    "authorization", "credential", "private_key",
)


def _redact(value: Any, key: str = "") -> Any:
    if any(marker in key.casefold() for marker in _SECRET_KEYS):
        return "***REDACTED***"
    if isinstance(value, dict):
        return {k: _redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(v, key) for v in value]
    return value


def record(action: str, status: str, **details: Any) -> None:
    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "status": status,
        "details": _redact(details),
    }
    path = audit_path()
    with _LOCK:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")


def recent(limit: int = 50) -> list[dict[str, Any]]:
    path = audit_path()
    if not path.exists():
        return []
    rows = path.read_text(encoding="utf-8", errors="replace").splitlines()
    result: list[dict[str, Any]] = []
    for row in rows[-max(1, min(int(limit), 500)):]:
        try:
            result.append(json.loads(row))
        except json.JSONDecodeError:
            continue
    return result
