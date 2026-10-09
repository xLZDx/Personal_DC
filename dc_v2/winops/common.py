"""Shared foundation for the native Windows operations layer (Personal DC v2).

Stdlib-only. Provides:

* private state directory layout (``%LOCALAPPDATA%\\Personal_DC_V2``);
* DPAPI (current user) helpers through ctypes;
* credential redaction for text and structures;
* a hash-chained audit log (tamper *evident*, not tamper *proof*);
* operator approval tickets bound to a digest of the exact action;
* path containment on top of the shared ``personal_dc.policy`` (reparse points, state dir);
* the ``native.json`` configuration (defaults + operator overlay OUTSIDE every write root).

Trust modes
-----------
``READ_ONLY``       system inspection only; no approval needed.
``WORKSPACE_WRITE`` development work in approved roots; only ``git`` read/commit subcommands run
                    without approval - interpreters, shells, other executables need an approval.
``ELEVATED``        services, installers, publication repair: always requires an operator approval
                    bound to the exact action digest. The server never bypasses UAC.

The MCP front door ("No authentication" plus the loopback-hop secret) is **not** user authorization.
The operator grants approvals out-of-band with ``python -m dc_v2.winops.approve``. KNOWN LIMITATION:
approval signing uses a DPAPI key of the same Windows user as the server; it is only a real boundary
because no approval-free route to arbitrary code execution is exposed (see KNOWN_LIMITATIONS.md).
"""
from __future__ import annotations

import asyncio
import contextlib
import copy
import ctypes
import functools
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from personal_dc.policy import CREDENTIAL_SUFFIXES, Policy, PolicyError

READ_ONLY = "read_only"
WORKSPACE_WRITE = "workspace_write"
ELEVATED = "elevated"
MODES = (READ_ONLY, WORKSPACE_WRITE, ELEVATED)

REPO_ROOT = Path(__file__).resolve().parents[2]
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
IO_REPARSE_TAG_SYMLINK = 0xA000000C
IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003
APPROVAL_TTL_DEFAULT_S = 900
APPROVAL_TTL_MAX_S = 3600
MAX_AUDIT_FIELD = 1500
MAX_REVIEWABLE_PARAMS = 20000
_ID_RE = re.compile(r"^[a-z]{2,6}-[a-f0-9]{12,32}$")


class ApprovalRequired(PolicyError):
    """Raised internally; tools convert it to a structured response."""

    def __init__(self, payload: dict[str, Any]) -> None:
        super().__init__("APPROVAL_REQUIRED")
        self.payload = payload


# ---------------------------------------------------------------- threading
def threaded(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Run a blocking tool function in a worker thread.

    FastMCP calls plain ``def`` tools inline on the event loop, so a tool that waits (command_execute,
    service waits, PowerShell, installers) would freeze every other request, including cancel/stop.
    ``functools.wraps`` keeps the signature and annotations, so the tool schema is unchanged.
    """
    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        return await asyncio.to_thread(fn, *args, **kwargs)
    return wrapper


# ---------------------------------------------------------------- state dirs
def state_dir() -> Path:
    override = os.environ.get("PDC_V2_STATE_DIR")
    if override:
        return Path(override).resolve()
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    return Path(base) / "Personal_DC_V2"


def state_subdir(name: str) -> Path:
    path = state_dir() / name
    path.mkdir(parents=True, exist_ok=True)
    return path


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None = None) -> str:
    return (dt or utcnow()).isoformat()


def new_id(prefix: str, nbytes: int = 8) -> str:
    return f"{prefix}-{secrets.token_hex(nbytes)}"


def valid_id(value: Any) -> bool:
    return isinstance(value, str) and bool(_ID_RE.fullmatch(value))


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def digest_of(action: str, params: dict[str, Any]) -> str:
    return sha256_text(canonical({"action": action, "params": params}))


# ------------------------------------------------------------------ file io
def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write via a temp file in the same directory, then replace (bounded retry)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + "." + secrets.token_hex(4) + ".tmp")
    try:
        with tmp.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        last: Exception | None = None
        for attempt in range(8):
            try:
                os.replace(tmp, path)
                return
            except PermissionError as exc:  # transient WinError 5/32 from short-lived handles
                last = exc
                time.sleep(0.05 * (attempt + 1))
        raise last or OSError("REPLACE_FAILED")
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise


def atomic_write_json(path: Path, obj: Any) -> None:
    atomic_write_bytes(path, (json.dumps(obj, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        return default
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise PolicyError("STATE_FILE_CORRUPT:" + path.name) from exc


_THREAD_LOCKS: dict[str, threading.RLock] = {}
_THREAD_LOCKS_GUARD = threading.Lock()


def _thread_lock(path: Path) -> threading.RLock:
    key = str(path).casefold()
    with _THREAD_LOCKS_GUARD:
        return _THREAD_LOCKS.setdefault(key, threading.RLock())


@contextlib.contextmanager
def file_lock(path: Path) -> Iterator[None]:
    """Cross-process advisory lock (msvcrt on Windows) plus a per-path thread lock."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with _thread_lock(path):
        with path.open("a+b") as handle:
            locked = False
            try:
                if os.name == "nt":
                    import msvcrt
                    handle.seek(0)
                    for _ in range(100):
                        try:
                            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                            locked = True
                            break
                        except OSError:
                            time.sleep(0.05)
                    if not locked:
                        raise PolicyError("STATE_LOCK_TIMEOUT")
                yield
            finally:
                if locked:
                    import msvcrt
                    handle.seek(0)
                    with contextlib.suppress(OSError):
                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)


# --------------------------------------------------------------------- DPAPI
class _Blob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


_ENTROPY = b"personal-dc-v2.winops"


def _blob(data: bytes) -> tuple[_Blob, Any]:
    buf = ctypes.create_string_buffer(data, len(data))
    return _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf


def dpapi_protect(data: bytes) -> bytes:
    if os.name != "nt":
        raise PolicyError("DPAPI_WINDOWS_ONLY")
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    src, keep1 = _blob(data)
    ent, keep2 = _blob(_ENTROPY)
    out = _Blob()
    if not crypt32.CryptProtectData(ctypes.byref(src), None, ctypes.byref(ent), None, None, 0, ctypes.byref(out)):
        raise PolicyError("DPAPI_PROTECT_FAILED")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)
        del keep1, keep2


def dpapi_unprotect(data: bytes) -> bytes:
    if os.name != "nt":
        raise PolicyError("DPAPI_WINDOWS_ONLY")
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    src, keep1 = _blob(data)
    ent, keep2 = _blob(_ENTROPY)
    out = _Blob()
    if not crypt32.CryptUnprotectData(ctypes.byref(src), None, ctypes.byref(ent), None, None, 0, ctypes.byref(out)):
        raise PolicyError("DPAPI_UNPROTECT_FAILED")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)
        del keep1, keep2


def secret_path(name: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
        raise PolicyError("INVALID_SECRET_NAME")
    return state_dir() / "secrets" / (name + ".dpapi")


def load_secret(name: str) -> bytes | None:
    path = secret_path(name)
    if not path.is_file():
        return None
    return dpapi_unprotect(path.read_bytes())


# ----------------------------------------------------------------- redaction
_KEY_MARKERS = ("password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
                "authorization", "credential", "private_key", "usr", "cookie")
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_TEXT_SECRET = re.compile(
    r"(?i)\b(pass(?:word|wd)?|pwd|secret|token|api[_-]?key|authorization|credential|usr|user(?:name)?)"
    r"(\s*[=:]\s*)(&quot;.*?&quot;|\"(?:[^\"]|\"\")*\"|'[^']*'|[^\s;&\"',]+)"
)
_IB_ATTR = re.compile(r'(?i)\b(ib\s*=\s*)("[^"]*"|\'[^\']*\')')


def redact_text(text: str) -> str:
    text = _BEARER.sub(lambda m: m.group(1) + " ***", text)
    text = _IB_ATTR.sub(lambda m: m.group(1) + '"***"', text)
    text = _TEXT_SECRET.sub(lambda m: m.group(1) + m.group(2) + "***", text)
    return text


_SECRET_FLAG = re.compile(r"(?i)^[-/]{1,2}(pass(word|wd)?|pwd|secret|token|api-?key|key|credential|auth)$")


def redact(value: Any, key: str = "") -> Any:
    if any(marker in key.casefold() for marker in _KEY_MARKERS):
        return "***REDACTED***"
    if isinstance(value, dict):
        return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        out: list[Any] = []
        previous = None
        for item in value:
            # argv convention: a secret flag is followed by its value as a separate element
            if isinstance(previous, str) and _SECRET_FLAG.match(previous) and isinstance(item, str):
                out.append("***")
            else:
                out.append(redact(item, key))
            previous = item
        return out
    if isinstance(value, str):
        return redact_text(value)
    return value


def bounded(text: str, limit_chars: int) -> tuple[str, bool]:
    if len(text) <= limit_chars:
        return text, False
    return text[:limit_chars], True


def _clip(value: Any, depth: int = 0) -> Any:
    """Bound every audit detail so one huge argument can never make the log unreadable."""
    if isinstance(value, str):
        if len(value) <= MAX_AUDIT_FIELD:
            return value
        return value[:MAX_AUDIT_FIELD] + f"...[{len(value)} chars sha256:{sha256_text(value)[:16]}]"
    if depth > 4:
        return "[depth-limit]"
    if isinstance(value, dict):
        return {str(k)[:80]: _clip(v, depth + 1) for k, v in list(value.items())[:60]}
    if isinstance(value, (list, tuple)):
        items = [_clip(v, depth + 1) for v in value[:40]]
        if len(value) > 40:
            items.append(f"[+{len(value) - 40} more]")
        return items
    return value


# ---------------------------------------------------------------- audit chain
def _audit_file() -> Path:
    return state_subdir("audit") / "native-audit.jsonl"


_GENESIS = "0" * 64


def _record_hash(prev: str, event: dict[str, Any]) -> str:
    return sha256_text(prev + canonical(event))


def _last_record(path: Path) -> tuple[str, int]:
    """Hash and seq of the last complete record; reads backwards in growing windows."""
    size = path.stat().st_size
    window = 65536
    while True:
        with path.open("rb") as handle:
            handle.seek(max(0, size - window))
            chunk = handle.read()
        lines = chunk.split(b"\n")
        if size > window:
            lines = lines[1:]  # first line may be cut
        for raw in reversed(lines):
            if not raw.strip():
                continue
            try:
                last = json.loads(raw)
                return last["hash"], int(last["seq"])
            except (ValueError, KeyError, TypeError):
                continue
        if window >= size or window >= 16 * 1024 * 1024:
            raise PolicyError("AUDIT_CHAIN_UNREADABLE")
        window *= 4


def audit(action: str, status: str, actor: str = "mcp", **details: Any) -> None:
    """Append a redacted, bounded, hash-chained audit event. Fail closed on corruption."""
    path = _audit_file()
    with file_lock(path.with_suffix(".lock")):
        prev, seq = _GENESIS, 0
        torn = False
        if path.is_file() and path.stat().st_size:
            prev, seq = _last_record(path)
            with path.open("rb") as handle:
                handle.seek(-1, os.SEEK_END)
                torn = handle.read(1) != b"\n"
        event = {"seq": seq + 1, "ts": iso(), "actor": actor, "action": action,
                 "status": status, "details": _clip(redact(details))}
        event["prev"] = prev
        event["hash"] = _record_hash(prev, {k: v for k, v in event.items() if k not in ("hash",)})
        with path.open("ab") as handle:
            if torn:  # a crash left a partial line; terminate it so verify flags exactly that line
                handle.write(b"\n")
            handle.write((json.dumps(event, ensure_ascii=False) + "\n").encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())


def audit_verify(limit_errors: int = 5) -> dict[str, Any]:
    path = _audit_file()
    if not path.is_file():
        return {"ok": True, "events": 0, "errors": []}
    prev, count, errors = _GENESIS, 0, []
    with path.open("rb") as handle:
        for line_no, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            try:
                event = json.loads(raw)
                claimed = event.pop("hash")
                if event.get("prev") != prev or _record_hash(prev, event) != claimed:
                    errors.append({"line": line_no, "error": "CHAIN_BREAK"})
                prev = claimed
                count += 1
            except (ValueError, KeyError, TypeError):
                errors.append({"line": line_no, "error": "UNPARSEABLE"})
            if len(errors) >= limit_errors:
                break
    return {"ok": not errors, "events": count, "head": prev, "errors": errors,
            "note": "unkeyed chain: detects accidental/partial tampering, not a same-user rewrite"}


def audit_tail(limit_rows: int = 50) -> list[dict[str, Any]]:
    path = _audit_file()
    if not path.is_file():
        return []
    rows = path.read_bytes()[-262144:].splitlines()[-max(1, min(int(limit_rows), 500)):]
    out = []
    for raw in rows:
        with contextlib.suppress(ValueError):
            out.append(json.loads(raw))
    return out


# ---------------------------------------------------------------- config
_DEFAULT_CONFIG: dict[str, Any] = {
    # Executables that may run in workspace_write mode WITHOUT approval (and still only for the
    # git subcommands in git_free_subcommands). Interpreters (python/node/npm/dotnet/pip) are
    # deliberately NOT here: they are arbitrary code execution and need an approval.
    "dev_executables": ["git.exe"],
    "deny_deletion": True,   # tool-level "no deletion" policy (winops/deletion_policy.py); operator may not weaken it remotely
    "git_free_subcommands": ["status", "diff", "log", "show", "branch", "rev-parse", "ls-files", "add",
                             "commit", "switch", "blame", "describe", "shortlog", "remote"],
    "shell_executables": ["powershell.exe", "pwsh.exe", "cmd.exe"],
    "env_passthrough": ["SystemRoot", "WINDIR", "ComSpec", "PATHEXT", "TEMP", "TMP", "NUMBER_OF_PROCESSORS",
                        "PROCESSOR_ARCHITECTURE", "USERNAME", "USERDOMAIN", "COMPUTERNAME", "ProgramFiles",
                        "ProgramFiles(x86)", "ProgramData", "LOCALAPPDATA", "APPDATA", "USERPROFILE"],
    "extra_path_dirs": ["C:\\Python314", "C:\\Python314\\Scripts", "C:\\Program Files\\Git\\cmd",
                        "C:\\Program Files\\nodejs"],
    "limits": {"max_managed_processes": 8, "max_output_bytes_per_stream": 8388608,
               "max_timeout_s": 3600, "max_process_lifetime_s": 86400, "default_timeout_s": 60,
               "max_page_bytes": 65536, "max_download_bytes": 104857600, "process_retention_days": 14,
               "plan_max_age_s": 86400},
    "service_allowlist": [],
    "service_denylist_extra": [],
    "install_roots": ["D:\\Apps"],
    "installer_roots": ["D:\\Downloads", "D:\\Temp"],
    "trusted_publishers": [],
    "trusted_thumbprints": [],
    "trusted_installer_sha256": [],
    "odata_allowed_hosts": ["127.0.0.1", "localhost", "::1"],
    "apache_roots": ["C:\\Apache24", "C:\\Apache", "C:\\Program Files\\Apache Software Foundation",
                     "C:\\Program Files (x86)\\Apache Software Foundation", "C:\\Program Files\\Apache24"],
    "onec_roots": ["C:\\Program Files\\1cv8", "C:\\Program Files (x86)\\1cv8"],
    "publication_roots": ["C:\\inetpub\\wwwroot", "C:\\Apache24\\htdocs", "D:\\1c_publications"],
    "protected_write_prefixes": ["C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)", "C:\\ProgramData"],
}


def native_config() -> dict[str, Any]:
    """Built-in defaults overlaid by the operator file ``<state>/config/native.json``.

    The overlay lives in the private state directory, which no model-facing file tool can write.
    The repository's ``config/native.json`` is documentation only and is intentionally NOT read:
    a file inside a write-allowed root must never be able to widen security policy.
    """
    cfg = copy.deepcopy(_DEFAULT_CONFIG)
    data = read_json(state_dir() / "config" / "native.json", {})
    if isinstance(data, dict):
        for key, value in data.items():
            if key.startswith("_"):
                continue
            if key not in cfg or type(value) is not type(cfg[key]):
                raise PolicyError("NATIVE_CONFIG_INVALID_KEY_OR_TYPE:" + str(key)[:40])
            if isinstance(value, dict):
                cfg[key].update(value)
            else:
                cfg[key] = value
    for entry in cfg["service_allowlist"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("actions", []), list) \
                or not isinstance(entry.get("approval_free", []), list):
            raise PolicyError("NATIVE_CONFIG_SERVICE_ALLOWLIST_INVALID")
    return cfg


def limit(name: str) -> int:
    return int(native_config()["limits"][name])


# -------------------------------------------------------------- path safety
def _state_protected() -> list[Path]:
    paths = [state_dir(), Path.home() / ".claude", Path.home() / ".ssh"]
    local = os.environ.get("LOCALAPPDATA")
    if local:
        paths.append(Path(local) / "Personal_DC")
    return [p.resolve(strict=False) for p in paths]


def _is_under(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath([str(path), str(root)]).casefold() == str(root).casefold()
    except ValueError:
        return False


def is_reparse(path: Path) -> bool:
    """True for symlinks / junctions / mount points. Fails CLOSED on unexpected stat errors."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    tag = getattr(st, "st_reparse_tag", None)
    if tag is not None:
        return tag in (IO_REPARSE_TAG_SYMLINK, IO_REPARSE_TAG_MOUNT_POINT)
    return bool(getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def assert_no_reparse_chain(path: Path, roots: list[Path]) -> None:
    """Reject reparse points on every existing component between ``path`` and its allowed root.

    ``path`` must be the LEXICAL (unresolved) absolute path; checking an already-resolved path
    cannot see a junction because resolution has followed it.
    """
    root = next((r for r in roots if _is_under(path, r)), None)
    if root is None:
        return  # not lexically below a root: containment of the resolved path decides
    current = path
    while True:
        if os.path.lexists(current) and is_reparse(current):
            raise PolicyError("REPARSE_POINT_IN_PATH:" + current.name)
        if current == root or current.parent == current:
            return
        current = current.parent


def safe_path(raw: str | Path, *, write: bool = False, extra_roots: list[str] | None = None) -> Path:
    """Shared ``Policy`` resolution plus v2-only checks: state dir, protected prefixes, reparse points."""
    policy = Policy()   # performs the syntactic gate (UNC/ADS/devices) before touching the filesystem
    roots = list(policy.allowed_roots)
    lexical = Path(os.path.abspath(os.path.expanduser(str(raw))))
    try:
        resolved = policy.resolve_path(raw, write=write)
    except PolicyError as exc:
        if not extra_roots or not str(exc).startswith("Path is outside allowed roots"):
            raise
        resolved = Path(raw).expanduser().resolve(strict=False)
        roots = [Path(r).resolve(strict=False) for r in extra_roots]
        if not any(_is_under(resolved, r) for r in roots):
            raise
        parts = {p.casefold() for p in resolved.parts}
        name = resolved.name.casefold()
        if parts & policy.protected_components or name in policy.protected_names or name.startswith(".env") \
                or resolved.suffix.casefold() in CREDENTIAL_SUFFIXES:
            raise PolicyError("PROTECTED_PATH")
    for protected in _state_protected():
        if _is_under(resolved, protected):
            raise PolicyError("PROTECTED_LOCATION")
    if write:
        for prefix in native_config()["protected_write_prefixes"]:
            if _is_under(resolved, Path(prefix)):
                raise PolicyError("PROTECTED_WINDOWS_LOCATION")
    assert_no_reparse_chain(lexical, roots)
    assert_no_reparse_chain(resolved, roots)
    return resolved


# ---------------------------------------------------------------- approvals
def _approval_key() -> bytes:
    key = load_secret("approval-key")
    if not key or len(key) < 32:
        raise PolicyError("APPROVAL_KEY_NOT_PROVISIONED")
    return key


def _sign(key: bytes, record: dict[str, Any]) -> str:
    return hmac.new(key, canonical(record).encode("utf-8"), hashlib.sha256).hexdigest()


def approvals_dir() -> Path:
    return state_subdir("approvals")


def request_approval(action: str, params: dict[str, Any], mode: str = ELEVATED) -> dict[str, Any]:
    """Register a pending request and return the structured APPROVAL_REQUIRED payload."""
    digest = digest_of(action, params)
    display = canonical(redact(params))
    if len(display) > MAX_REVIEWABLE_PARAMS:
        raise PolicyError("PARAMS_TOO_LARGE_TO_REVIEW")
    base = state_subdir("approvals")
    now = iso()
    for path in sorted(base.glob("req-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:200]:
        if path.name.endswith(".grant.json"):
            continue
        try:
            data = read_json(path, {})
        except PolicyError:
            continue
        rid = data.get("id", "x")
        if data.get("digest") == digest and data.get("expires_at", "") > now \
                and not (base / (rid + ".used")).exists() and not (base / (rid + ".denied")).exists():
            return _approval_payload(data)
    rid = new_id("req")
    record = {"id": rid, "action": action, "mode": mode, "digest": digest,
              "summary": f"{action} {display[:300]}", "params_display": display,
              "created_at": now, "expires_at": iso(utcnow() + timedelta(hours=4))}
    atomic_write_json(base / (rid + ".json"), record)
    audit("approval.request", "PENDING", approval_id=rid, request_action=action, digest=digest)
    return _approval_payload(record)


def _approval_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "APPROVAL_REQUIRED",
        "approval_id": record["id"],
        "action": record["action"],
        "mode": record["mode"],
        "digest": record["digest"],
        "how": ("Operator runs on the workstation: python -m dc_v2.winops.approve show " + record["id"]
                + " ; then grant " + record["id"] + " ; then repeat this call with approval_id set."),
        "summary": record["summary"],
    }


def require_approval(action: str, params: dict[str, Any], approval_id: str | None, mode: str = ELEVATED) -> str:
    """Verify (and consume) an operator approval for exactly this action+params.

    Returns the approval id. Raises ``ApprovalRequired`` when none was supplied.
    """
    if not approval_id:
        raise ApprovalRequired(request_approval(action, params, mode))
    if not valid_id(approval_id) or not approval_id.startswith("req-"):
        raise PolicyError("INVALID_APPROVAL_ID")
    digest = digest_of(action, params)
    base = approvals_dir()
    with file_lock(base / "approvals.lock"):
        if (base / (approval_id + ".denied")).exists():
            audit("approval.use", "DENIED", approval_id=approval_id, reason="OPERATOR_DENIED")
            raise PolicyError("APPROVAL_DENIED_BY_OPERATOR")
        grant = read_json(base / (approval_id + ".grant.json"))
        if not grant:
            audit("approval.use", "DENIED", approval_id=approval_id, reason="NOT_GRANTED")
            raise PolicyError("APPROVAL_NOT_GRANTED")
        signature = grant.pop("sig", "")
        if not hmac.compare_digest(signature, _sign(_approval_key(), grant)):
            audit("approval.use", "DENIED", approval_id=approval_id, reason="BAD_SIGNATURE")
            raise PolicyError("APPROVAL_SIGNATURE_INVALID")
        if grant.get("id") != approval_id:
            audit("approval.use", "DENIED", approval_id=approval_id, reason="GRANT_ID_MISMATCH")
            raise PolicyError("APPROVAL_GRANT_ID_MISMATCH")
        if grant.get("digest") != digest or grant.get("action") != action:
            audit("approval.use", "DENIED", approval_id=approval_id, reason="DIGEST_MISMATCH")
            raise PolicyError("APPROVAL_DIGEST_MISMATCH")
        if grant.get("expires_at", "") <= iso():
            audit("approval.use", "DENIED", approval_id=approval_id, reason="EXPIRED")
            raise PolicyError("APPROVAL_EXPIRED")
        marker = base / (approval_id + ".used")
        try:
            with marker.open("x", encoding="utf-8") as handle:
                handle.write(iso())
        except FileExistsError as exc:
            audit("approval.use", "DENIED", approval_id=approval_id, reason="REPLAY")
            raise PolicyError("APPROVAL_ALREADY_USED") from exc
    audit("approval.use", "CONSUMED", approval_id=approval_id, request_action=action, digest=digest)
    return approval_id


def grant_approval(approval_id: str, ttl_s: int = APPROVAL_TTL_DEFAULT_S, grantor: str = "") -> dict[str, Any]:
    """Operator-side: sign a grant for a pending request (used by the approve CLI)."""
    if not valid_id(approval_id) or not approval_id.startswith("req-"):
        raise PolicyError("INVALID_APPROVAL_ID")
    base = approvals_dir()
    with file_lock(base / "approvals.lock"):
        pending = read_json(base / (approval_id + ".json"))
        if not pending:
            raise PolicyError("APPROVAL_REQUEST_NOT_FOUND")
        if (base / (approval_id + ".denied")).exists():
            raise PolicyError("REQUEST_WAS_DENIED")
        ttl = max(30, min(int(ttl_s), APPROVAL_TTL_MAX_S))
        record = {"id": approval_id, "action": pending["action"], "digest": pending["digest"],
                  "granted_at": iso(), "expires_at": iso(utcnow() + timedelta(seconds=ttl)),
                  "grantor": grantor or os.environ.get("USERNAME", "operator")}
        # intent first: if the audit cannot be written the grant must not exist
        audit("approval.grant", "GRANTED", actor="operator-cli", approval_id=approval_id,
              request_action=pending["action"], digest=pending["digest"], ttl_s=ttl)
        record["sig"] = _sign(_approval_key(), record)
        atomic_write_json(base / (approval_id + ".grant.json"), record)
    return {k: v for k, v in record.items() if k != "sig"}


def deny_approval(approval_id: str) -> None:
    if not valid_id(approval_id) or not approval_id.startswith("req-"):
        raise PolicyError("INVALID_APPROVAL_ID")
    base = approvals_dir()
    with file_lock(base / "approvals.lock"):
        (base / (approval_id + ".denied")).write_text(iso(), encoding="utf-8")
        (base / (approval_id + ".grant.json")).unlink(missing_ok=True)
    audit("approval.deny", "DENIED", actor="operator-cli", approval_id=approval_id)


def init_approval_key() -> bool:
    path = secret_path("approval-key")
    if path.is_file():
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_bytes(path, dpapi_protect(secrets.token_bytes(32)))
    audit("approval.key", "PROVISIONED", actor="operator-cli")
    return True


def approval_or_response(action: str, params: dict[str, Any], approval_id: str | None,
                         mode: str = ELEVATED) -> dict[str, Any] | None:
    """Tool helper: ``None`` when approved, otherwise the response dict to return."""
    try:
        require_approval(action, params, approval_id, mode)
        return None
    except ApprovalRequired as exc:
        return exc.payload
