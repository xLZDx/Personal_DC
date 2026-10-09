"""Software inventory, installer verification and approval-gated deployment with rollback.

Design:
* No general silent-install bypass: only MSI (``msiexec /i``), and EXE installers
  whose silent profile is one of a small closed set (``inno``, ``nsis``) chosen
  by the *plan*, never free-form arguments.
* Installers must live in configured ``installer_roots``, be hash-pinned
  (``expected_sha256``) or pre-trusted, and carry a valid Authenticode signature
  from a trusted publisher/thumbprint (or be on the trusted-hash list).
* ``deployment_apply`` copies the installer into a private staging directory,
  re-hashes the staged copy (no TOCTOU) and runs it as a managed process. The
  server never elevates: an installer needing admin rights fails and is reported
  ``needs_elevation`` instead of being forced through UAC.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import time
from pathlib import Path
from typing import Any

from mcp.types import ToolAnnotations
from personal_dc.policy import PolicyError

from . import process_tools as pt
from .common import (ELEVATED, approval_or_response, atomic_write_json, audit, digest_of, iso, native_config,
                     new_id, read_json, redact_text, safe_path, state_subdir, valid_id)
from .sysrun import ps_json

_RO = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
_MUT = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False)

INSTALLER_EXT = {".msi", ".exe"}
PROFILES = {
    "msi": {"ext": ".msi"},
    "inno": {"ext": ".exe", "args": ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-"], "dir": "/DIR={dir}"},
    "nsis": {"ext": ".exe", "args": ["/S"], "dir": "/D={dir}"},
}
REBOOT_CODES = {3010, 1641}
ELEVATION_CODES = {740, 1925, 5}
_SOFT_KEYS = [
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
]


def _installed() -> list[dict[str, Any]]:
    import winreg
    rows: list[dict[str, Any]] = []
    for hive_name, sub in _SOFT_KEYS:
        hive = winreg.HKEY_LOCAL_MACHINE if hive_name == "HKLM" else winreg.HKEY_CURRENT_USER
        try:
            key = winreg.OpenKey(hive, sub)
        except OSError:
            continue
        with key:
            for i in range(winreg.QueryInfoKey(key)[0]):
                try:
                    name = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, name) as item:
                        def val(n: str) -> Any:
                            try:
                                return winreg.QueryValueEx(item, n)[0]
                            except OSError:
                                return None
                        display = val("DisplayName")
                        if not display or val("SystemComponent") == 1:
                            continue
                        rows.append({"key": name, "scope": hive_name, "name": display,
                                     "version": val("DisplayVersion"), "publisher": val("Publisher"),
                                     "install_location": val("InstallLocation"),
                                     "install_date": val("InstallDate"),
                                     "windows_installer": bool(val("WindowsInstaller")),
                                     "uninstall": redact_text(str(val("UninstallString") or ""))[:300]})
                except OSError:
                    continue
    return rows


def software_inspect(name_contains: str = "", limit_rows: int = 100) -> dict[str, Any]:
    """List installed software from the Windows uninstall registry (read-only)."""
    needle = name_contains.strip().casefold()[:80]
    rows = [r for r in _installed() if needle in str(r["name"]).casefold()]
    rows.sort(key=lambda r: str(r["name"]).casefold())
    pending_reboot = _reboot_pending()
    audit("software.inspect", "OK", count=len(rows))
    return {"count": len(rows), "software": rows[:max(1, min(int(limit_rows), 500))],
            "reboot_pending": pending_reboot}


def _reboot_pending() -> bool:
    import winreg
    checks = [(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"),
              (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired")]
    for hive, sub in checks:
        try:
            winreg.CloseKey(winreg.OpenKey(hive, sub))
            return True
        except OSError:
            continue
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager") as key:
            return bool(winreg.QueryValueEx(key, "PendingFileRenameOperations")[0])
    except OSError:
        return False


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


_SIG_PS = r"""
$s = Get-AuthenticodeSignature -LiteralPath $env:PDC_ARG_PATH
[pscustomobject]@{
  status = [string]$s.Status; status_message = $s.StatusMessage;
  subject = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { $null };
  thumbprint = if ($s.SignerCertificate) { $s.SignerCertificate.Thumbprint } else { $null };
  not_after = if ($s.SignerCertificate) { $s.SignerCertificate.NotAfter.ToString('o') } else { $null };
  timestamped = ($null -ne $s.TimeStamperCertificate)
} | ConvertTo-Json -Compress
"""

_MSI_PS = r"""
$i = New-Object -ComObject WindowsInstaller.Installer
$db = $i.GetType().InvokeMember('OpenDatabase','InvokeMethod',$null,$i,@($env:PDC_ARG_PATH,0))
function Prop($n) {
  $v = $db.GetType().InvokeMember('OpenView','InvokeMethod',$null,$db,@("SELECT Value FROM Property WHERE Property='$n'"))
  $v.GetType().InvokeMember('Execute','InvokeMethod',$null,$v,$null) | Out-Null
  $r = $v.GetType().InvokeMember('Fetch','InvokeMethod',$null,$v,$null)
  if ($r) { $r.GetType().InvokeMember('StringData','GetProperty',$null,$r,@(1)) } else { $null }
}
[pscustomobject]@{ product_code=Prop 'ProductCode'; product_name=Prop 'ProductName'; version=Prop 'ProductVersion';
  manufacturer=Prop 'Manufacturer' } | ConvertTo-Json -Compress
"""


def _installer_path(path: str) -> Path:
    resolved = safe_path(path, extra_roots=native_config()["installer_roots"])
    if not resolved.is_file() or resolved.suffix.casefold() not in INSTALLER_EXT:
        raise PolicyError("INSTALLER_MUST_BE_EXISTING_MSI_OR_EXE")
    if not any(str(resolved).casefold().startswith(str(Path(r).resolve(strict=False)).casefold())
               for r in native_config()["installer_roots"]):
        raise PolicyError("INSTALLER_OUTSIDE_INSTALLER_ROOTS")
    return resolved


def _trust(sig: dict[str, Any], sha: str) -> tuple[bool, str]:
    cfg = native_config()
    if sha in {h.lower() for h in cfg["trusted_installer_sha256"]}:
        return True, "TRUSTED_HASH"
    if sig.get("status") != "Valid":
        return False, "SIGNATURE_" + str(sig.get("status")).upper()
    thumbs = {t.replace(" ", "").upper() for t in cfg["trusted_thumbprints"]}
    if (sig.get("thumbprint") or "").upper() in thumbs:
        return True, "TRUSTED_THUMBPRINT"
    subject = (sig.get("subject") or "").casefold()
    if any(p.casefold() in subject for p in cfg["trusted_publishers"] if p):
        return True, "TRUSTED_PUBLISHER"
    return False, "PUBLISHER_NOT_TRUSTED"


def installer_verify(path: str, expected_sha256: str = "") -> dict[str, Any]:
    """Hash + Authenticode verification of an installer; returns a trust verdict (never installs)."""
    installer = _installer_path(path)
    sha = _sha256_file(installer)
    if expected_sha256 and sha != expected_sha256.strip().lower():
        audit("installer.verify", "HASH_MISMATCH", path=str(installer))
        return {"path": str(installer), "sha256": sha, "hash_matches_expected": False, "trusted": False,
                "verdict": "REJECT_HASH_MISMATCH"}
    sig = ps_json(_SIG_PS, {"path": str(installer)}, timeout=60) or {}
    trusted, why = _trust(sig, sha)
    info: dict[str, Any] = {}
    if installer.suffix.casefold() == ".msi":
        try:
            info = ps_json(_MSI_PS, {"path": str(installer)}, timeout=60) or {}
        except PolicyError:
            info = {"error": "MSI_PROPERTIES_UNREADABLE"}
    hash_pinned = bool(expected_sha256)
    verdict = "ACCEPT" if trusted and (hash_pinned or why == "TRUSTED_HASH") else \
        "REJECT_UNTRUSTED" if not trusted else "REJECT_NEEDS_PINNED_SHA256"
    audit("installer.verify", verdict, path=str(installer), sha256=sha, trust=why)
    return {"path": str(installer), "size": installer.stat().st_size, "sha256": sha,
            "hash_matches_expected": hash_pinned or None, "signature": sig, "trusted": trusted, "trust_basis": why,
            "msi": info, "verdict": verdict}


def _plans() -> Path:
    return state_subdir("deploy")


def _load_plan(plan_id: str) -> dict[str, Any]:
    if not valid_id(plan_id) or not plan_id.startswith("dpl-"):
        raise PolicyError("INVALID_PLAN_ID")
    plan = read_json(_plans() / (plan_id + ".json"))
    if not plan:
        raise PolicyError("PLAN_NOT_FOUND")
    return plan


def _save_plan(plan: dict[str, Any]) -> None:
    atomic_write_json(_plans() / (plan["id"] + ".json"), plan)


def _install_dir(install_dir: str) -> str:
    if not install_dir:
        return ""
    resolved = Path(install_dir).resolve(strict=False)
    roots = [Path(r).resolve(strict=False) for r in native_config()["install_roots"]]
    if not any(os.path.commonpath([str(resolved), str(r)]).casefold() == str(r).casefold()
               for r in roots if resolved.drive.casefold() == r.drive.casefold()):
        raise PolicyError("INSTALL_DIR_OUTSIDE_APPROVED_ROOTS")
    if re.search(r'["&|<>^%]', str(resolved)):
        raise PolicyError("INSTALL_DIR_INVALID")
    return str(resolved)


def deployment_plan(installer_path: str, expected_sha256: str, profile: str = "msi",
                    install_dir: str = "") -> dict[str, Any]:
    """Create a deployment plan for a VERIFIED installer. Nothing is executed or approved here."""
    if profile not in PROFILES:
        raise PolicyError("UNSUPPORTED_INSTALLER_PROFILE")
    if not re.fullmatch(r"[a-fA-F0-9]{64}", expected_sha256 or ""):
        raise PolicyError("EXPECTED_SHA256_REQUIRED")
    verified = installer_verify(installer_path, expected_sha256)
    if verified["verdict"] != "ACCEPT":
        raise PolicyError("INSTALLER_REJECTED:" + verified["verdict"])
    installer = Path(verified["path"])
    if installer.suffix.casefold() != PROFILES[profile]["ext"]:
        raise PolicyError("PROFILE_DOES_NOT_MATCH_INSTALLER_TYPE")
    target = _install_dir(install_dir)
    before = [r for r in _installed()]
    plan_id = new_id("dpl")
    plan = {"id": plan_id, "created_at": iso(), "state": "planned", "installer": str(installer),
            "sha256": verified["sha256"], "profile": profile, "install_dir": target,
            "msi": verified.get("msi") or {}, "signature": {k: verified["signature"].get(k) for k in
                                                           ("status", "subject", "thumbprint")},
            "inventory_before": sorted(r["key"] for r in before)[:3000], "log": None, "history": []}
    plan["digest"] = digest_of("deployment.apply", _bound(plan))
    _save_plan(plan)
    audit("deployment.plan", "PLANNED", plan_id=plan_id, installer=str(installer), profile=profile)
    return {"plan_id": plan_id, "digest": plan["digest"], "profile": profile, "install_dir": target or None,
            "sha256": plan["sha256"], "signature": plan["signature"], "elevation_note":
            "Server does not elevate. Per-machine installs need an already-elevated server context; "
            "otherwise apply reports needs_elevation.", "next": "deployment_apply(plan_id) -> operator approval"}


def _bound(plan: dict[str, Any]) -> dict[str, Any]:
    return {"plan": plan["id"], "installer": plan["installer"], "sha256": plan["sha256"],
            "profile": plan["profile"], "install_dir": plan["install_dir"]}


def _argv_for(plan: dict[str, Any], staged: Path, log: Path, uninstall: bool = False) -> tuple[Path, list[str]]:
    profile = plan["profile"]
    msiexec = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "msiexec.exe"
    if profile == "msi":
        if uninstall:
            code = (plan.get("msi") or {}).get("product_code")
            if not code or not re.fullmatch(r"\{[0-9A-Fa-f-]{36}\}", code):
                raise PolicyError("ROLLBACK_NOT_SUPPORTED_NO_PRODUCT_CODE")
            return msiexec, ["/x", code, "/qn", "/norestart", "/L*v", str(log)]
        args = ["/i", str(staged), "/qn", "/norestart", "/L*v", str(log)]
        if plan["install_dir"]:
            args.append("INSTALLDIR=" + plan["install_dir"])
        return msiexec, args
    spec = PROFILES[profile]
    if uninstall:
        raise PolicyError("ROLLBACK_NOT_SUPPORTED_FOR_PROFILE")
    args = list(spec["args"])
    if plan["install_dir"]:
        args.append(spec["dir"].format(dir=plan["install_dir"]))
    return staged, args


def deployment_apply(plan_id: str, approval_id: str | None = None, timeout_s: int = 1800) -> dict[str, Any]:
    """Run an approved plan: stage + re-hash the installer, execute as a managed process, record outcome."""
    plan = _load_plan(plan_id)
    if plan["state"] not in ("planned", "failed"):
        raise PolicyError("PLAN_NOT_APPLICABLE_IN_STATE:" + plan["state"])
    if digest_of("deployment.apply", _bound(plan)) != plan["digest"]:
        audit("deployment.apply", "DENIED", plan_id=plan_id, reason="PLAN_TAMPERED")
        raise PolicyError("PLAN_DIGEST_MISMATCH")
    pending = approval_or_response("deployment.apply", _bound(plan), approval_id, ELEVATED)
    if pending:
        return pending
    source = Path(plan["installer"])
    if not source.is_file() or _sha256_file(source) != plan["sha256"]:
        raise PolicyError("INSTALLER_CHANGED_SINCE_PLAN")
    stage_dir = state_subdir("staging") / plan_id
    stage_dir.mkdir(parents=True, exist_ok=True)
    staged = stage_dir / source.name
    shutil.copy2(source, staged)
    if _sha256_file(staged) != plan["sha256"]:
        raise PolicyError("STAGED_COPY_HASH_MISMATCH")
    log = stage_dir / "install.log"
    exe, args = _argv_for(plan, staged, log)
    env = pt.build_env()
    managed = pt.launch(kind="deployment", label="install:" + plan_id, argv=args, cmdline=None, exe_path=exe,
                        cwd=stage_dir, env=env, timeout_s=max(60, min(int(timeout_s), 7200)), mode=ELEVATED,
                        approval_id=approval_id, summary={"plan": plan_id, "profile": plan["profile"],
                                                          "exe": exe.name}, kill_orphans=False)
    plan.update(state="running", process_id=managed.meta["id"], log=str(log), started_at=iso())
    plan["history"].append({"at": iso(), "event": "apply_started", "process_id": managed.meta["id"]})
    _save_plan(plan)
    pt.wait_done(managed, 5)
    return {"plan_id": plan_id, "state": plan["state"], "process_id": managed.meta["id"],
            "next": "poll deployment_status(plan_id)"}


def deployment_status(plan_id: str) -> dict[str, Any]:
    """Status of a deployment: process outcome, reboot requirement, detected new software entries."""
    plan = _load_plan(plan_id)
    if plan["state"] == "running" and plan.get("process_id"):
        managed = pt.get_managed(plan["process_id"])
        meta = managed.meta
        if meta["state"] in pt.TERMINAL:
            code = meta.get("exit_code")
            if meta["state"] == "exited" and code in (0, *REBOOT_CODES):
                plan["state"] = "installed"
            elif code in ELEVATION_CODES:
                plan["state"] = "needs_elevation"
            else:
                plan["state"] = "failed"
            plan["exit_code"] = code
            plan["reboot_required"] = code in REBOOT_CODES or _reboot_pending()
            after = {r["key"] for r in _installed()}
            plan["new_software_keys"] = sorted(after - set(plan["inventory_before"]))[:50]
            plan["ended_at"] = iso()
            plan["history"].append({"at": iso(), "event": plan["state"], "exit_code": code})
            _save_plan(plan)
            audit("deployment.end", plan["state"], plan_id=plan_id, exit_code=code)
    log_tail = ""
    if plan.get("log") and Path(plan["log"]).is_file():
        raw = Path(plan["log"]).read_bytes()[-4000:]
        log_tail = redact_text((raw.decode("utf-16-le", errors="ignore") if raw[:2] == b"\xff\xfe"
                                else raw.decode("utf-8", errors="replace")))[-1500:]
    return {k: plan.get(k) for k in ("id", "state", "profile", "installer", "sha256", "exit_code",
                                     "reboot_required", "new_software_keys", "started_at", "ended_at",
                                     "history")} | {"log_tail": log_tail}


def deployment_rollback(plan_id: str, approval_id: str | None = None, timeout_s: int = 1800) -> dict[str, Any]:
    """Uninstall what a plan installed (MSI by ProductCode). Other profiles report NOT_SUPPORTED."""
    plan = _load_plan(plan_id)
    if plan["state"] not in ("installed", "failed"):
        raise PolicyError("ROLLBACK_NOT_APPLICABLE_IN_STATE:" + plan["state"])
    bound = {"plan": plan_id, "rollback": True, "product": (plan.get("msi") or {}).get("product_code"),
             "profile": plan["profile"]}
    try:
        _argv_for(plan, Path("."), Path("."), uninstall=True)
    except PolicyError as exc:
        return {"status": "NOT_SUPPORTED", "reason": str(exc),
                "manual": "Uninstall via Windows Apps & features or the product's own uninstaller."}
    pending = approval_or_response("deployment.rollback", bound, approval_id, ELEVATED)
    if pending:
        return pending
    stage_dir = state_subdir("staging") / plan_id
    stage_dir.mkdir(parents=True, exist_ok=True)
    log = stage_dir / "uninstall.log"
    exe, args = _argv_for(plan, Path("."), log, uninstall=True)
    managed = pt.launch(kind="deployment", label="rollback:" + plan_id, argv=args, cmdline=None, exe_path=exe,
                        cwd=stage_dir, env=pt.build_env(), timeout_s=max(60, min(int(timeout_s), 7200)),
                        mode=ELEVATED, approval_id=approval_id, summary={"plan": plan_id, "rollback": True},
                        kill_orphans=False)
    pt.wait_done(managed, max(60, min(int(timeout_s), 7200)))
    code = managed.meta.get("exit_code")
    plan["state"] = "rolled_back" if code in (0, *REBOOT_CODES) else "rollback_failed"
    plan["history"].append({"at": iso(), "event": plan["state"], "exit_code": code})
    plan["reboot_required"] = code in REBOOT_CODES or _reboot_pending()
    _save_plan(plan)
    audit("deployment.rollback", plan["state"], plan_id=plan_id, exit_code=code)
    return {"plan_id": plan_id, "state": plan["state"], "exit_code": code,
            "reboot_required": plan["reboot_required"]}


def register_deploy_tools(server: Any) -> None:
    server.tool(annotations=_RO)(software_inspect)
    server.tool(annotations=_RO)(installer_verify)
    server.tool(annotations=_MUT)(deployment_plan)
    server.tool(annotations=_MUT)(deployment_apply)
    server.tool(annotations=_RO)(deployment_status)
    server.tool(annotations=_MUT)(deployment_rollback)
