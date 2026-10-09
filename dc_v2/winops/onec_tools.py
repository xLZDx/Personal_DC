"""1C:Enterprise / Apache / OData diagnostics and reversible, approval-gated repair.

Nothing here assumes an Apache path, 1C version, publication name or database: everything is discovered
from services, configured install roots and the Apache configuration itself. Credentials are never
returned or logged: connection strings are redacted, OData credentials are read only from an
operator-provisioned DPAPI secret (``odata-<ref>``) and business records are never returned (only
metadata names and record counts).
"""
from __future__ import annotations

import base64
import contextlib
import difflib
import hashlib
import json
import os
import re
import shutil
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from mcp.types import ToolAnnotations
from personal_dc.policy import PolicyError

from . import service_tools as svc
from .common import (ELEVATED, _is_under, approval_or_response, assert_no_reparse_chain, atomic_write_bytes,
                     atomic_write_json, audit, digest_of, iso, load_secret, native_config, new_id, read_json,
                     redact_text, state_subdir, threaded, valid_id)
from .sysrun import ps_json, run_capture

_RO = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
_NET = ToolAnnotations(readOnlyHint=True, openWorldHint=True)
_MUT = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False)

MAX_CONF_BYTES = 2 * 1024 * 1024
MAX_VRD_BYTES = 512 * 1024
MAX_METADATA_BYTES = 16 * 1024 * 1024
BACKUP_KEEP = 20
_PUB_NAME = re.compile(r"^[\w.-]{1,100}$", re.UNICODE)
_HTTPD_RE = re.compile(r'"?([A-Za-z]:\\[^"\r\n]*?httpd\.exe)"?', re.IGNORECASE)
ODATA_PREFIX = "/odata/standard.odata"


# ------------------------------------------------------------------ helpers
def _under(path: Path, roots: list[str]) -> bool:
    return any(_is_under(path, Path(r).resolve(strict=False)) for r in roots)


def _read_limited(path: Path, limit_bytes: int) -> bytes:
    if path.stat().st_size > limit_bytes:
        raise PolicyError("FILE_TOO_LARGE")
    return path.read_bytes()


def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse_xml_safe(data: bytes) -> ET.Element:
    """Reject DTDs/entities ANYWHERE in the document and any non-UTF-8 encoding (UTF-16 would hide them)."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff") or b"\x00" in data[:400]:
        raise PolicyError("XML_ENCODING_NOT_ALLOWED")
    upper = data.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise PolicyError("XML_DTD_NOT_ALLOWED")
    try:
        return ET.fromstring(data)
    except ET.ParseError as exc:
        raise PolicyError("XML_INVALID") from exc


_CONN_SECRET = re.compile(r'(?i)\b(usr|pwd|user|password)\s*=\s*("(?:[^"]|"")*"|&quot;.*?&quot;|[^;]*)')


def _redact_conn(conn: str) -> str:
    return _CONN_SECRET.sub(lambda m: m.group(1) + "=***", conn)


def _parse_ib(conn: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for key in ("File", "Srvr", "Ref", "Ws"):
        match = re.search(rf'(?i)\b{key}\s*=\s*"((?:[^"]|"")*)"|\b{key}\s*=\s*([^;]*)', conn)
        if match:
            value = match.group(1) if match.group(1) is not None else match.group(2)
            out[key.lower()] = value.replace('""', '"').strip()
    return out


def _allowed_hosts() -> set[str]:
    hosts = {h.casefold() for h in native_config()["odata_allowed_hosts"]}
    hosts.add(socket.gethostname().casefold())
    return hosts


def _tcp_check(host: str, port: int, timeout: float = 3.0) -> dict[str, Any]:
    if host.casefold() not in _allowed_hosts():
        return {"host": host, "port": port, "checked": False, "reason": "HOST_NOT_ALLOWED_FOR_PROBE"}
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"host": host, "port": port, "checked": True, "open": True,
                    "ms": round((time.monotonic() - started) * 1000)}
    except OSError as exc:
        return {"host": host, "port": port, "checked": True, "open": False, "error": type(exc).__name__}


# ------------------------------------------------------------ discovery: 1C
def discover_onec() -> dict[str, Any]:
    found = []
    roots = list(native_config()["onec_roots"])
    local = os.environ.get("LOCALAPPDATA")
    if local and (Path(local) / "Programs").is_dir():      # per-user installs (1cv8, 1cv8_x64, ...)
        roots += [str(p) for p in sorted((Path(local) / "Programs").glob("1cv8*")) if p.is_dir()]
    for root in roots:
        base = Path(root)
        if not base.is_dir():
            continue
        for ver in sorted(p for p in base.iterdir() if p.is_dir()):
            bin_dir = ver / "bin"
            exes = {n: (bin_dir / n).is_file() for n in ("1cv8.exe", "1cv8c.exe", "webinst.exe", "ibcmd.exe",
                                                         "ragent.exe", "rmngr.exe", "ras.exe")}
            modules = {n: (bin_dir / n).is_file() for n in ("wsap24.dll", "wsap22.dll", "wsisapi.dll")}
            if any(exes.values()) or any(modules.values()):
                found.append({"version": ver.name, "path": str(ver), "executables": exes, "web_modules": modules})
    return {"platforms": found}


def _onec_services() -> list[dict[str, Any]]:
    script = r"""
Get-CimInstance Win32_Service | Where-Object { $_.PathName -match '(ragent|rmngr|ras|1cv8|httpd)\.exe' } |
  Select-Object Name, DisplayName, State, StartMode, PathName | ConvertTo-Json -Compress -Depth 2
"""
    rows = ps_json(script, timeout=45) or []
    rows = [rows] if isinstance(rows, dict) else rows
    return [{"name": r["Name"], "display_name": r["DisplayName"], "state": r["State"], "start_mode": r["StartMode"],
             "path_name": redact_text(str(r.get("PathName") or ""))} for r in rows]


def _infobases() -> tuple[list[dict[str, str]], str | None]:
    appdata = os.environ.get("APPDATA")
    if not appdata:
        return [], "APPDATA_NOT_SET"
    path = Path(appdata) / "1C" / "1CEStart" / "ibases.v8i"
    if not path.is_file():
        return [], None
    try:
        text = _read_limited(path, 1024 * 1024).decode("utf-8-sig", errors="replace")
    except (OSError, PolicyError) as exc:
        return [], type(exc).__name__
    out, name = [], None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1]
        elif line.lower().startswith("connect=") and name:
            conn = _parse_ib(line[8:])
            kind = "file" if "file" in conn else "server" if "srvr" in conn else "web" if "ws" in conn else "other"
            out.append({"name": name, "kind": kind})
    return out[:100], None


# --------------------------------------------------------- discovery: Apache
def discover_apache() -> tuple[list[dict[str, Any]], bool]:
    """Return (installs, degraded). ``degraded`` means the service query failed: callers must fail closed."""
    cfg = native_config()
    installs: dict[str, dict[str, Any]] = {}
    degraded = False
    script = r"""
Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'httpd\.exe' } |
  Select-Object Name, State, StartMode, PathName | ConvertTo-Json -Compress -Depth 2
"""
    try:
        rows = ps_json(script, timeout=45) or []
    except PolicyError:
        rows, degraded = [], True
    rows = [rows] if isinstance(rows, dict) else rows
    for row in rows:
        path_name = str(row.get("PathName") or "")
        match = _HTTPD_RE.search(path_name)
        if not match:
            continue
        exe = Path(match.group(1))
        root = exe.parent.parent
        conf_m = re.search(r'-f\s+"?([^"\r\n]+?)"?(?:\s+-|\s*$)', path_name)
        d_m = re.search(r'-d\s+"?([^"\r\n]+?)"?(?:\s+-|\s*$)', path_name)
        server_root = Path(d_m.group(1)) if d_m else root
        conf = Path(conf_m.group(1)) if conf_m else server_root / "conf" / "httpd.conf"
        installs[str(exe).casefold()] = {"httpd_exe": str(exe), "server_root": str(server_root), "conf": str(conf),
                                        "service": {"name": row["Name"], "state": row["State"],
                                                    "start_mode": row["StartMode"]}}
    for root in cfg["apache_roots"]:
        base = Path(root)
        candidates = [base] + ([p for p in base.iterdir() if p.is_dir()] if base.is_dir() else [])
        for cand in candidates:
            exe = cand / "bin" / "httpd.exe"
            if exe.is_file() and str(exe).casefold() not in installs:
                installs[str(exe).casefold()] = {"httpd_exe": str(exe), "server_root": str(cand),
                                                "conf": str(cand / "conf" / "httpd.conf"), "service": None}
    result = []
    for item in installs.values():
        item["exe_exists"] = Path(item["httpd_exe"]).is_file()
        item["conf_exists"] = Path(item["conf"]).is_file()
        result.append(item)
    return result, degraded


def _pick_apache(server_root: str = "") -> dict[str, Any]:
    installs, _degraded = discover_apache()
    if not installs:
        raise PolicyError("APACHE_NOT_FOUND")
    if server_root:
        for item in installs:
            if str(Path(item["server_root"])).casefold() == str(Path(server_root)).casefold():
                return item
        raise PolicyError("APACHE_ROOT_NOT_DISCOVERED")
    if len(installs) > 1:
        raise PolicyError("MULTIPLE_APACHE_INSTALLS_SPECIFY_server_root")
    return installs[0]


def _expand(text: str, defines: dict[str, str]) -> str:
    return re.sub(r"\$\{(\w+)\}", lambda m: defines.get(m.group(1), m.group(0)), text)


def _collect_conf(install: dict[str, Any]) -> dict[str, Any]:
    """Parse httpd.conf (+Include tree, bounded) into the directives that matter for 1C publishing."""
    server_root = Path(install["server_root"])
    roots = [str(server_root)] + list(native_config()["apache_roots"])
    pending = [Path(install["conf"])]
    seen: set[str] = set()
    out: dict[str, Any] = {"files": [], "listen": [], "modules": {}, "publications": [], "errors": [],
                           "truncated": False}
    defines: dict[str, str] = {"SRVROOT": str(server_root).replace("\\", "/")}
    aliases: dict[str, str] = {}
    while pending:
        if len(seen) >= 50:
            out["truncated"] = True
            break
        path = pending.pop(0)
        key = str(path).casefold()
        if key in seen:
            continue
        seen.add(key)
        try:
            if not _under(path, roots):
                out["errors"].append({"file": str(path), "error": "OUTSIDE_APACHE_ROOTS"})
                continue
            text = _read_limited(path, MAX_CONF_BYTES).decode("utf-8", errors="replace")
        except (OSError, PolicyError) as exc:
            out["errors"].append({"file": str(path), "error": type(exc).__name__})
            continue
        out["files"].append(str(path))
        for raw in text.splitlines():
            line = _expand(raw.strip(), defines)
            if not line or line.startswith("#"):
                continue
            low = line.casefold()
            if low.startswith("define "):
                parts = line.split(None, 2)
                if len(parts) == 3:
                    defines[parts[1]] = parts[2].strip('"')
            elif low.startswith("listen "):
                out["listen"].append(line.split(None, 1)[1].strip())
            elif low.startswith("loadmodule "):
                parts = re.match(r'(?i)loadmodule\s+(\S+)\s+"?([^"\r\n]+?)"?\s*$', line)
                if parts:
                    module_path = parts.group(2).replace("/", "\\")
                    if not re.match(r"^[A-Za-z]:\\", module_path):
                        module_path = str(server_root / module_path)
                    out["modules"][parts.group(1)] = module_path
            elif low.startswith(("include ", "includeoptional ")):
                target = line.split(None, 1)[1].strip().strip('"').replace("/", "\\")
                pattern = Path(target) if Path(target).is_absolute() else server_root / target
                if any(ch in target for ch in "*?"):
                    pending.extend(sorted(pattern.parent.glob(pattern.name))[:30])
                else:
                    pending.append(pattern)
            elif low.startswith("alias "):
                m = re.match(r'(?i)alias\s+"?([^"\s]+)"?\s+"?([^"\r\n]+?)"?\s*$', line)
                if m:
                    aliases[m.group(2).replace("/", "\\").rstrip("\\").casefold()] = m.group(1)
            elif low.startswith("managedapplicationdescriptor"):
                m = re.match(r'(?i)managedapplicationdescriptor\s+"?([^"\r\n]+?)"?\s*$', line)
                if m:
                    out["publications"].append({"vrd": m.group(1).replace("/", "\\"), "conf_file": str(path)})
    for pub in out["publications"]:
        folder = str(Path(pub["vrd"]).parent).rstrip("\\").casefold()
        url = aliases.get(folder)
        pub["alias"] = url
        pub["name"] = (url or "/" + Path(pub["vrd"]).parent.name).strip("/")
    return out


def _vrd_details(path: Path) -> dict[str, Any]:
    info: dict[str, Any] = {"vrd": str(path), "exists": path.is_file()}
    if not info["exists"]:
        return info
    data = _read_limited(path, MAX_VRD_BYTES)
    info["sha256"] = hashlib.sha256(data).hexdigest()
    root = _parse_xml_safe(data)
    info["base"] = root.attrib.get("base")
    ib = root.attrib.get("ib", "")
    info["ib"] = _redact_conn(ib)
    info["ib_parts"] = _parse_ib(ib)
    info["odata"] = {"element_present": False, "enabled": False}
    info["services"] = {}
    for el in root.iter():
        tag = _strip_ns(el.tag)
        if tag == "standardOdata":
            info["odata"] = {"element_present": True, "enabled": el.attrib.get("enable", "").lower() == "true",
                             "attrs": {k: v for k, v in el.attrib.items() if k in
                                       ("enable", "reuseSessions", "sessionMaxAge", "poolSize", "poolTimeout")}}
        elif tag in ("ws", "httpServices", "analytics", "pointEnable"):
            info["services"][tag] = {k: v for k, v in el.attrib.items() if k in ("publishByDefault", "enable")}
    return info


def _publication_list(install: dict[str, Any]) -> list[dict[str, Any]]:
    conf = _collect_conf(install)
    pubs = []
    for pub in conf["publications"]:
        vrd = Path(pub["vrd"])
        try:
            details = _vrd_details(vrd)
        except PolicyError as exc:
            details = {"vrd": str(vrd), "exists": vrd.is_file(), "error": str(exc)}
        pubs.append({"name": pub["name"], "alias": pub["alias"], "conf_file": pub["conf_file"], **details})
    names = [str(p["name"]).casefold() for p in pubs]
    for pub in pubs:
        pub["ambiguous"] = names.count(str(pub["name"]).casefold()) > 1
    return pubs


def _configtest(install: dict[str, Any]) -> dict[str, Any]:
    if not install["exe_exists"] or not install["conf_exists"]:
        return {"ok": False, "reason": "HTTPD_OR_CONF_MISSING"}
    result = run_capture([install["httpd_exe"], "-t", "-f", install["conf"], "-d", install["server_root"]],
                         timeout=25)
    if result.get("launch_error"):
        return {"ok": False, "reason": "HTTPD_LAUNCH_FAILED:" + str(result.get("error"))}
    text = redact_text((result["stderr"] + result["stdout"]).strip())[:1500]
    return {"ok": result["exit_code"] == 0 and "syntax ok" in text.casefold(), "exit_code": result["exit_code"],
            "output": text, "timed_out": result["timed_out"]}


def _finding(fid: str, severity: str, message: str, **evidence: Any) -> dict[str, Any]:
    return {"id": fid, "severity": severity, "message": message, "evidence": evidence}


def _listen_endpoint(listen: str) -> tuple[str, int] | None:
    """Parse a Listen directive into (host, port); a bare port means all interfaces -> loopback probe."""
    spec = listen.split()[0]
    if spec.isdigit():
        return "127.0.0.1", int(spec)
    host, _, port = spec.rpartition(":")
    if not port.isdigit():
        return None
    host = host.strip("[]")
    return ("127.0.0.1" if host in ("0.0.0.0", "*", "::", "") else host), int(port)


# -------------------------------------------------------------- MCP tools
def apache_diagnostics(server_root: str = "") -> dict[str, Any]:
    """Discover Apache, test its configuration, list 1C publications and flag common misconfigurations."""
    installs, degraded = discover_apache()
    report: dict[str, Any] = {"installs": [], "findings": [], "discovery_degraded": degraded}
    findings = report["findings"]
    if degraded:
        findings.append(_finding("SERVICE_DISCOVERY_FAILED", "medium",
                                 "Windows service query failed; Apache service state is unknown"))
    if not installs:
        findings.append(_finding("APACHE_NOT_FOUND", "high", "No Apache httpd service or install found"))
        return report
    matched = 0
    for install in installs:
        if server_root and str(Path(install["server_root"])).casefold() != str(Path(server_root)).casefold():
            continue
        matched += 1
        entry = dict(install)
        entry["configtest"] = _configtest(install)
        conf = _collect_conf(install) if install["conf_exists"] else {
            "errors": [{"file": install["conf"], "error": "CONF_MISSING"}], "listen": [], "modules": {},
            "publications": [], "files": [], "truncated": False}
        entry["listen"], entry["conf_files"] = conf["listen"], conf["files"]
        entry["conf_errors"], entry["conf_truncated"] = conf["errors"], conf["truncated"]
        module_1c = {k: v for k, v in conf["modules"].items() if "1c" in k.casefold() or "wsap" in v.casefold()}
        entry["onec_modules"] = {k: {"path": v, "exists": Path(v).is_file()} for k, v in module_1c.items()}
        entry["publications"] = _publication_list(install) if install["conf_exists"] else []
        tag = install["server_root"]
        if conf["errors"] or conf["truncated"]:
            findings.append(_finding("CONFIG_READ_INCOMPLETE", "medium",
                                     "Some Apache config files could not be read or the include limit was hit; "
                                     "other findings may be incomplete", errors=conf["errors"][:5],
                                     truncated=conf["truncated"], root=tag))
        if install["service"] and install["service"]["state"] != "Running":
            findings.append(_finding("APACHE_SERVICE_NOT_RUNNING", "high", "Apache service is not running",
                                     service=install["service"]["name"], state=install["service"]["state"], root=tag))
        if not entry["configtest"]["ok"]:
            findings.append(_finding("APACHE_CONFIG_INVALID", "high", "httpd -t did not report Syntax OK",
                                     output=entry["configtest"].get("output") or entry["configtest"].get("reason"),
                                     root=tag))
        if not module_1c:
            findings.append(_finding("ONEC_MODULE_NOT_LOADED", "high",
                                     "No 1C web extension LoadModule (wsap*.dll) in Apache config", root=tag))
        for key, mod in entry["onec_modules"].items():
            if not mod["exists"]:
                findings.append(_finding("ONEC_MODULE_FILE_MISSING", "high",
                                         "LoadModule points to a missing file (platform moved/removed?)",
                                         module=key, path=mod["path"]))
        if not entry["publications"]:
            findings.append(_finding("NO_1C_PUBLICATION", "medium", "No ManagedApplicationDescriptor found", root=tag))
        for pub in entry["publications"]:
            findings.extend(_publication_findings(pub))
        if install["service"] and install["service"]["state"] == "Running":
            for listen in conf["listen"][:5]:
                endpoint = _listen_endpoint(listen)
                if endpoint:
                    check = _tcp_check(*endpoint, 2.0)
                    if check.get("checked") and not check.get("open"):
                        findings.append(_finding("LISTEN_PORT_NOT_ACCEPTING", "high",
                                                 "Apache is Running but the Listen endpoint does not accept connections",
                                                 host=endpoint[0], port=endpoint[1]))
        report["installs"].append(entry)
    if server_root and not matched:
        findings.append(_finding("SERVER_ROOT_FILTER_MATCHED_NOTHING", "medium",
                                 "server_root does not match any discovered install",
                                 discovered=[i["server_root"] for i in installs]))
    audit("onec.apache_diagnostics", "OK", installs=len(report["installs"]), findings=len(findings))
    return report


def _publication_findings(pub: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    name = pub.get("name")
    if pub.get("ambiguous"):
        out.append(_finding("PUBLICATION_NAME_AMBIGUOUS", "medium", "Several publications share this name",
                            publication=name))
    if not pub.get("exists"):
        return out + [_finding("VRD_MISSING", "high", "Publication descriptor file does not exist",
                               publication=name, vrd=pub.get("vrd"))]
    if pub.get("error"):
        return out + [_finding("VRD_INVALID", "high", "Publication descriptor cannot be parsed", publication=name,
                               error=pub["error"])]
    if not pub.get("odata", {}).get("enabled"):
        out.append(_finding("ODATA_DISABLED", "medium", "standardOdata is not enabled in the publication",
                            publication=name, element_present=pub["odata"]["element_present"]))
    parts = pub.get("ib_parts", {})
    if "file" in parts and not Path(parts["file"]).exists():
        out.append(_finding("IB_FILE_PATH_MISSING", "high", "File infobase path does not exist", publication=name,
                            path=parts["file"]))
    if not pub.get("ib_parts"):
        out.append(_finding("IB_CONNECTION_MISSING", "high", "Publication has no ib connection string",
                            publication=name))
    return out


def onec_diagnostics() -> dict[str, Any]:
    """Inventory 1C platform versions, 1C services, known infobases (names only) and publication health."""
    platforms = discover_onec()
    services = _onec_services()
    infobases, infobase_error = _infobases()
    apache = apache_diagnostics()
    findings = list(apache["findings"])
    if infobase_error:
        findings.append(_finding("INFOBASE_LIST_UNREADABLE", "low", "ibases.v8i could not be read",
                                 error=infobase_error))
    if not platforms["platforms"]:
        findings.append(_finding("ONEC_PLATFORM_NOT_FOUND", "high", "No 1C platform under configured onec_roots",
                                 roots=native_config()["onec_roots"]))
    versions = {p["version"] for p in platforms["platforms"]}
    for install in apache["installs"]:
        for key, mod in install.get("onec_modules", {}).items():
            m = re.search(r"1cv8[\\/]([0-9.]+)[\\/]", mod["path"], re.IGNORECASE)
            if m and versions and m.group(1) not in versions:
                findings.append(_finding("ONEC_MODULE_VERSION_NOT_INSTALLED", "high",
                                         "Apache module belongs to a platform version that is not installed",
                                         module_version=m.group(1), installed=sorted(versions)))
    audit("onec.diagnostics", "OK", findings=len(findings))
    return {"platforms": platforms["platforms"], "services": services, "infobases": infobases,
            "apache": apache["installs"], "findings": findings}


def onec_publication_inspect(publication: str = "", server_root: str = "") -> dict[str, Any]:
    """Inspect 1C web publications (descriptor, redacted connection, OData flags, hash)."""
    install = _pick_apache(server_root)
    pubs = _publication_list(install)
    if publication:
        pubs = [p for p in pubs if str(p.get("name", "")).casefold() == publication.casefold()]
        if not pubs:
            raise PolicyError("PUBLICATION_NOT_FOUND")
    audit("onec.publication_inspect", "OK", count=len(pubs))
    return {"server_root": install["server_root"], "publications": pubs}


def onec_connection_check(publication: str = "", server_root: str = "") -> dict[str, Any]:
    """Check reachability of the infobase behind each publication (path/TCP only; no login, no data)."""
    install = _pick_apache(server_root)
    results = []
    for pub in _publication_list(install):
        if publication and str(pub.get("name", "")).casefold() != publication.casefold():
            continue
        parts = pub.get("ib_parts", {})
        entry: dict[str, Any] = {"publication": pub.get("name"), "ib": pub.get("ib")}
        if "file" in parts:
            db = Path(parts["file"]) / "1Cv8.1CD"
            entry.update(kind="file", path_exists=Path(parts["file"]).is_dir(), database_file_present=db.is_file())
        elif "srvr" in parts:
            host, _, port = parts["srvr"].partition(":")
            entry.update(kind="server", cluster_host=host, ref=parts.get("ref"),
                         tcp=_tcp_check(host or "127.0.0.1", int(port) if port.isdigit() else 1541))
        else:
            entry.update(kind="unknown")
        results.append(entry)
    if not results:
        raise PolicyError("NO_MATCHING_PUBLICATION")
    audit("onec.connection_check", "OK", count=len(results))
    return {"checks": results}


# ------------------------------------------------------------------ OData
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:  # noqa: D401
        return None


def _odata_url(publication: str, url: str, path: str, server_root: str, with_credential: bool) -> str:
    if path and (not re.fullmatch(r"[\w$./()=?&',%-]{1,300}", path, re.UNICODE)
                 or ".." in urllib.parse.unquote(urllib.parse.unquote(path))):
        raise PolicyError("ODATA_PATH_INVALID")
    if with_credential and path not in ("", "$metadata"):
        raise PolicyError("CREDENTIALED_PROBE_ALLOWS_ONLY_METADATA_OR_ROOT")
    if url:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname \
                or parsed.hostname.casefold() not in _allowed_hosts():
            raise PolicyError("ODATA_HOST_NOT_ALLOWED")
        if parsed.username or parsed.password or parsed.fragment or parsed.query:
            raise PolicyError("ODATA_URL_USERINFO_QUERY_FRAGMENT_NOT_ALLOWED")
        if ODATA_PREFIX not in parsed.path.casefold() or ".." in urllib.parse.unquote(parsed.path):
            raise PolicyError("ODATA_URL_MUST_TARGET_STANDARD_ODATA")
        base = url.rstrip("/")
    else:
        if not _PUB_NAME.fullmatch(publication or "") or publication.strip(".") == "":
            raise PolicyError("PUBLICATION_REQUIRED")
        install = _pick_apache(server_root)
        endpoint = next((e for e in map(_listen_endpoint, _collect_conf(install)["listen"]) if e), ("127.0.0.1", 80))
        base = f"http://{endpoint[0]}:{endpoint[1]}/{urllib.parse.quote(publication)}{ODATA_PREFIX}"
    if path and base.rstrip("/").endswith("/" + path.lstrip("/")):
        return base                                   # the caller's URL already names the target
    if path:
        quoted = urllib.parse.quote(path, safe="/$=?&',()%")      # Cyrillic entity names must be percent-encoded
        full = base + "/" + quoted.lstrip("/")
        if "?" not in path and path != "$metadata":
            full += "?$top=1&$format=json"
        elif "?" in path and "$top" not in path and "$metadata" not in path:
            full += "&$top=1"
        return full
    return base + "/"


_EDMX_NAMESPACES = {"http://schemas.microsoft.com/ado/2007/06/edmx", "http://docs.oasis-open.org/odata/ns/edmx"}


def _edmx_structure_error(root: ET.Element) -> str | None:
    """OData $metadata must be an EDMX document: Edmx root in a known namespace > DataServices > Schema > EntityContainer."""
    namespace = root.tag[1:].split("}", 1)[0] if root.tag.startswith("{") else ""
    if _strip_ns(root.tag) != "Edmx" or namespace not in _EDMX_NAMESPACES:
        return "NOT_EDMX"
    services = [c for c in root if _strip_ns(c.tag) == "DataServices"]
    if len(services) != 1:
        return "EDMX_DATASERVICES_MISSING"
    schemas = [c for c in services[0] if _strip_ns(c.tag) == "Schema"]
    if not schemas:
        return "EDMX_SCHEMA_MISSING"
    if not any(_strip_ns(e.tag) == "EntityContainer" for s in schemas for e in s):
        return "EDMX_ENTITY_CONTAINER_MISSING"
    return None


def _bound_basic_auth(blob: bytes, target: str) -> str:
    """Authorization header for a credential that is BOUND to one scheme/host/port/publication.

    The operator provisions the binding with the credential (``approve set-odata-credential``); a target
    that does not match it never receives the secret. Unbound (legacy ``user:password``) blobs are refused.
    """
    try:
        data = json.loads(blob.decode("utf-8"))
        user, password = str(data["user"]), str(data["password"])
        scheme, host, port, pub = str(data["scheme"]), str(data["host"]).casefold(), int(data["port"]), str(data["publication"])
    except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
        raise PolicyError("CREDENTIAL_REF_NOT_BOUND_REPROVISION_WITH_ENDPOINT") from exc
    parts = urllib.parse.urlsplit(target)
    segment = urllib.parse.unquote(parts.path.strip("/").split("/", 1)[0])
    default = 443 if parts.scheme == "https" else 80
    if (parts.scheme, (parts.hostname or "").casefold(), parts.port or default, segment.casefold()) !=             (scheme, host, port, pub.casefold()):
        audit("odata.probe", "CREDENTIAL_BINDING_MISMATCH", url=redact_text(target))
        raise PolicyError("CREDENTIAL_NOT_BOUND_TO_THIS_ENDPOINT")
    if ":" in user:
        raise PolicyError("CREDENTIAL_REF_MALFORMED")
    return "Basic " + base64.b64encode((user + ":" + password).encode("utf-8")).decode("ascii")


def odata_probe(publication: str = "", path: str = "$metadata", url: str = "", credential_ref: str = "",
                timeout_s: int = 10, server_root: str = "") -> dict[str, Any]:
    """GET-probe a local 1C OData endpoint. Returns status/timing and metadata names or record COUNT only.

    Credentials are never accepted as arguments: use an operator-provisioned `credential_ref`
    (DPAPI secret odata-<ref> containing user:password); a credentialed probe is limited to `$metadata`
    or the service root. Hosts are restricted to loopback/allowlist; redirects and proxies are not followed.
    """
    target = _odata_url(publication, url, path, server_root, bool(credential_ref))
    headers = {"Accept": "application/xml, application/json", "User-Agent": "PersonalDC-odata-probe/2"}
    if credential_ref:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", credential_ref):
            raise PolicyError("INVALID_CREDENTIAL_REF")
        blob = load_secret("odata-" + credential_ref)
        if not blob:
            raise PolicyError("CREDENTIAL_REF_NOT_PROVISIONED")
        headers["Authorization"] = _bound_basic_auth(blob, target)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)   # never via a system proxy
    started = time.monotonic()
    result: dict[str, Any] = {"url": redact_text(target), "credential_ref": credential_ref or None}
    try:
        with opener.open(urllib.request.Request(target, headers=headers, method="GET"),
                         timeout=max(2, min(int(timeout_s), 30))) as resp:
            status, hdrs, body = resp.status, resp.headers, resp.read(MAX_METADATA_BYTES + 1)
    except urllib.error.HTTPError as exc:
        status, hdrs, body = exc.code, exc.headers, b""
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        result.update(reachable=False, error=type(reason).__name__, elapsed_ms=round((time.monotonic() - started) * 1000))
        audit("odata.probe", "UNREACHABLE", url=result["url"], error=result["error"])
        return result
    result.update(reachable=True, status=status, content_type=hdrs.get("Content-Type"), size=len(body),
                  elapsed_ms=round((time.monotonic() - started) * 1000))
    auth = hdrs.get("WWW-Authenticate")
    if status == 401:
        result["auth_required"] = (auth or "").split()[0] if auth else True
    if 200 <= status < 300:
        if target.split("?", 1)[0].endswith("$metadata"):
            if len(body) > MAX_METADATA_BYTES:
                result["metadata"] = {"error": "TOO_LARGE", "limit_bytes": MAX_METADATA_BYTES}
            else:
                try:
                    root = _parse_xml_safe(body)
                    sets = [e.attrib.get("Name") for e in root.iter() if _strip_ns(e.tag) == "EntitySet"]
                    types = sum(1 for e in root.iter() if _strip_ns(e.tag) == "EntityType")
                    structure = _edmx_structure_error(root)
                    if structure:
                        result["metadata"] = {"error": structure}
                    else:
                        result["metadata"] = {"entity_types": types, "entity_sets": len(sets), "sample_sets": sets[:40]}
                except PolicyError as exc:
                    result["metadata"] = {"error": str(exc)}
        elif "json" in (hdrs.get("Content-Type") or "").lower():
            try:
                data = json.loads(body)
                value = data.get("value") if isinstance(data, dict) else None
                result["records_returned"] = len(value) if isinstance(value, list) else None
                result["note"] = "record contents are intentionally not returned"
            except ValueError:
                result["json_error"] = True
    audit("odata.probe", "OK" if 200 <= status < 300 else "HTTP_" + str(status), url=result["url"])
    return result


# ------------------------------------------------------- repair (reversible)
def _locate_vrd(publication: str, server_root: str) -> tuple[dict[str, Any], dict[str, Any]]:
    install = _pick_apache(server_root)
    matches = [p for p in _publication_list(install) if str(p.get("name", "")).casefold() == publication.casefold()]
    if not matches:
        raise PolicyError("PUBLICATION_NOT_FOUND")
    if len(matches) > 1:
        raise PolicyError("PUBLICATION_AMBIGUOUS")
    pub = matches[0]
    vrd = Path(pub["vrd"])
    if vrd.suffix.casefold() != ".vrd" or not vrd.is_file():
        raise PolicyError("VRD_NOT_FOUND")
    _check_vrd_path(vrd, [install["server_root"]])
    return install, pub


def _check_vrd_path(vrd: Path, extra_roots: list[str]) -> None:
    """Every VRD mutation (repair, recovery, rollback) passes through here immediately before writing."""
    if vrd.suffix.casefold() != ".vrd" or not vrd.is_file():
        raise PolicyError("VRD_NOT_FOUND")
    allowed = [Path(r).resolve(strict=False) for r in list(native_config()["publication_roots"]) + extra_roots]
    if not any(_is_under(vrd.resolve(strict=True), r) for r in allowed):
        raise PolicyError("VRD_OUTSIDE_PUBLICATION_ROOTS")
    assert_no_reparse_chain(Path(os.path.abspath(vrd)), allowed)


def _mask_comments(text: str) -> str:
    return re.sub(r"<!--.*?-->", lambda m: " " * len(m.group(0)), text, flags=re.S)


def _enable_odata_text(text: str) -> str:
    """Set standardOdata enable="true" (or insert the element before the root's closing tag)."""
    masked = _mask_comments(text)
    match = re.search(r"<(?:[\w.-]+:)?standardOdata\b[^>]*>", masked)
    if match:
        tag = text[match.start():match.end()]
        if re.search(r"""\benable\s*=\s*("[^"]*"|'[^']*')""", tag):
            new_tag = re.sub(r"""(\benable\s*=\s*)("[^"]*"|'[^']*')""", r'\1"true"', tag, count=1)
        else:
            new_tag = re.sub(r"(<(?:[\w.-]+:)?standardOdata)", r'\1 enable="true"', tag, count=1)
        return text[:match.start()] + new_tag + text[match.end():]
    close = masked.rfind("</point>")
    if close < 0:
        raise PolicyError("VRD_STRUCTURE_UNSUPPORTED")
    newline = "\r\n" if "\r\n" in text else "\n"
    snippet = ('\t<standardOdata enable="true" reuseSessions="autouse" sessionMaxAge="20" '
               'poolSize="10" poolTimeout="5"/>' + newline)
    return text[:close] + snippet + text[close:]


def _decode_vrd(old: bytes) -> tuple[str, bytes]:
    bom = b"\xef\xbb\xbf" if old.startswith(b"\xef\xbb\xbf") else b""
    try:
        return old[len(bom):].decode("utf-8"), bom
    except UnicodeDecodeError as exc:
        raise PolicyError("VRD_NOT_UTF8") from exc


def _prepare_enable(install: dict[str, Any], pub: dict[str, Any]) -> tuple[dict[str, Any], bytes, list[str]] | None:
    vrd = Path(pub["vrd"])
    old = _read_limited(vrd, MAX_VRD_BYTES)
    text, bom = _decode_vrd(old)
    new_text = _enable_odata_text(text)
    if new_text == text:
        return None
    new_bytes = bom + new_text.encode("utf-8")
    _parse_xml_safe(new_bytes)
    plan = {"operation": "enable_standard_odata", "publication": pub["name"], "vrd": str(vrd),
            "old_sha256": hashlib.sha256(old).hexdigest(), "new_sha256": hashlib.sha256(new_bytes).hexdigest(),
            "server_root": install["server_root"]}
    diff = [redact_text(line.rstrip("\n")) for line in difflib.unified_diff(
        text.splitlines(True), new_text.splitlines(True), "current", "proposed", n=1)][:60]
    return plan, new_bytes, diff


def _prune_backups() -> None:
    base = state_subdir("backups")
    folders = sorted((p for p in base.iterdir() if p.is_dir()), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in folders[BACKUP_KEEP:]:
        shutil.rmtree(old, ignore_errors=True)


def _backup_vrd(vrd: Path, operation: str) -> dict[str, Any]:
    bid = new_id("bak")
    folder = state_subdir("backups") / bid
    folder.mkdir(parents=True)
    copy = folder / vrd.name
    original = vrd.read_bytes()
    atomic_write_bytes(copy, original)
    if hashlib.sha256(copy.read_bytes()).hexdigest() != hashlib.sha256(original).hexdigest():
        raise PolicyError("BACKUP_VERIFY_FAILED")
    manifest = {"id": bid, "operation": operation, "original": str(vrd), "backup": str(copy),
                "sha256": hashlib.sha256(original).hexdigest(), "created_at": iso()}
    atomic_write_json(folder / "manifest.json", manifest)
    with contextlib.suppress(OSError):
        _prune_backups()
    return manifest


def _restore(manifest: dict[str, Any]) -> bool:
    """Atomic restore of the backed-up bytes; True only when the restored file hashes correctly."""
    try:
        data = Path(manifest["backup"]).read_bytes()
        atomic_write_bytes(Path(manifest["original"]), data)
        return hashlib.sha256(Path(manifest["original"]).read_bytes()).hexdigest() == manifest["sha256"]
    except (OSError, PolicyError, KeyError):
        return False


def _apply_vrd_change(install: dict[str, Any], plan: dict[str, Any], new_bytes: bytes) -> dict[str, Any]:
    """Single implementation of 'back up, write, validate, auto-restore' for repair AND recovery."""
    vrd = Path(plan["vrd"])
    _check_vrd_path(vrd, [install["server_root"]])
    if hashlib.sha256(vrd.read_bytes()).hexdigest() != plan["old_sha256"]:
        raise PolicyError("PUBLICATION_CHANGED_SINCE_PLAN")
    baseline = _configtest(install) if install["conf_exists"] else {"ok": True}
    manifest = _backup_vrd(vrd, plan["operation"])
    audit("onec.repair", "APPLYING", publication=plan.get("publication"), backup_id=manifest["id"],
          old_sha256=plan["old_sha256"], new_sha256=plan["new_sha256"])
    try:
        atomic_write_bytes(vrd, new_bytes)
        if hashlib.sha256(vrd.read_bytes()).hexdigest() != plan["new_sha256"]:
            raise PolicyError("WRITE_VERIFY_FAILED")
        _vrd_details(vrd)                                   # still parses; descriptor semantics readable
        if install["conf_exists"]:
            after = _configtest(install)
            if baseline.get("ok") and not after["ok"]:     # only blame the change if it was healthy before
                raise PolicyError("POST_CHECK_FAILED_CONFIGTEST")
    except (OSError, PolicyError) as exc:
        restored = _restore(manifest)
        audit("onec.repair", "ROLLED_BACK" if restored else "ROLLBACK_FAILED", backup_id=manifest["id"],
              reason=type(exc).__name__)
        return {"status": "FAILED_ROLLED_BACK" if restored else "FAILED_ROLLBACK_INCOMPLETE",
                "reason": str(exc)[:200], "backup_id": manifest["id"], "restored_verified": restored}
    manifest["applied_sha256"] = plan["new_sha256"]
    atomic_write_json(Path(manifest["backup"]).parent / "manifest.json", manifest)
    audit("onec.repair", "APPLIED", publication=plan.get("publication"), backup_id=manifest["id"])
    return {"status": "APPLIED", "publication": plan.get("publication"), "backup_id": manifest["id"],
            "new_sha256": plan["new_sha256"], "baseline_configtest_ok": baseline.get("ok"),
            "rollback": {"operation": "rollback", "backup_id": manifest["id"]},
            "next": "run odata_probe / odata_recovery to verify; the 1C module re-reads the descriptor per request"}


def onec_publication_repair(publication: str, operation: str = "enable_standard_odata", apply: bool = False,
                            approval_id: str | None = None, backup_id: str = "",
                            server_root: str = "") -> dict[str, Any]:
    """Plan (default) or apply a supported, reversible publication repair.

    operation: enable_standard_odata | rollback (needs backup_id).
    apply=True requires an operator approval bound to the exact change (file hash before/after).
    The original descriptor is backed up first; a failed post-check restores it automatically.
    """
    if operation == "rollback":
        return _rollback_vrd(backup_id, apply, approval_id)
    if operation != "enable_standard_odata":
        raise PolicyError("UNSUPPORTED_REPAIR_OPERATION")
    install, pub = _locate_vrd(publication, server_root)
    prepared = _prepare_enable(install, pub)
    if prepared is None:
        return {"status": "NO_CHANGE_NEEDED", "publication": publication}
    plan, new_bytes, diff = prepared
    if not apply:
        return {"status": "PLAN", "plan": plan, "plan_digest": digest_of("onec.repair", plan), "diff": diff,
                "reversible": True, "next": "repeat with apply=true (an operator approval will be requested)"}
    pending = approval_or_response("onec.repair", plan, approval_id, ELEVATED)
    if pending:
        return {**pending, "plan": plan, "diff": diff}
    return _apply_vrd_change(install, plan, new_bytes)


def _rollback_vrd(backup_id: str, apply: bool, approval_id: str | None) -> dict[str, Any]:
    if not valid_id(backup_id) or not backup_id.startswith("bak-"):
        raise PolicyError("INVALID_BACKUP_ID")
    folder = state_subdir("backups") / backup_id
    manifest = read_json(folder / "manifest.json")
    if not manifest:
        raise PolicyError("BACKUP_NOT_FOUND")
    backup, original = Path(manifest["backup"]), Path(manifest["original"])
    if backup.parent.resolve(strict=False) != folder.resolve(strict=False) or original.suffix.casefold() != ".vrd":
        raise PolicyError("BACKUP_MANIFEST_INVALID")
    if hashlib.sha256(backup.read_bytes()).hexdigest() != manifest["sha256"]:
        raise PolicyError("BACKUP_INTEGRITY_FAILED")
    _check_vrd_path(original, [i["server_root"] for i in discover_apache()[0]])
    current = hashlib.sha256(original.read_bytes()).hexdigest()
    plan = {"operation": "rollback", "backup_id": backup_id, "target": str(original), "restore_sha256": manifest["sha256"],
            "current_sha256": current}
    if not apply:
        return {"status": "PLAN", "plan": plan, "note": "a pre-rollback backup of the current file is taken first"}
    pending = approval_or_response("onec.repair", plan, approval_id, ELEVATED)
    if pending:
        return pending
    _check_vrd_path(original, [i["server_root"] for i in discover_apache()[0]])
    if hashlib.sha256(original.read_bytes()).hexdigest() != current:
        raise PolicyError("PUBLICATION_CHANGED_SINCE_PLAN")
    safety = _backup_vrd(original, "pre-rollback")
    if not _restore(manifest):
        _restore(safety)
        raise PolicyError("ROLLBACK_VERIFY_FAILED_PREVIOUS_STATE_RESTORED")
    with contextlib.suppress(PolicyError, OSError):
        _vrd_details(original)
    audit("onec.repair", "ROLLBACK_APPLIED", backup_id=backup_id, pre_rollback_backup=safety["id"])
    return {"status": "ROLLED_BACK", "target": str(original), "pre_rollback_backup_id": safety["id"]}


# ------------------------------------------------------ Apache control
def apache_service_control(action: str = "status", service: str = "", timeout_s: int = 60,
                           approval_id: str | None = None, server_root: str = "") -> dict[str, Any]:
    """Apache: configtest | status | start | stop | restart.

    start/stop/restart need the service in the allowlist plus an operator approval, and
    start/restart are refused when `httpd -t` fails (never replace a running Apache with a broken config).
    """
    if action not in ("configtest", "status", "start", "stop", "restart"):
        raise PolicyError("UNKNOWN_APACHE_ACTION")
    install = _pick_apache(server_root)
    name = service or (install["service"] or {}).get("name") or ""
    if action == "configtest":
        return {"server_root": install["server_root"], "configtest": _configtest(install)}
    if not name or not install["service"] or install["service"]["name"].casefold() != name.casefold():
        raise PolicyError("SERVICE_NOT_THE_DISCOVERED_APACHE_SERVICE")
    if action == "status":
        return {"service": name, "state": svc.service_current_state(name)}
    if action in ("start", "restart"):
        test = _configtest(install)
        if not test["ok"]:
            audit("apache.control", "REFUSED_BAD_CONFIG", service=name, action=action)
            return {"status": "REFUSED", "reason": "APACHE_CONFIG_INVALID", "configtest": test}
    return svc._mutate(name, action, timeout_s, approval_id)


# --------------------------------------------------------------- recovery
def _recovery_plan(publication: str, server_root: str) -> dict[str, Any]:
    installs, degraded = discover_apache()
    blocked = {"publication": None, "steps": [], "blocked": True}
    if degraded:
        return {**blocked, "notes": ["Windows service discovery failed; refusing to plan (fail closed)."]}
    if not installs:
        return {**blocked, "notes": ["No Apache found."]}
    install = _pick_apache(server_root)
    notes: list[str] = []
    test = _configtest(install)
    service = install["service"]
    pubs = _publication_list(install)
    by_name = [p for p in pubs if str(p["name"]).casefold() == publication.casefold()] if publication else pubs
    pub = by_name[0] if len(by_name) == 1 else None
    if not test["ok"]:
        notes.append("Apache configuration is invalid; automated recovery will not touch the service. "
                     "Fix httpd.conf (see configtest output) and re-run.")
        return {**blocked, "install": install["server_root"], "notes": notes, "configtest": test}
    if pub is None or pub.get("ambiguous"):
        notes.append("Publication is ambiguous or missing; pass publication=<name>.")
        return {**blocked, "install": install["server_root"], "notes": notes}
    steps: list[dict[str, Any]] = []
    new_bytes = None
    if pub.get("exists") and not pub.get("error") and not pub.get("odata", {}).get("enabled"):
        try:
            _check_vrd_path(Path(pub["vrd"]), [install["server_root"]])
        except PolicyError as exc:
            return {**blocked, "install": install["server_root"], "publication": pub["name"],
                    "notes": ["Publication descriptor refused by path policy: " + str(exc)]}
        prepared = _prepare_enable(install, pub)
        if prepared:
            step_plan, new_bytes, _diff = prepared
            steps.append({"step": "enable_standard_odata", **{k: step_plan[k] for k in
                          ("publication", "vrd", "old_sha256", "new_sha256")}})
    if service and service["state"] != "Running":
        steps.append({"step": "apache_start", "service": service["name"]})
    elif service:
        probe = odata_probe(pub["name"], "$metadata", timeout_s=8, server_root=server_root)
        verdict = _odata_verdict(probe)
        if verdict in ("UNREACHABLE", "SERVER_ERROR"):
            steps.append({"step": "apache_restart", "service": service["name"]})
        else:
            notes.append(f"OData probe verdict {verdict} (HTTP {probe.get('status')}); a restart cannot fix this")
    return {"install": install["server_root"], "publication": pub["name"], "steps": steps, "notes": notes,
            "blocked": False, "_new_bytes": new_bytes, "_install": install}


def _odata_verdict(probe: dict[str, Any]) -> str:
    """HEALTHY only for HTTP 2xx with valid OData metadata; auth/404/malformed are distinct, never healthy."""
    if not probe.get("reachable"):
        return "UNREACHABLE"
    status = int(probe.get("status") or 0)
    if status in (401, 403):
        return "AUTH_REQUIRED"
    if status == 404:
        return "PUBLICATION_NOT_FOUND"
    if status >= 500:
        return "SERVER_ERROR"
    meta = probe.get("metadata")
    if 200 <= status < 300 and isinstance(meta, dict) and "error" not in meta and meta.get("entity_sets", 0) >= 0             and "entity_types" in meta:
        return "HEALTHY"
    return "MALFORMED_OR_UNEXPECTED"


def odata_recovery(publication: str = "", apply: bool = False, approval_id: str | None = None,
                   server_root: str = "") -> dict[str, Any]:
    """Diagnose and (with approval) recover local OData: enable OData, start/restart Apache, re-probe.

    Default is a PLAN. apply=True needs one operator approval bound to the full step list INCLUDING the
    descriptor path and before/after hashes; every service step still obeys the service allowlist/denylist
    and re-runs `httpd -t` immediately before it. Execution stops at the first failing step.
    """
    plan = _recovery_plan(publication, server_root)
    new_bytes, install = plan.pop("_new_bytes", None), plan.pop("_install", None)
    bound = {"steps": plan["steps"], "publication": plan.get("publication")}
    if not apply or plan["blocked"] or not plan["steps"]:
        return {"status": "PLAN" if plan["steps"] else "NOTHING_TO_DO", "plan": plan,
                "plan_digest": digest_of("odata.recovery", bound)}
    pending = approval_or_response("odata.recovery", bound, approval_id, ELEVATED)
    if pending:
        return {**pending, "plan": plan}
    results, overall = [], "APPLIED"
    for step in plan["steps"]:
        try:
            if step["step"] == "enable_standard_odata":
                outcome = _apply_vrd_change(install, step | {"operation": "enable_standard_odata"}, new_bytes)
                ok = outcome["status"] == "APPLIED"
            else:
                if not _configtest(install)["ok"]:
                    outcome, ok = {"status": "REFUSED", "reason": "APACHE_CONFIG_INVALID_NOW"}, False
                else:
                    outcome = svc._mutate(step["service"], step["step"].split("_")[1], 60, None, pre_approved=True)
                    ok = bool(outcome.get("confirmed"))
        except (PolicyError, OSError) as exc:
            outcome, ok = {"status": "ERROR", "reason": str(exc)[:200]}, False
        results.append({"step": step["step"], "ok": ok, "result": outcome})
        if not ok:
            overall = "STOPPED_AT_FAILED_STEP"
            break
    final = odata_probe(plan["publication"], "$metadata", timeout_s=10, server_root=server_root)
    verdict = _odata_verdict(final)
    if overall == "APPLIED" and verdict != "HEALTHY":
        overall = "APPLIED_AUTH_REQUIRED_UNVERIFIED" if verdict == "AUTH_REQUIRED" else "APPLIED_BUT_ENDPOINT_NOT_HEALTHY:" + verdict
    audit("odata.recovery", overall, publication=plan["publication"], steps=len(results),
          final_status=final.get("status"), verdict=verdict)
    return {"status": overall, "results": results, "final_probe": final, "verdict": verdict}


def register_onec_tools(server: Any) -> None:
    server.tool(annotations=_RO)(threaded(onec_diagnostics))
    server.tool(annotations=_RO)(threaded(onec_connection_check))
    server.tool(annotations=_RO)(threaded(onec_publication_inspect))
    server.tool(annotations=_MUT)(threaded(onec_publication_repair))
    server.tool(annotations=_RO)(threaded(apache_diagnostics))
    server.tool(annotations=_MUT)(threaded(apache_service_control))
    server.tool(annotations=_NET)(threaded(odata_probe))
    server.tool(annotations=_MUT)(threaded(odata_recovery))
