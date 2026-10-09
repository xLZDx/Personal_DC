"""1C:Enterprise / Apache / OData diagnostics and reversible, approval-gated repair.

Nothing here assumes an Apache path, 1C version, publication name or database:
everything is discovered from services, configured install roots and the
Apache configuration itself. Credentials are never returned or logged: connection
strings are redacted, OData credentials are read only from an operator-provisioned
DPAPI secret (``odata-<ref>``) and business records are never returned (only
metadata names and record counts).
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import secrets
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
from .common import (ELEVATED, approval_or_response, assert_no_reparse_chain, atomic_write_bytes,
                     atomic_write_json, audit, canonical, digest_of, iso, load_secret, native_config, new_id,
                     read_json, redact_text, sha256_text, state_subdir, valid_id)
from .sysrun import ps_json, run_capture

_RO = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
_NET = ToolAnnotations(readOnlyHint=True, openWorldHint=True)
_MUT = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False)

MAX_CONF_BYTES = 2 * 1024 * 1024
MAX_VRD_BYTES = 512 * 1024
_PUB_NAME = re.compile(r"^[\w.-]{1,100}$", re.UNICODE)
_HTTPD_RE = re.compile(r'"?([A-Za-z]:\\[^"\r\n]*?httpd\.exe)"?', re.IGNORECASE)


# ------------------------------------------------------------------ helpers
def _under(path: Path, roots: list[str]) -> bool:
    for root in roots:
        try:
            if os.path.commonpath([str(path), str(Path(root).resolve(strict=False))]).casefold() == \
                    str(Path(root).resolve(strict=False)).casefold():
                return True
        except ValueError:
            continue
    return False


def _read_limited(path: Path, limit_bytes: int) -> bytes:
    if path.stat().st_size > limit_bytes:
        raise PolicyError("FILE_TOO_LARGE")
    return path.read_bytes()


def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse_xml_safe(data: bytes) -> ET.Element:
    head = data[:4096].upper()
    if b"<!DOCTYPE" in head or b"<!ENTITY" in data.upper():
        raise PolicyError("XML_DTD_NOT_ALLOWED")
    try:
        return ET.fromstring(data)
    except ET.ParseError as exc:
        raise PolicyError("XML_INVALID") from exc


def _redact_conn(conn: str) -> str:
    return re.sub(r'(?i)(usr|pwd|user|password)\s*=\s*("[^"]*"|[^;]*)', lambda m: m.group(1) + "=***", conn)


def _parse_ib(conn: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for key in ("File", "Srvr", "Ref", "Ws"):
        match = re.search(rf'(?i)\b{key}\s*=\s*"([^"]*)"|\b{key}\s*=\s*([^;]*)', conn)
        if match:
            out[key.lower()] = (match.group(1) if match.group(1) is not None else match.group(2)).strip()
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
    for root in native_config()["onec_roots"]:
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


def _infobases() -> list[dict[str, str]]:
    appdata = os.environ.get("APPDATA")
    if not appdata:
        return []
    path = Path(appdata) / "1C" / "1CEStart" / "ibases.v8i"
    if not path.is_file():
        return []
    try:
        text = _read_limited(path, 1024 * 1024).decode("utf-8-sig", errors="replace")
    except (OSError, PolicyError):
        return []
    out, name = [], None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1]
        elif line.lower().startswith("connect=") and name:
            conn = _parse_ib(line[8:])
            kind = "file" if "file" in conn else "server" if "srvr" in conn else "web" if "ws" in conn else "other"
            out.append({"name": name, "kind": kind})
    return out[:100]


# --------------------------------------------------------- discovery: Apache
def discover_apache() -> list[dict[str, Any]]:
    cfg = native_config()
    installs: dict[str, dict[str, Any]] = {}
    script = r"""
Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'httpd\.exe' } |
  Select-Object Name, State, StartMode, PathName | ConvertTo-Json -Compress -Depth 2
"""
    try:
        rows = ps_json(script, timeout=45) or []
    except PolicyError:
        rows = []
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
    return result


def _pick_apache(server_root: str = "") -> dict[str, Any]:
    installs = discover_apache()
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


def _collect_conf(install: dict[str, Any]) -> dict[str, Any]:
    """Parse httpd.conf (+Include tree, bounded) into the directives that matter for 1C publishing."""
    server_root = Path(install["server_root"])
    pending = [Path(install["conf"])]
    seen: set[str] = set()
    out: dict[str, Any] = {"files": [], "listen": [], "modules": {}, "publications": [], "errors": []}
    aliases: dict[str, str] = {}
    while pending and len(seen) < 50:
        path = pending.pop(0)
        key = str(path).casefold()
        if key in seen:
            continue
        seen.add(key)
        try:
            if not _under(path, [str(server_root)] + native_config()["apache_roots"] + [str(path.parent)]):
                continue
            text = _read_limited(path, MAX_CONF_BYTES).decode("utf-8", errors="replace")
        except (OSError, PolicyError) as exc:
            out["errors"].append({"file": str(path), "error": type(exc).__name__})
            continue
        out["files"].append(str(path))
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            low = line.casefold()
            if low.startswith("listen "):
                out["listen"].append(line.split(None, 1)[1].strip())
            elif low.startswith("loadmodule "):
                parts = re.match(r'(?i)loadmodule\s+(\S+)\s+"?([^"\r\n]+?)"?\s*$', line)
                if parts:
                    out["modules"][parts.group(1)] = parts.group(2).replace("/", "\\")
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
    return pubs


def _configtest(install: dict[str, Any]) -> dict[str, Any]:
    if not install["exe_exists"] or not install["conf_exists"]:
        return {"ok": False, "reason": "HTTPD_OR_CONF_MISSING"}
    result = run_capture([install["httpd_exe"], "-t", "-f", install["conf"], "-d", install["server_root"]],
                         timeout=25)
    text = redact_text((result["stderr"] + result["stdout"]).strip())[:1500]
    return {"ok": result["exit_code"] == 0 and "syntax ok" in text.casefold(), "exit_code": result["exit_code"],
            "output": text, "timed_out": result["timed_out"]}


def _finding(fid: str, severity: str, message: str, **evidence: Any) -> dict[str, Any]:
    return {"id": fid, "severity": severity, "message": message, "evidence": evidence}


# -------------------------------------------------------------- MCP tools
def apache_diagnostics(server_root: str = "") -> dict[str, Any]:
    """Discover Apache, test its configuration, list 1C publications and flag common misconfigurations."""
    installs = discover_apache()
    report: dict[str, Any] = {"installs": [], "findings": []}
    if not installs:
        report["findings"].append(_finding("APACHE_NOT_FOUND", "high", "No Apache httpd service or install found"))
        return report
    for install in installs:
        if server_root and str(Path(install["server_root"])).casefold() != str(Path(server_root)).casefold():
            continue
        entry = dict(install)
        entry["configtest"] = _configtest(install)
        conf = _collect_conf(install) if install["conf_exists"] else {"errors": ["CONF_MISSING"], "listen": [],
                                                                     "modules": {}, "publications": [], "files": []}
        entry["listen"], entry["conf_files"] = conf["listen"], conf["files"]
        module_1c = {k: v for k, v in conf["modules"].items() if "1c" in k.casefold() or "wsap" in v.casefold()}
        entry["onec_modules"] = {k: {"path": v, "exists": Path(v).is_file()} for k, v in module_1c.items()}
        entry["publications"] = _publication_list(install) if install["conf_exists"] else []
        findings = report["findings"]
        tag = install["server_root"]
        if install["service"] and install["service"]["state"] != "Running":
            findings.append(_finding("APACHE_SERVICE_NOT_RUNNING", "high", "Apache service is not running",
                                     service=install["service"]["name"], state=install["service"]["state"], root=tag))
        if not entry["configtest"]["ok"]:
            findings.append(_finding("APACHE_CONFIG_INVALID", "high", "httpd -t did not report Syntax OK",
                                     output=entry["configtest"].get("output"), root=tag))
        if not module_1c:
            findings.append(_finding("ONEC_MODULE_NOT_LOADED", "high",
                                     "No 1C web extension LoadModule (wsap*.dll) in Apache config", root=tag))
        for key, mod in entry["onec_modules"].items():
            if not mod["exists"]:
                findings.append(_finding("ONEC_MODULE_FILE_MISSING", "high",
                                         "LoadModule points to a missing file (platform moved/removed?)",
                                         module=key, path=mod["path"]))
        if not entry["publications"]:
            findings.append(_finding("NO_1C_PUBLICATION", "medium",
                                     "No ManagedApplicationDescriptor found", root=tag))
        for pub in entry["publications"]:
            findings.extend(_publication_findings(pub))
        for listen in conf["listen"][:5]:
            port_text = listen.rsplit(":", 1)[-1].split()[0]
            if port_text.isdigit() and install["service"] and install["service"]["state"] == "Running":
                check = _tcp_check("127.0.0.1", int(port_text), 2.0)
                if check.get("checked") and not check.get("open"):
                    findings.append(_finding("LISTEN_PORT_NOT_ACCEPTING", "high",
                                             "Apache is Running but the Listen port does not accept connections",
                                             port=int(port_text)))
        report["installs"].append(entry)
    audit("onec.apache_diagnostics", "OK", installs=len(report["installs"]), findings=len(report["findings"]))
    return report


def _publication_findings(pub: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    name = pub.get("name")
    if not pub.get("exists"):
        return [_finding("VRD_MISSING", "high", "Publication descriptor file does not exist", publication=name,
                         vrd=pub.get("vrd"))]
    if pub.get("error"):
        return [_finding("VRD_INVALID", "high", "Publication descriptor cannot be parsed", publication=name,
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
    infobases = _infobases()
    apache = apache_diagnostics()
    findings = list(apache["findings"])
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
    audit("onec.connection_check", "OK", count=len(results))
    return {"checks": results}


# ------------------------------------------------------------------ OData
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:  # noqa: D401
        return None


def _odata_url(publication: str, url: str, path: str, server_root: str) -> str:
    cfg_hosts = _allowed_hosts()
    if url:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.hostname.casefold() not in cfg_hosts:
            raise PolicyError("ODATA_HOST_NOT_ALLOWED")
        base = url.split("?", 1)[0].rstrip("/")
    else:
        if not _PUB_NAME.fullmatch(publication or ""):
            raise PolicyError("PUBLICATION_REQUIRED")
        install = _pick_apache(server_root)
        port = "80"
        for listen in _collect_conf(install)["listen"]:
            last = listen.rsplit(":", 1)[-1].split()[0]
            if last.isdigit():
                port = last
                break
        base = f"http://127.0.0.1:{port}/{urllib.parse.quote(publication)}/odata/standard.odata"
    if path:
        if not re.fullmatch(r"[\w$./()=?&',%-]{1,300}", path, re.UNICODE) or ".." in path:
            raise PolicyError("ODATA_PATH_INVALID")
        full = base + "/" + path.lstrip("/")
        if "?" not in path and path != "$metadata":
            full += "?$top=1&$format=json"
        elif "?" in path and "$top" not in path and "$metadata" not in path:
            full += "&$top=1"
        return full
    return base + "/"


def odata_probe(publication: str = "", path: str = "$metadata", url: str = "", credential_ref: str = "",
                timeout_s: int = 10, server_root: str = "") -> dict[str, Any]:
    """GET-probe a local 1C OData endpoint. Returns status/timing and metadata names or record COUNT only.

    Credentials are never accepted as arguments: use an operator-provisioned `credential_ref`
    (DPAPI secret odata-<ref> containing user:password). Hosts are restricted to loopback/allowlist.
    """
    target = _odata_url(publication, url, path, server_root)
    headers = {"Accept": "application/xml, application/json", "User-Agent": "PersonalDC-odata-probe/2"}
    if credential_ref:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", credential_ref):
            raise PolicyError("INVALID_CREDENTIAL_REF")
        blob = load_secret("odata-" + credential_ref)
        if not blob:
            raise PolicyError("CREDENTIAL_REF_NOT_PROVISIONED")
        import base64
        headers["Authorization"] = "Basic " + base64.b64encode(blob).decode("ascii")
    opener = urllib.request.build_opener(_NoRedirect)
    started = time.monotonic()
    result: dict[str, Any] = {"url": redact_text(target), "credential_ref": credential_ref or None}
    try:
        with opener.open(urllib.request.Request(target, headers=headers, method="GET"),
                         timeout=max(2, min(int(timeout_s), 30))) as resp:
            status, hdrs, body = resp.status, resp.headers, resp.read(4 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as exc:
        status, hdrs = exc.code, exc.headers
        body = exc.read(2048)
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
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
            if len(body) > 4 * 1024 * 1024:
                result["metadata"] = {"error": "TOO_LARGE"}
            else:
                try:
                    root = _parse_xml_safe(body)
                    sets = [e.attrib.get("Name") for e in root.iter() if _strip_ns(e.tag) == "EntitySet"]
                    types = sum(1 for e in root.iter() if _strip_ns(e.tag) == "EntityType")
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
    else:
        result["error_excerpt"] = redact_text(body[:300].decode("utf-8", errors="replace"))
    audit("odata.probe", "OK" if 200 <= status < 300 else "HTTP_" + str(status), url=result["url"])
    return result


# ------------------------------------------------------- repair (reversible)
_VRD_SUFFIX = ".vrd"


def _locate_vrd(publication: str, server_root: str) -> tuple[dict[str, Any], dict[str, Any]]:
    install = _pick_apache(server_root)
    for pub in _publication_list(install):
        if str(pub.get("name", "")).casefold() == publication.casefold():
            vrd = Path(pub["vrd"])
            if vrd.suffix.casefold() != _VRD_SUFFIX or not vrd.is_file():
                raise PolicyError("VRD_NOT_FOUND")
            assert_no_reparse_chain(vrd.resolve(strict=True), [Path(vrd.anchor)])
            return install, pub
    raise PolicyError("PUBLICATION_NOT_FOUND")


def _enable_odata_text(text: str) -> str:
    def fix(match: re.Match[str]) -> str:
        tag = match.group(0)
        if re.search(r'\benable\s*=\s*"', tag):
            return re.sub(r'(\benable\s*=\s*")[^"]*(")', r"\1true\2", tag)
        return tag.replace("<standardOdata", '<standardOdata enable="true"', 1)

    if re.search(r"<(?:\w+:)?standardOdata\b", text):
        return re.sub(r"<(?:\w+:)?standardOdata\b[^>]*>", fix, text, count=1)
    if "</point>" not in text:
        raise PolicyError("VRD_STRUCTURE_UNSUPPORTED")
    newline = "\r\n" if "\r\n" in text else "\n"
    snippet = ('\t<standardOdata enable="true" reuseSessions="autouse" sessionMaxAge="20" '
               'poolSize="10" poolTimeout="5"/>' + newline)
    return text.replace("</point>", snippet + "</point>", 1)


def _backup_vrd(vrd: Path, operation: str) -> dict[str, Any]:
    bid = new_id("bak")
    folder = state_subdir("backups") / bid
    folder.mkdir(parents=True)
    copy = folder / vrd.name
    shutil.copy2(vrd, copy)
    manifest = {"id": bid, "operation": operation, "original": str(vrd), "backup": str(copy),
                "sha256": hashlib.sha256(copy.read_bytes()).hexdigest(), "created_at": iso()}
    atomic_write_json(folder / "manifest.json", manifest)
    return manifest


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
    vrd = Path(pub["vrd"])
    old = _read_limited(vrd, MAX_VRD_BYTES)
    text = old.decode("utf-8-sig" if old.startswith(b"\xef\xbb\xbf") else "utf-8")
    new_text = _enable_odata_text(text)
    if new_text == text:
        return {"status": "NO_CHANGE_NEEDED", "publication": publication}
    _parse_xml_safe(new_text.encode("utf-8"))
    bom = b"\xef\xbb\xbf" if old.startswith(b"\xef\xbb\xbf") else b""
    new_bytes = bom + new_text.encode("utf-8")
    plan = {"operation": operation, "publication": publication, "vrd": str(vrd),
            "old_sha256": hashlib.sha256(old).hexdigest(), "new_sha256": hashlib.sha256(new_bytes).hexdigest()}
    diff = [redact_text(line.rstrip("\n")) for line in difflib.unified_diff(
        text.splitlines(True), new_text.splitlines(True), "current", "proposed", n=1)][:60]
    if not apply:
        return {"status": "PLAN", "plan": plan, "plan_digest": digest_of("onec.repair", plan), "diff": diff,
                "reversible": True, "next": "repeat with apply=true (an operator approval will be requested)"}
    pending = approval_or_response("onec.repair", plan, approval_id, ELEVATED)
    if pending:
        return {**pending, "plan": plan, "diff": diff}
    if hashlib.sha256(vrd.read_bytes()).hexdigest() != plan["old_sha256"]:
        raise PolicyError("PUBLICATION_CHANGED_SINCE_PLAN")
    manifest = _backup_vrd(vrd, operation)
    audit("onec.repair", "APPLYING", publication=publication, backup_id=manifest["id"], **{
        k: plan[k] for k in ("old_sha256", "new_sha256")})
    try:
        atomic_write_bytes(vrd, new_bytes)
        _parse_xml_safe(vrd.read_bytes())
        check = _configtest(install)
        if not check["ok"] and install["conf_exists"]:
            raise PolicyError("POST_CHECK_FAILED_CONFIGTEST")
    except (OSError, PolicyError) as exc:
        shutil.copy2(manifest["backup"], vrd)
        audit("onec.repair", "ROLLED_BACK", backup_id=manifest["id"], reason=type(exc).__name__)
        return {"status": "FAILED_ROLLED_BACK", "reason": str(exc)[:200], "backup_id": manifest["id"]}
    audit("onec.repair", "APPLIED", publication=publication, backup_id=manifest["id"])
    return {"status": "APPLIED", "publication": publication, "backup_id": manifest["id"],
            "new_sha256": plan["new_sha256"], "rollback": {"operation": "rollback", "backup_id": manifest["id"]},
            "next": "run odata_probe / odata_recovery to verify; restart Apache only if required"}


def _rollback_vrd(backup_id: str, apply: bool, approval_id: str | None) -> dict[str, Any]:
    if not valid_id(backup_id) or not backup_id.startswith("bak-"):
        raise PolicyError("INVALID_BACKUP_ID")
    manifest = read_json(state_subdir("backups") / backup_id / "manifest.json")
    if not manifest:
        raise PolicyError("BACKUP_NOT_FOUND")
    backup, original = Path(manifest["backup"]), Path(manifest["original"])
    if hashlib.sha256(backup.read_bytes()).hexdigest() != manifest["sha256"]:
        raise PolicyError("BACKUP_INTEGRITY_FAILED")
    plan = {"operation": "rollback", "backup_id": backup_id, "target": str(original), "sha256": manifest["sha256"]}
    if not apply:
        return {"status": "PLAN", "plan": plan}
    pending = approval_or_response("onec.repair", plan, approval_id, ELEVATED)
    if pending:
        return pending
    atomic_write_bytes(original, backup.read_bytes())
    audit("onec.repair", "ROLLBACK_APPLIED", backup_id=backup_id)
    return {"status": "ROLLED_BACK", "target": str(original)}


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
    install = _pick_apache(server_root)
    steps: list[dict[str, Any]] = []
    notes: list[str] = []
    test = _configtest(install)
    service = install["service"]
    pubs = {p["name"]: p for p in _publication_list(install)}
    pub = pubs.get(publication) if publication else (next(iter(pubs.values())) if len(pubs) == 1 else None)
    if not test["ok"]:
        notes.append("Apache configuration is invalid; automated recovery will not touch the service. "
                     "Fix httpd.conf (see configtest output) and re-run.")
        return {"install": install["server_root"], "publication": pub and pub.get("name"), "steps": [],
                "notes": notes, "configtest": test, "blocked": True}
    if pub is None:
        notes.append("Publication is ambiguous or missing; pass publication=<name>.")
        return {"install": install["server_root"], "steps": [], "notes": notes, "blocked": True}
    if pub.get("exists") and not pub.get("odata", {}).get("enabled"):
        steps.append({"step": "enable_standard_odata", "publication": pub["name"]})
    if service and service["state"] != "Running":
        steps.append({"step": "apache_start", "service": service["name"]})
    elif service:
        probe = odata_probe(pub["name"], "$metadata", timeout_s=8, server_root=server_root)
        if not probe.get("reachable") or probe.get("status", 200) >= 500:
            steps.append({"step": "apache_restart", "service": service["name"]})
        else:
            notes.append(f"OData probe status {probe.get('status')}")
    return {"install": install["server_root"], "publication": pub["name"], "steps": steps, "notes": notes,
            "blocked": False}


def odata_recovery(publication: str = "", apply: bool = False, approval_id: str | None = None,
                   server_root: str = "") -> dict[str, Any]:
    """Diagnose and (with approval) recover local OData: enable OData, start/restart Apache, re-probe.

    Default is a PLAN. apply=True needs one operator approval bound to the full step list; each service
    step still obeys the service allowlist/denylist. Unfixable causes are reported, not guessed at.
    """
    plan = _recovery_plan(publication, server_root)
    if not apply or plan["blocked"] or not plan["steps"]:
        return {"status": "PLAN" if plan["steps"] else "NOTHING_TO_DO", "plan": plan,
                "plan_digest": digest_of("odata.recovery", {"steps": plan["steps"], "publication": plan["publication"]})}
    bound = {"steps": plan["steps"], "publication": plan["publication"]}
    pending = approval_or_response("odata.recovery", bound, approval_id, ELEVATED)
    if pending:
        return {**pending, "plan": plan}
    results = []
    for step in plan["steps"]:
        if step["step"] == "enable_standard_odata":
            current = onec_publication_repair(step["publication"], "enable_standard_odata", apply=False,
                                              server_root=server_root)
            if current.get("status") == "PLAN":
                inner = current["plan"]
                outcome = _apply_repair_preapproved(inner, server_root)
            else:
                outcome = current
        elif step["step"] in ("apache_start", "apache_restart"):
            outcome = svc._mutate(step["service"], step["step"].split("_")[1], 60, None, pre_approved=True)
        else:
            outcome = {"status": "UNKNOWN_STEP"}
        results.append({"step": step["step"], "result": outcome})
    final = odata_probe(plan["publication"], "$metadata", timeout_s=10, server_root=server_root)
    audit("odata.recovery", "DONE", publication=plan["publication"], steps=len(results),
          final_status=final.get("status"))
    return {"status": "APPLIED", "results": results, "final_probe": final}


def _apply_repair_preapproved(plan: dict[str, Any], server_root: str) -> dict[str, Any]:
    """Apply an already-approved enable_standard_odata plan (approval bound at the recovery level)."""
    install, pub = _locate_vrd(plan["publication"], server_root)
    vrd = Path(pub["vrd"])
    old = _read_limited(vrd, MAX_VRD_BYTES)
    if hashlib.sha256(old).hexdigest() != plan["old_sha256"]:
        raise PolicyError("PUBLICATION_CHANGED_SINCE_PLAN")
    text = old.decode("utf-8-sig" if old.startswith(b"\xef\xbb\xbf") else "utf-8")
    bom = b"\xef\xbb\xbf" if old.startswith(b"\xef\xbb\xbf") else b""
    new_bytes = bom + _enable_odata_text(text).encode("utf-8")
    manifest = _backup_vrd(vrd, "enable_standard_odata")
    try:
        atomic_write_bytes(vrd, new_bytes)
        _parse_xml_safe(vrd.read_bytes())
        if install["conf_exists"] and not _configtest(install)["ok"]:
            raise PolicyError("POST_CHECK_FAILED_CONFIGTEST")
    except (OSError, PolicyError) as exc:
        shutil.copy2(manifest["backup"], vrd)
        audit("onec.repair", "ROLLED_BACK", backup_id=manifest["id"], reason=type(exc).__name__)
        return {"status": "FAILED_ROLLED_BACK", "reason": str(exc)[:200], "backup_id": manifest["id"]}
    audit("onec.repair", "APPLIED", publication=plan["publication"], backup_id=manifest["id"])
    return {"status": "APPLIED", "backup_id": manifest["id"]}


def register_onec_tools(server: Any) -> None:
    server.tool(annotations=_RO)(onec_diagnostics)
    server.tool(annotations=_RO)(onec_connection_check)
    server.tool(annotations=_RO)(onec_publication_inspect)
    server.tool(annotations=_MUT)(onec_publication_repair)
    server.tool(annotations=_RO)(apache_diagnostics)
    server.tool(annotations=_MUT)(apache_service_control)
    server.tool(annotations=_NET)(odata_probe)
    server.tool(annotations=_MUT)(odata_recovery)
