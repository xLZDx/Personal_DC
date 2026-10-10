"""Single registration point for every native Windows operations tool."""
from __future__ import annotations

import os
from typing import Any

from mcp.types import ToolAnnotations

from . import common
from .common import redact, redact_text, threaded
from .command_tools import register_command_tools
from .deploy_tools import register_deploy_tools
from .onec_tools import register_onec_tools
from .process_tools import register_process_tools
from .service_tools import register_service_tools

_RO = ToolAnnotations(readOnlyHint=True, openWorldHint=False)

TOOL_NAMES = (
    "command_execute", "command_start", "command_status", "command_output", "command_cancel", "command_history",
    "process_list", "process_inspect", "process_start", "process_status", "process_output", "process_stop",
    "service_list", "service_inspect", "service_start", "service_stop", "service_restart", "service_wait",
    "onec_diagnostics", "onec_connection_check", "onec_publication_inspect", "onec_publication_repair",
    "apache_diagnostics", "apache_service_control", "odata_probe", "odata_recovery",
    "software_inspect", "installer_verify", "deployment_plan", "deployment_apply", "deployment_status",
    "deployment_rollback", "native_security_status", "native_audit_tail",
)


def native_security_status() -> dict[str, Any]:
    """Report trust modes, approval-key provisioning, audit-chain integrity and configured allowlists."""
    cfg = common.native_config()
    return {
        "trust_modes": list(common.MODES),
        "approval_key_provisioned": common.secret_path("approval-key").is_file(),
        "audit": common.audit_verify(),
        "service_allowlist": [redact_text(str(e.get("name"))) for e in cfg["service_allowlist"]
                              if isinstance(e, dict)],
        "dev_executables": [redact_text(str(x)) for x in cfg["dev_executables"]],
        "approval_authority_isolated": False,
        "trusted_publishers_configured": bool(cfg["trusted_publishers"] or cfg["trusted_thumbprints"]),
        "elevated_server_process": _is_admin(),
        "note": ("MCP front door is NOT user authorization; elevated actions require an operator approval "
                 "granted out-of-band (python -m dc_v2.winops.approve). The approval key is held by the same "
                 "Windows user as this server, so approval is a deliberate-intent control, not a privilege boundary."),
    }


def native_audit_tail(limit: int = 50) -> list[dict[str, Any]]:
    """Recent hash-chained native audit events (secrets redacted at write time)."""
    return redact(common.audit_tail(max(1, min(int(limit), 500))))


def _is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def register_all(server: Any) -> None:
    if os.name != "nt":
        raise SystemExit("WINDOWS_ONLY_NATIVE_PROFILE")
    register_command_tools(server)
    register_process_tools(server)
    register_service_tools(server)
    register_onec_tools(server)
    register_deploy_tools(server)
    server.tool(annotations=_RO)(threaded(native_security_status))
    server.tool(annotations=_RO)(threaded(native_audit_tail))
