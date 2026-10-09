"""Native Personal DC v2 entrypoint for the owner's Windows workstation.

Restores the already-tested v1 Windows file/Git/test tools behind v2's
independent local-hop authenticated tunnel. Not the Docker executor. This
entrypoint intentionally does NOT expose generic host shell, arbitrary
PowerShell, delete, service control, or tunnel key manipulation.

The model-facing tools still use personal_dc.policy.Policy allowlisted roots.
See deployment limitations: current-user process identity is not a secure
OS sandbox; owner should not expose this to untrusted clients.
"""
from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP
from personal_dc.server import mcp as native_tools

from .showcase_mcp import LocalHopGuard
from .windows_native_tools import register_native_tools
from .binary_transfer import register_binary_tools

# Registered only in the separate v2 process, never in legacy v1.
register_native_tools(native_tools)
register_binary_tools(native_tools)


def create_native_app(secret: str) -> LocalHopGuard:
    # Use the same independently provisioned v2 loopback key guard.
    # The underlying MCP instance exposes the v1 file/Git/test operations
    # as real Windows-backed calls, not simulated demo recordings.
    return LocalHopGuard(native_tools.streamable_http_app(), secret)


def main() -> None:
    import uvicorn

    if os.name != "nt":
        raise SystemExit("WINDOWS_ONLY_NATIVE_PROFILE")
    secret = os.environ.get("PDC_V2_BACKEND_KEY", "")
    if len(secret) != 64:
        raise SystemExit("V2_LOCAL_HOP_CREDENTIAL_REQUIRED")
    # No inherited control-plane credentials should reach this backend.
    os.environ.pop("CONTROL_PLANE_API_KEY", None)
    os.environ.pop("OPENAI_ADMIN_KEY", None)
    # v2 is independently versioned; v1 keeps its original 0.1.0 identity.
    os.environ["PERSONAL_DC_PRODUCT_VERSION"] = "2.0.0"
    # Old FastMCP instance is instantiated with v1's configured port.
    # HTTP app itself is served on v2's independent loopback port.
    app = create_native_app(secret)
    uvicorn.run(
        app, host="127.0.0.1", port=18766,
        access_log=False, log_level="warning", proxy_headers=False,
        timeout_keep_alive=5, limit_concurrency=12,
    )


if __name__ == "__main__":
    main()
