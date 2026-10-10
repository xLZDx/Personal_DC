"""Negative-auth and positive-MCP integration test of the separate v2 demo."""
from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

URL = "http://127.0.0.1:18766/mcp"
KEY = os.environ.get("PDC_V2_BACKEND_KEY", "")
OUT = Path(os.environ.get("LOCALAPPDATA", "")) / "Personal_DC_V2" / "run" / "local-probe.json"

async def verify():
    results = {}
    async with httpx.AsyncClient(timeout=9, trust_env=False) as client:
        data = {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "local-showcase-test", "version": "1.0"}},
        }
        headers = {"Accept": "application/json, text/event-stream"}
        result = await client.post(URL, headers=headers, json=data)
        results["unauthenticated_denied"] = result.status_code == 401
        result = await client.post(URL, headers={**headers, "X-PDC-V2-Demo-Auth": "wrong"}, json=data)
        results["invalid_key_denied"] = result.status_code == 401
        result = await client.post(URL, headers={**headers,
                                                "Origin": "https://untrusted.example"}, json=data)
        results["origin_without_key_denied"] = result.status_code == 401
        # A private OpenAI Tunnel can forward browser-origin and proxy headers.
        # With the right local-hop credential the guard strips these metadata
        # before FastMCP receives them; the MCP is still synthetic/read-only.
        result = await client.post(URL, headers={**headers, "X-PDC-V2-Demo-Auth": KEY,
                                                "Host": "remote-control-plane.example",
                                                "Origin": "https://chatgpt.com",
                                                "X-Forwarded-Host": "api.openai.com"}, json=data)
        results["tunnel_metadata_with_key_accepted"] = (
            result.status_code == 200 and
            "Personal DC 2.2" in str(result.json().get("result", {}))
        )
    async with httpx.AsyncClient(timeout=9, trust_env=False,
                                headers={"X-PDC-V2-Demo-Auth": KEY}) as client:
        async with streamable_http_client(URL, http_client=client,
                                          terminate_on_close=False) as (read, write, _):
            async with ClientSession(read, write) as session:
                info = await session.initialize()
                results["mcp_initialized"] = "Personal DC 2.2" in info.serverInfo.name
                listing = await session.list_tools()
                names = {x.name for x in listing.tools}
                needed = {"demo_health", "demo_capabilities", "demo_recorded_execution",
                          "demo_security_model", "demo_architecture", "demo_approval_example"}
                results["exact_read_only_catalog"] = names == needed and all(
                    x.annotations and x.annotations.readOnlyHint for x in listing.tools)
                health = await session.call_tool("demo_health", {})
                results["synthetic_only"] = bool(
                    health.structuredContent.get("data_class") == "PUBLIC_SYNTHETIC" and
                    health.structuredContent.get("execution_in_this_mcp") is False)
                for test in ("python", "node", "npm-build", "git"):
                    evidence = await session.call_tool("demo_recorded_execution", {"profile": test})
                    results["captured_" + test] = bool(
                        evidence.structuredContent.get("status") == "RECORDED_EVIDENCE" and
                        evidence.structuredContent.get("verified_in_isolated_guest") is True)
                denied = await session.call_tool("demo_recorded_execution",
                                                {"profile": "powershell-host"})
                results["unknown_profile_denied"] = denied.structuredContent.get("status") == "DENIED"
                approval = await session.call_tool("demo_approval_example",
                                                  {"action": "production_deploy"})
                results["approval_not_granted"] = bool(
                    approval.structuredContent.get("status") == "APPROVAL_REQUIRED" and
                    approval.structuredContent.get("effect_performed") is False)
    return results

def main():
    if len(KEY) != 64:
        raise SystemExit("LOCAL_KEY_NOT_AVAILABLE")
    report = {"schema": "personal-dc.v2.local-probe.v1",
              "checked_utc": datetime.now(timezone.utc).isoformat(), "checks": {}}
    try:
        report["checks"] = asyncio.run(verify())
        report["status"] = "PASS" if all(report["checks"].values()) else "FAIL"
    except Exception as exc:
        report["status"] = "ERROR"
        report["error_type"] = type(exc).__name__
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("V2_LOCAL_PROBE_" + report["status"])
    print("CHECKS", len(report["checks"]), sum(report["checks"].values()))
    raise SystemExit(0 if report["status"] == "PASS" else 1)

if __name__ == "__main__":
    main()
