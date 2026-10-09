"""Strictly synthetic, non-executing customer-showcase contract tests."""
from __future__ import annotations
import asyncio
from dataclasses import replace
import httpx
import pytest
from dc_v2 import showcase_mcp as demo

def test_is_public_synthetic_and_not_production():
    health = demo.demo_health()
    assert health["ok"]
    assert health["execution_in_this_mcp"] is False
    assert health["live_workstation_access"] is False
    assert health["data_class"] == "PUBLIC_SYNTHETIC"
    assert health["production_release"] == "HOLD"

def test_demo_capabilities_do_not_claim_production_execution():
    x = demo.demo_capabilities()
    assert x["v2_model_facing_demo"] == "READ_ONLY_EVIDENCE"
    assert len(x["v2_not_yet_approved_for_production"]) >= 4

@pytest.mark.parametrize("profile", [
    "python", "node", "npm-build", "git",
    "no-inherited-secrets", "network-is-disabled"])
def test_recorded_evidence_is_explicitly_not_execution(profile):
    result = demo.demo_recorded_execution(profile)
    assert result["status"] == "RECORDED_EVIDENCE"
    assert result["verified_in_isolated_guest"] is True
    assert result["profile"] == profile
    assert "does not execute a command" in result["note"]

@pytest.mark.parametrize("input_value", [
    "../secrets", "powershell-host", "docker-socket", "git-push", ""])
def test_no_arbitrary_execution_profile(input_value):
    assert demo.demo_recorded_execution(input_value)["status"] == "DENIED"

@pytest.mark.parametrize("action", [
    "publish_changes", "external_network", "production_deploy"])
def test_boundary_never_approves(action):
    x = demo.demo_approval_example(action)
    assert x["status"] == "APPROVAL_REQUIRED"
    assert x["operator_approved"] is False
    assert x["effect_performed"] is False

def test_invalid_action_denied():
    assert demo.demo_approval_example("read_private_file")["status"] == "DENIED"

def test_short_key_refused():
    with pytest.raises(ValueError, match="MISSING_V2_LOCAL_HOP_SECRET"):
        demo.create_app("wrong")

@pytest.mark.parametrize("headers,status", [
    ({},401),
    ({"X-PDC-V2-Demo-Auth":"wrong"},401),
    ({"X-PDC-V2-Demo-Auth":"f"*64,"Origin":"https://untrusted.example"},403),
    ({"X-PDC-V2-Demo-Auth":"f"*64,"Host":"evil.example"},403),
])
def test_local_hop_requires_key_and_host(headers,status):
    token = "f"*64
    async def check():
        app = demo.create_app(token)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=("127.0.0.1",0)),
            base_url="http://127.0.0.1:18766", trust_env=False) as client:
            result = await client.post(
                "/mcp", headers=headers,
                json={"jsonrpc":"2.0","id":1,"method":"ping"})
            assert result.status_code == status
            assert "CONTROL_PLANE_API_KEY" not in result.text
    asyncio.run(check())

def test_nonlocal_client_denied():
    async def check():
        app = demo.create_app("f"*64)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=("10.1.2.3",0)),
            base_url="http://127.0.0.1:18766", trust_env=False) as client:
            result = await client.post("/mcp",
                headers={"X-PDC-V2-Demo-Auth":"f"*64},
                json={"jsonrpc":"2.0","id":1,"method":"ping"})
            assert result.status_code == 403
    asyncio.run(check())
