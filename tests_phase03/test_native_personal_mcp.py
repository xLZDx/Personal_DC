"""Native v2 must expose actual Windows file/Git/test tools, not demo stubs."""
from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from dc_v2.native_personal_mcp import create_native_app
from personal_dc.server import mcp as windows_mcp


def test_native_app_uses_actual_windows_tool_server():
    tools = asyncio.run(windows_mcp.list_tools())
    names = {tool.name for tool in tools}
    assert {
        "health", "list_projects", "list_directory", "read_text_file",
        "write_text_file", "replace_text", "create_directory",
        "project_git_status", "project_git_diff", "git_create_branch",
        "git_stage_paths", "git_commit", "git_push", "run_project_tests",
    } <= names
    assert "demo_recorded_execution" not in names
    assert "execute_arbitrary_shell" not in names


def test_native_local_hop_does_not_disable_auth():
    app = create_native_app("f" * 64)
    async def verify():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 0)),
            base_url="http://127.0.0.1:18766",
            trust_env=False,
        ) as client:
            payload = {"jsonrpc":"2.0","id":1,"method":"ping"}
            response = await client.post("/mcp",json=payload)
            assert response.status_code == 401
            response = await client.post(
                "/mcp",
                headers={"X-PDC-V2-Demo-Auth":"bad"},
                json=payload,
            )
            assert response.status_code == 401
    asyncio.run(verify())


def test_wrong_local_hop_key_refused():
    with pytest.raises(ValueError):
        create_native_app("too-short")
