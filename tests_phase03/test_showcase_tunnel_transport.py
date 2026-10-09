"""Real official MCP SDK through the tunnel-facing guard with proxy headers.

Synthetic fixtures only; listener binds an OS-assigned loopback port and is
closed before returning. This is NOT a production control-plane probe.
"""
from __future__ import annotations

import asyncio
import secrets
import socket
import threading
import time

import httpx
import pytest

from dc_v2.showcase_mcp import create_app


def test_real_mcp_client_with_forwarded_metadata():
    uvicorn = pytest.importorskip("uvicorn")
    pytest.importorskip("mcp")
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    token = secrets.token_hex(32)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    url = f"http://127.0.0.1:{port}/mcp"
    app = create_app(token)
    server = uvicorn.Server(uvicorn.Config(
        app, host="127.0.0.1", port=port, access_log=False,
        proxy_headers=False, log_level="critical", ws="none"))
    thread = threading.Thread(
        target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()

    try:
        deadline = time.monotonic() + 10
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert server.started, "test listener not ready"

        async def remote_tunnel_client():
            async with httpx.AsyncClient(
                trust_env=False, timeout=10,
                headers={
                    "X-PDC-V2-Demo-Auth": token,
                    "Host": "remote-control-plane.example",
                    "Origin": "https://chatgpt.com",
                    "X-Forwarded-Host": "api.openai.com",
                    "X-Forwarded-Proto": "https",
                },
            ) as client:
                async with streamable_http_client(
                    url, http_client=client, terminate_on_close=False
                ) as (reader, writer, _):
                    async with ClientSession(reader, writer) as session:
                        info = await session.initialize()
                        assert "Customer Showcase" in info.serverInfo.name
                        tools = await session.list_tools()
                        names = {tool.name for tool in tools.tools}
                        assert names == {
                            "demo_health", "demo_capabilities",
                            "demo_recorded_execution", "demo_security_model",
                            "demo_architecture", "demo_approval_example",
                        }
                        health = await session.call_tool("demo_health", {})
                        assert health.structuredContent["production_release"] == "HOLD"

        asyncio.run(asyncio.wait_for(remote_tunnel_client(), timeout=25))
    finally:
        server.should_exit = True
        thread.join(timeout=8)
        sock.close()
    assert not thread.is_alive(), "test listener did not terminate"
