from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[1]


async def _smoke() -> None:
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(ROOT / "run_server.py")],
        cwd=str(ROOT),
    )
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = {tool.name for tool in tools.tools}
            assert "health" in names
            assert "read_text_file" in names
            assert "replace_text" in names
            assert "git_stage_paths" in names
            assert "git_push" in names
            assert not any("delete" in name.casefold() for name in names)

            result = await session.call_tool("health", {})
            assert result.isError is not True


def test_stdio_mcp_round_trip():
    asyncio.run(_smoke())
