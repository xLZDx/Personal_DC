from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[1]


async def _check_git_status() -> None:
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(ROOT / "run_server.py")],
        cwd=str(ROOT),
    )
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            started = time.monotonic()
            result = await session.call_tool(
                "project_git_status",
                {"project": str(ROOT)},
            )
            elapsed = time.monotonic() - started
            assert result.isError is not True
            assert elapsed < 5


def test_stdio_git_status_round_trip():
    asyncio.run(_check_git_status())
