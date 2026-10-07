from __future__ import annotations

import asyncio
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


async def main():
    async with streamablehttp_client("http://127.0.0.1:18765/mcp") as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = await s.list_tools()
            print("TOOLS", [t.name for t in tools.tools])
            result = await s.call_tool("health", {})
            print("HEALTH", result)


asyncio.run(main())
