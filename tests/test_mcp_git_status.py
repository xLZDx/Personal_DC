from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import time
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[1]


async def _check_git_status() -> None:
    with tempfile.TemporaryDirectory(prefix="personal-dc-test-") as tmp:
        home = Path(tmp)
        config = home / "config"
        config.mkdir(parents=True)

        (config / "policy.json").write_text(
            json.dumps(
                {
                    "allowed_roots": [str(ROOT)],
                    "protected_components": [".git", ".ssh", ".aws", ".azure", ".gnupg"],
                    "protected_names": [".env", "id_rsa", "id_ed25519", "credentials", "credentials.json", "secrets.json"],
                    "allowed_executables": ["git", "git.exe", "python", "python.exe", "npm", "npm.cmd"],
                    "blocked_command_patterns": [],
                }
            ),
            encoding="utf-8",
        )
        (config / "projects.json").write_text(
            json.dumps({"projects": {"Personal_DC": str(ROOT)}}),
            encoding="utf-8",
        )

        env = dict(os.environ)
        env["PERSONAL_DC_HOME"] = str(home)

        params = StdioServerParameters(
            command=sys.executable,
            args=[str(ROOT / "run_server.py")],
            cwd=str(ROOT),
            env=env,
        )
        async with stdio_client(params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                started = time.monotonic()
                result = await session.call_tool(
                    "project_git_status",
                    {"project": "Personal_DC"},
                )
                elapsed = time.monotonic() - started
                assert result.isError is not True
                assert elapsed < 5


def test_stdio_git_status_round_trip():
    asyncio.run(_check_git_status())
