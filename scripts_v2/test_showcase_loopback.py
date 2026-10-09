"""Full positive/negative synthetic loopback MCP test with disposable token."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = Path(r"D:\Temp\Personal_DC_v2_2_full_20261008")
OUT = ROOT / "evidence" / "v2_2" / "showcase-loopback-test.json"
URL_PORT = 18766

def free_port() -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", URL_PORT)) != 0

def main() -> int:
    if not free_port():
        print("SHOWCASE_TEST_PORT_BUSY")
        return 2
    env = os.environ.copy()
    env.pop("CONTROL_PLANE_API_KEY", None)
    env.pop("OPENAI_ADMIN_KEY", None)
    env["PDC_V2_BACKEND_KEY"] = secrets.token_hex(32)
    process = subprocess.Popen([sys.executable, "-m", "dc_v2.showcase_mcp"],
                               cwd=str(ROOT), env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    result = {"schema": "pdc-v2-showcase-test.v1",
              "checked_utc": datetime.now(timezone.utc).isoformat(),
              "candidate": "synthetic-only", "checks": {}, "status": "ERROR"}
    try:
        end = time.monotonic() + 18
        while time.monotonic() < end and free_port() and process.poll() is None:
            time.sleep(0.15)
        if free_port():
            raise RuntimeError("SHOWCASE_SERVER_DID_NOT_START")
        os.environ["PDC_V2_BACKEND_KEY"] = env["PDC_V2_BACKEND_KEY"]
        sys.path.insert(0, str(ROOT / "scripts_v2"))
        from probe_v2_showcase import verify
        result["checks"] = asyncio.run(verify())
        result["status"] = "PASS" if all(result["checks"].values()) else "FAIL"
    except Exception as exc:
        result["error_type"] = type(exc).__name__
        result["error_module"] = getattr(exc, "name", "")
    finally:
        os.environ.pop("PDC_V2_BACKEND_KEY", None)
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        result["server_stopped"] = free_port()
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(result, indent=2)+"\n",encoding="utf-8")
    print("SHOWCASE_TEST_"+result["status"])
    print("CHECKS",sum(result["checks"].values()),"/",len(result["checks"]))
    print("SERVER_STOPPED",result["server_stopped"])
    return 0 if result["status"]=="PASS" and result["server_stopped"] else 1

if __name__=="__main__":
    raise SystemExit(main())
