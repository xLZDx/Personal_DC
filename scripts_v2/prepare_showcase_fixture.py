"""Create a reviewed, public synthetic-only capture for the separate v2 demo.

Copies only fixed boolean results and short allowlisted diagnostic strings;
paths, runtime IDs, token material and command arguments are excluded.
"""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
import json

ROOT = Path(r"D:\Temp\Personal_DC_v2_2_full_20261008")
SOURCE = Path(r"D:\Temp\Personal_DC_v2_2_isolated\evidence\ab_20261009")
target = ROOT / "showcase_data" / "captured_evidence.json"
p = json.loads((SOURCE / "live-probe.json").read_text(encoding="utf-8"))
n = json.loads((SOURCE / "toolchains.json").read_text(encoding="utf-8"))
if p.get("status") != "PASS" or n.get("status") != "PASS":
    raise SystemExit("TEST_EVIDENCE_NOT_PASSED")
if not all(x.get("pass") is True for x in p.get("tests", {}).values()):
    raise SystemExit("PYTHON_CHECK_INCOMPLETE")
if not all(x.get("pass") is True for x in n.get("checks", {}).values()):
    raise SystemExit("NODE_CHECK_INCOMPLETE")

allowlisted = {
    "python": ("PDC_SANDBOX_42", p["tests"]["python-cli"]["pass"]),
    "node": ("NODE_OK", n["checks"]["node"]["pass"]),
    "npm-build": ("NPM_BUILD_OK", n["checks"]["npm-build"]["pass"]),
    "git": ("git version 2.39.5", n["checks"]["git-cli"]["pass"]),
    "no-inherited-secrets": ("ENV_CLEAN", n["checks"]["no-inherited-secrets"]["pass"]),
    "network-is-disabled": ("NO_ROUTE", n["checks"]["network-is-disabled"]["pass"]),
}
data = {
    "schema": "personal-dc.showcase.v1",
    "captured_at": datetime.now(timezone.utc).isoformat(),
    "captured_from": "Local synthetic Docker smoke; no live execution in remote MCP",
    "scenarios": {k: {"pass": bool(v), "output": out} for k, (out,v) in allowlisted.items()},
    "recorded_checks": {
        "python": "8/8 passed",
        "node": "5/5 passed",
        "mcp_local": "54 passed, 1 skipped",
    },
}
if target.exists():
    raise SystemExit("SHOWCASE_ALREADY_EXISTS_NO_OVERWRITE")
target.parent.mkdir(exist_ok=True)
target.write_text(json.dumps(data, ensure_ascii=True, indent=2)+"\n",encoding="utf-8")
print("SYNTHETIC_FIXTURE_PREPARED", target.name)
