"""Operator approval CLI. Run by the workstation owner, never exposed as an MCP tool.

    python -m dc_v2.winops.approve init              # provision the DPAPI approval key (once)
    python -m dc_v2.winops.approve list              # pending / granted requests
    python -m dc_v2.winops.approve show  req-XXXX    # full summary + digest to review
    python -m dc_v2.winops.approve grant req-XXXX [--ttl 600]
    python -m dc_v2.winops.approve deny  req-XXXX
    python -m dc_v2.winops.approve verify-audit

An approval is bound to the SHA-256 of the exact action and parameters, expires
(default 15 min, max 60 min) and can be used once.
"""
from __future__ import annotations

import argparse
import json
import sys

from personal_dc.policy import PolicyError

from .common import (APPROVAL_TTL_DEFAULT_S, approvals_dir, audit, audit_verify, grant_approval,
                     init_approval_key, iso, read_json, valid_id)


def _requests() -> list[dict]:
    base = approvals_dir()
    rows = []
    for path in sorted(base.glob("req-*.json")):
        if path.name.endswith(".grant.json"):
            continue
        data = read_json(path, {})
        rid = data.get("id", path.stem)
        data["granted"] = (base / (rid + ".grant.json")).is_file()
        data["used"] = (base / (rid + ".used")).is_file()
        data["denied"] = (base / (rid + ".denied")).is_file()
        rows.append(data)
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dc_v2.winops.approve")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    sub.add_parser("list")
    sub.add_parser("verify-audit")
    for name in ("show", "grant", "deny"):
        p = sub.add_parser(name)
        p.add_argument("approval_id")
        if name == "grant":
            p.add_argument("--ttl", type=int, default=APPROVAL_TTL_DEFAULT_S)
    args = parser.parse_args(argv)
    try:
        if args.cmd == "init":
            print("approval key created" if init_approval_key() else "approval key already present")
        elif args.cmd == "list":
            for r in _requests():
                state = "USED" if r["used"] else "DENIED" if r["denied"] else "GRANTED" if r["granted"] else "PENDING"
                print(f'{r.get("id")}  {state:8}  {r.get("action")}  {r.get("created_at")}')
        elif args.cmd == "verify-audit":
            print(json.dumps(audit_verify(), indent=2))
        else:
            if not valid_id(args.approval_id) or not args.approval_id.startswith("req-"):
                raise PolicyError("INVALID_APPROVAL_ID")
            base = approvals_dir()
            req = read_json(base / (args.approval_id + ".json"))
            if not req:
                raise PolicyError("APPROVAL_REQUEST_NOT_FOUND")
            if args.cmd == "show":
                print(json.dumps(req, indent=2, ensure_ascii=False))
            elif args.cmd == "deny":
                (base / (args.approval_id + ".denied")).write_text(iso(), encoding="utf-8")
                (base / (args.approval_id + ".grant.json")).unlink(missing_ok=True)
                audit("approval.deny", "DENIED", actor="operator-cli", approval_id=args.approval_id)
                print("denied")
            else:
                print(json.dumps(req, indent=2, ensure_ascii=False))
                answer = input("Type the first 8 chars of the digest to GRANT: ").strip()
                if answer != req["digest"][:8]:
                    print("digest prefix mismatch - NOT granted")
                    return 2
                if (base / (args.approval_id + ".denied")).exists():
                    raise PolicyError("REQUEST_WAS_DENIED")
                print(json.dumps(grant_approval(args.approval_id, args.ttl), indent=2))
    except PolicyError as exc:
        print("ERROR:", exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
