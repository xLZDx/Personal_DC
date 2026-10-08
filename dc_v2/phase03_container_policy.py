"""Fail-closed Docker inspect policy verifier for disposable Phase03 workers.

Only inspects an already-provided JSON response. This is defense in depth,
not a proof that Docker Desktop is a VM-equivalent security boundary.
"""
from __future__ import annotations

from typing import Any

from .contracts import Denied, require


def check_container_policy(inspected: Any, *, expected_image: str,
                           expected_workspace: str) -> dict:
    require(type(inspected) is dict, "POLICY_MISMATCH")
    host = inspected.get("HostConfig")
    config = inspected.get("Config")
    mounts = inspected.get("Mounts")
    require(type(host) is dict and type(config) is dict and
            type(mounts) is list and len(mounts) == 1, "POLICY_MISMATCH")
    require(inspected.get("Image") == expected_image and
            config.get("User") == "65534:65534", "POLICY_MISMATCH")
    entrypoint = config.get("Entrypoint")
    require(entrypoint in (["/usr/bin/timeout"], "/usr/bin/timeout"),
            "POLICY_MISMATCH")
    require(host.get("NetworkMode") == "none" and
            host.get("Privileged") is False and
            host.get("ReadonlyRootfs") is True, "POLICY_MISMATCH")
    require(host.get("CapDrop") == ["ALL"] and
            "no-new-privileges:true" in (host.get("SecurityOpt") or []),
            "POLICY_MISMATCH")
    require(type(host.get("PidsLimit")) is int and
            0 < host["PidsLimit"] <= 128, "POLICY_MISMATCH")
    require(type(host.get("Memory")) is int and
            0 < host["Memory"] <= 536870912, "POLICY_MISMATCH")
    require(type(host.get("NanoCpus")) is int and
            0 < host["NanoCpus"] <= 1000000000, "POLICY_MISMATCH")
    require(host.get("IpcMode") == "none", "POLICY_MISMATCH")
    mount = mounts[0]
    require(type(mount) is dict and
            mount.get("Type") == "bind" and
            mount.get("Destination") == "/workspace" and
            mount.get("Source") == expected_workspace, "POLICY_MISMATCH")
    require(not host.get("PidMode") in ("host",) and
            not host.get("UsernsMode") in ("host",) and
            not host.get("CgroupnsMode") in ("host",), "POLICY_MISMATCH")
    return {"profile": "phase03-disposable-linux",
            "image_id": expected_image,
            "workspace_mount_valid": True,
            "container_policy_match": True,
            "security_boundary_certified": False}
