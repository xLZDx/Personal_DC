"""Synthetic Docker inspect threat-profile checks; no live daemon mutation."""
from __future__ import annotations

from copy import deepcopy
import pytest

from dc_v2.contracts import Denied
from dc_v2.phase03_container_policy import check_container_policy

IMAGE = "sha256:" + "a" * 64
WORKSPACE = r"D:\Temp\synthetic-pdc-workspace"


@pytest.fixture
def profile():
    return {
        "Image": IMAGE,
        "Config": {"User": "65534:65534", "Entrypoint": ["/usr/bin/timeout"]},
        "HostConfig": {
            "NetworkMode": "none", "Privileged": False, "ReadonlyRootfs": True,
            "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"],
            "PidsLimit": 128, "Memory": 536870912, "NanoCpus": 1000000000,
            "IpcMode": "none", "PidMode": "", "UsernsMode": "",
            "CgroupnsMode": "private"
        },
        "Mounts": [{"Type": "bind", "Destination": "/workspace",
                    "Source": WORKSPACE}]
    }


def test_pinned_profile_is_explicitly_not_vm_certification(profile):
    result = check_container_policy(profile, expected_image=IMAGE,
                                    expected_workspace=WORKSPACE)
    assert result["container_policy_match"]
    assert result["security_boundary_certified"] is False


@pytest.mark.parametrize("field,value", [
    ("NetworkMode", "host"), ("Privileged", True), ("ReadonlyRootfs", False),
    ("CapDrop", []), ("SecurityOpt", []), ("PidsLimit", 0),
    ("PidsLimit", 256), ("Memory", 0), ("Memory", 1073741824),
    ("NanoCpus", 0), ("NanoCpus", 2000000000), ("IpcMode", "host"),
    ("PidMode", "host"), ("UsernsMode", "host"), ("CgroupnsMode", "host")
])
def test_mutated_security_profile_denied(profile, field, value):
    altered = deepcopy(profile)
    altered["HostConfig"][field] = value
    with pytest.raises(Denied, match="POLICY_MISMATCH"):
        check_container_policy(altered, expected_image=IMAGE,
                               expected_workspace=WORKSPACE)


@pytest.mark.parametrize("mutation", ["wrong-image", "extra-mount",
                                      "docker-socket", "different-workspace",
                                      "root-user", "host-entrypoint"])
def test_identity_and_mount_policy_denied(profile, mutation):
    x = deepcopy(profile)
    if mutation == "wrong-image":
        x["Image"] = "sha256:" + "b"*64
    elif mutation == "extra-mount":
        x["Mounts"].append({"Type": "bind", "Destination": "/host",
                             "Source": "/secrets"})
    elif mutation == "docker-socket":
        x["Mounts"][0]["Source"] = "/var/run/docker.sock"
    elif mutation == "different-workspace":
        x["Mounts"][0]["Source"] = "/tmp/other"
    elif mutation == "root-user":
        x["Config"]["User"] = "0"
    else:
        x["Config"]["Entrypoint"] = ["/bin/sh"]
    with pytest.raises(Denied, match="POLICY_MISMATCH"):
        check_container_policy(x, expected_image=IMAGE,
                               expected_workspace=WORKSPACE)
