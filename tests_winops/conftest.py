"""Isolated state for native-operations tests: every test gets its own state dir and approval key."""
from __future__ import annotations

import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="native Windows layer")


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    state = tmp_path / "state"
    state.mkdir()
    monkeypatch.setenv("PDC_V2_STATE_DIR", str(state))
    monkeypatch.setenv("PERSONAL_DC_HOME", str(tmp_path / "home"))
    (tmp_path / "home" / "config").mkdir(parents=True)
    (tmp_path / "home" / "logs").mkdir()
    allowed = tmp_path / "work"
    allowed.mkdir()
    import json
    (tmp_path / "home" / "config" / "policy.json").write_text(json.dumps({
        "allowed_roots": [str(allowed)], "protected_components": [".git"],
        "protected_names": [".env"], "allowed_executables": ["git.exe"], "blocked_command_patterns": []}),
        encoding="utf-8")
    return state


@pytest.fixture()
def work(tmp_path):
    return tmp_path / "work"


@pytest.fixture()
def approvals_ready(isolated_state):
    from dc_v2.winops import common
    common.init_approval_key()
    return common
