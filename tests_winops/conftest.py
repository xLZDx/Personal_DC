"""Isolated state for native-operations tests.

Every test gets its own private state directory (``PDC_V2_STATE_DIR``), its own gateway home with a
policy whose only allowed root is ``<tmp>/work``, and a clean managed-process registry. Nothing here
touches the real ``%LOCALAPPDATA%\\Personal_DC_V2`` state, the real approval key or real services.
"""
from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

if sys.platform != "win32":      # a module-level pytestmark in conftest is ignored; ignore collection instead
    collect_ignore_glob = ["test_*.py"]


def _write_policy(home: Path, roots: list[Path]) -> None:
    (home / "config").mkdir(parents=True, exist_ok=True)
    (home / "logs").mkdir(parents=True, exist_ok=True)
    (home / "config" / "policy.json").write_text(json.dumps({
        "allowed_roots": [str(r) for r in roots], "protected_components": [".git"],
        "protected_names": [".env"], "allowed_executables": ["git.exe"], "blocked_command_patterns": []}),
        encoding="utf-8")


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    """Private state dir + gateway home; ``PDC_V2_STATE_DIR`` always points below ``tmp_path``."""
    state = tmp_path / "state"
    state.mkdir()
    monkeypatch.setenv("PDC_V2_STATE_DIR", str(state))
    monkeypatch.setenv("PERSONAL_DC_HOME", str(tmp_path / "home"))
    allowed = tmp_path / "work"
    allowed.mkdir()
    _write_policy(tmp_path / "home", [allowed])
    return state


@pytest.fixture(autouse=True)
def clean_process_registry():
    """Reset module-level managed-process state before AND after each test; kill leftovers.

    ``process_tools`` keeps a process-wide registry and a one-shot recovery flag. Without this a test that
    left a live process (or flipped ``_RECOVERED``) would leak into the next one.
    """
    from dc_v2.winops import process_tools as pt

    def _reset(kill: bool) -> None:
        with pt._REG_LOCK:
            leftovers = list(pt._REGISTRY.values())
            pt._REGISTRY.clear()
            pt._RESERVED = 0
        for managed in leftovers:
            managed.cancel.set()
            if kill:
                with contextlib.suppress(Exception):
                    pt._kill(managed)
                if managed.popen is not None:
                    with contextlib.suppress(Exception):
                        managed.popen.wait(timeout=5)
        pt._RECOVERED = False
        pt._UTF8_CACHE.clear()

    _reset(kill=False)
    yield
    _reset(kill=True)


@pytest.fixture(autouse=True)
def clean_transfer_cache():
    from dc_v2 import binary_transfer as bt
    bt._HASH_CACHE.clear()
    yield
    bt._HASH_CACHE.clear()


@pytest.fixture()
def work(tmp_path):
    return tmp_path / "work"


@pytest.fixture()
def set_policy(tmp_path):
    """Rewrite the gateway policy with a different list of allowed roots."""
    def _set(*roots: Path) -> None:
        _write_policy(tmp_path / "home", list(roots))
    return _set


@pytest.fixture()
def native_overlay(isolated_state):
    """Write/merge the operator overlay ``<state>/config/native.json`` (the only way config is widened)."""
    path = isolated_state / "config" / "native.json"

    def _apply(**values) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        current = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
        current.update(values)
        path.write_text(json.dumps(current), encoding="utf-8")
    return _apply


@pytest.fixture()
def trust_current_python(native_overlay):
    """Make the running interpreter an auto-trusted dev tool (interpreters normally REQUIRE approval)."""
    from dc_v2.winops import common
    real = Path(sys.executable).resolve()
    native_overlay(dev_executables=["git.exe", real.name],
                   extra_path_dirs=list(common._DEFAULT_CONFIG["extra_path_dirs"]) + [str(real.parent)])
    return real


@pytest.fixture()
def approvals_ready(isolated_state):
    from dc_v2.winops import common
    common.init_approval_key()
    return common


@pytest.fixture()
def make_junction():
    """Create an NTFS junction (``mklink /J``) and remove only the link itself at teardown."""
    created: list[Path] = []

    def _make(link: Path, target: Path) -> Path:
        subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True, capture_output=True)
        created.append(link)
        return link

    yield _make
    for link in created:
        with contextlib.suppress(OSError):
            os.rmdir(link)     # rmdir on a junction removes the link, never the target's content
