"""Personal v2 native command perimeter and independent registration."""
from __future__ import annotations

import asyncio
import pytest
from personal_dc.policy import PolicyError
from dc_v2.native_personal_mcp import native_tools
from dc_v2.windows_native_tools import (
    _COMMANDS, command_execute, service_status, system_diagnostics,
)


def test_native_tools_exposed_only_as_narrow_operators():
    names={x.name for x in asyncio.run(native_tools.list_tools())}
    assert {"system_diagnostics","service_status","command_execute"} <= names
    assert "powershell_execute" not in names
    assert "service_control" not in names


@pytest.mark.parametrize("command", [
    "powershell.exe -Command whoami", "cmd /c del", "sc stop",
    "whoami && calc", "git", "", "services --verbose",
])
def test_arbitrary_command_not_executable(command):
    with pytest.raises(PolicyError,match="COMMAND_NOT_IN_SAFE_ALLOWLIST"):
        command_execute(command)


@pytest.mark.parametrize("name",[
    "", "spooler & whoami", "bad service", "../etc/passwd",
    "X"*101, "x|y", "a/b",
])
def test_service_name_injection_blocked(name):
    with pytest.raises(PolicyError,match="INVALID_SERVICE_NAME"):
        service_status(name)


def test_diagnostic_kind_not_open_ended():
    with pytest.raises(PolicyError,match="UNKNOWN_DIAGNOSTIC_KIND"):
        system_diagnostics("stop all services")


def test_exact_arguments_not_shell_fragments():
    assert "powershell.exe" not in " ".join(_COMMANDS).lower()
    assert all(isinstance(args,tuple) and len(args)>0 for args in _COMMANDS.values())
    assert _COMMANDS["services"] == ("sc.exe","query","state=","all")
