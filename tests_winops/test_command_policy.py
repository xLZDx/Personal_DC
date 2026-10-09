"""Structural read-only allowlists and trust-mode gating for command execution."""
from __future__ import annotations

import pytest
from personal_dc.policy import PolicyError

from dc_v2.winops import command_tools as ct
from dc_v2.winops import process_tools as pt


@pytest.mark.parametrize("script", [
    "Get-Process", "Get-Service -Name Spooler", "Get-Process | Sort-Object CPU | Select-Object -First 5",
    "Get-CimInstance Win32_OperatingSystem | ConvertTo-Json", "Get-CimInstance -ClassName Win32_LogicalDisk",
    "Get-Date",
])
def test_readonly_powershell_accepts_structural_allowlist(script):
    assert ct.validate_readonly_powershell(script) == script


@pytest.mark.parametrize("script", [
    "Remove-Item C:\\x", "Get-Process; whoami", "Get-Process | ForEach-Object { $_.Kill() }",
    "Get-Process $(whoami)", "Get-Service -ComputerName other", "Get-CimInstance Win32_Process",
    "Get-CimInstance -Namespace root Win32_Share", "Get-Process & calc", "Get-Process > out.txt",
    "get-content C:\\Windows\\win.ini", "Invoke-Expression 'x'", "Get-Process |", "", "x" * 1001,
    "Get-Process | Out-File x", "Get-Service -Name `n", "Get-Process\nGet-Service",
])
def test_readonly_powershell_rejects_everything_else(script):
    with pytest.raises(PolicyError):
        ct.validate_readonly_powershell(script)


def test_cmd_not_available_read_only():
    with pytest.raises(PolicyError, match="CMD_NOT_AVAILABLE_IN_READ_ONLY_MODE"):
        ct.command_execute("dir", shell="cmd", mode="read_only")


@pytest.mark.parametrize("argv", [["python.exe", "-c", "print(1)"], ["cmd.exe", "/c", "dir"],
                                  ["whoami.exe", "/all; calc"], ["tasklist.exe", "/s", "other"],
                                  ["sc.exe", "stop", "x"], ["ipconfig.exe", "/release"]])
def test_readonly_exec_rejects_non_allowlisted(argv):
    with pytest.raises(PolicyError):
        ct.command_execute(shell="exec", argv=argv, mode="read_only")


def test_unknown_catalog_alias_still_rejected_like_v1():
    with pytest.raises(PolicyError, match="COMMAND_NOT_IN_SAFE_ALLOWLIST"):
        ct.command_execute("powershell.exe -Command whoami")


def test_shell_in_workspace_mode_needs_approval(work, approvals_ready):
    out = ct.command_execute("Write-Output hi", shell="powershell", cwd=str(work), mode="workspace_write")
    assert out["status"] == "APPROVAL_REQUIRED" and out["mode"] == "workspace_write"


def test_cwd_outside_roots_rejected(tmp_path, approvals_ready):
    with pytest.raises(PolicyError):
        ct.command_execute(shell="exec", argv=["git.exe", "status"], cwd=str(tmp_path), mode="workspace_write")


def test_bare_exe_never_resolves_from_cwd(work):
    (work / "evil.exe").write_bytes(b"MZ")
    env = pt.build_env()
    with pytest.raises(PolicyError):
        pt.resolve_exe("evil.exe", env)
    with pytest.raises(PolicyError, match="RELATIVE_EXECUTABLE_NOT_ALLOWED"):
        pt.resolve_exe(".\\evil.exe", env)


@pytest.mark.parametrize("name", ["PATH", "COMSPEC", "PDC_V2_BACKEND_KEY", "MY_TOKEN", "A B"])
def test_env_isolation_rejects_dangerous_names(name):
    with pytest.raises(PolicyError):
        pt.build_env({name: "x"})


def test_env_does_not_inherit_secrets(monkeypatch):
    monkeypatch.setenv("PDC_V2_BACKEND_KEY", "a" * 64)
    monkeypatch.setenv("CONTROL_PLANE_API_KEY", "k")
    env = pt.build_env()
    assert "PDC_V2_BACKEND_KEY" not in env and "CONTROL_PLANE_API_KEY" not in env


def test_git_force_push_and_global_options_blocked():
    with pytest.raises(PolicyError):
        pt.guard_git_args(["push", "--force", "origin", "x"])
    with pytest.raises(PolicyError):
        pt.guard_git_args(["push", "origin", "+main"])
    with pytest.raises(PolicyError):
        pt.guard_git_args(["-c", "core.sshCommand=calc", "fetch"])
    assert pt.guard_git_args(["status"])[-1] == "status"
