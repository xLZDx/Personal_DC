"""Tool-level "no deletion" policy for an administrator-token server."""
from __future__ import annotations

import pytest
from personal_dc.policy import PolicyError

from dc_v2.winops import command_tools, common, deletion_policy, process_tools

DENIED_TEXT = [
    r"Remove-Item C:\x -Recurse -Force", "remove-item x", "ri x", "rm -r x", r"del /q /f C:\x\*", "erase x",
    r"rd /s /q C:\x", "rmdir /s x", r"Remove-ItemProperty -Path HKCU:\x -Name y", "Remove-Service -Name x",
    "Uninstall-Package x", "Clear-RecycleBin", "format c: /q", "Format-Volume -DriveLetter D", r"cipher /w:C:\ ",
    "git clean -fdx", "git branch -D feature", "git push origin --delete feature", "git reset --hard HEAD~1",
    r"reg delete HKCU\Software\x /f", "sc delete MySvc", "sc.exe delete MySvc", "schtasks /delete /tn x /f",
    "net user bob /delete", "msiexec /x {11111111-2222-3333-4444-555555555555} /qn",
    "wmic product where name=x delete", "robocopy a b /mir", "vssadmin delete shadows /all", "wevtutil cl System",
    "bcdedit /delete {x}", "[System.IO.File]::Delete('x')", "(Get-Item x).Delete()", "Invoke-Expression 'x'",
    "iex $c", "& ('Rem'+'ove-Item') x", "powershell -EncodedCommand AAAA", "$fso.DeleteFile('x')",
]
ALLOWED_TEXT = [
    "Get-Service | Select-Object Name,Status", "Get-Date -Format o", r"Get-ChildItem C:\x | Format-Table",
    "ipconfig /all", "git status", "git log -n 5", "echo hello", "Get-Process | Sort-Object CPU",
    "Write-Output 'removed nothing'", r"dir C:\x", "type file.txt", "msiexec /i setup.msi /qn",
]


@pytest.mark.parametrize("text", DENIED_TEXT)
def test_deletion_text_is_denied(text, isolated_state):
    with pytest.raises(PolicyError, match="DELETION_NOT_ALLOWED"):
        deletion_policy.deny_deletion(text)


@pytest.mark.parametrize("text", ALLOWED_TEXT)
def test_ordinary_text_is_not_blocked(text, isolated_state):
    deletion_policy.deny_deletion(text)


def test_denial_is_audited(isolated_state):
    with pytest.raises(PolicyError):
        deletion_policy.deny_deletion("Remove-Item x", source="powershell")
    audit = (isolated_state / "audit" / "native-audit.jsonl").read_text(encoding="utf-8")
    assert "deletion.policy" in audit and "DENIED" in audit


def test_policy_applies_before_any_approval_is_requested(isolated_state):
    common.init_approval_key()
    for shell, command in (("powershell", r"Remove-Item C:\x"), ("cmd", r"del /q C:\x")):
        with pytest.raises(PolicyError, match="DELETION_NOT_ALLOWED"):
            command_tools.command_execute(command, shell=shell, mode="elevated")
    approvals = isolated_state / "approvals"
    assert not approvals.exists() or not list(approvals.glob("req-*.json"))


def test_exec_vector_and_process_start_are_scanned(isolated_state, work):
    with pytest.raises(PolicyError, match="DELETION_NOT_ALLOWED"):
        command_tools.command_execute("", shell="exec", argv=["cmd.exe", "/c", "del", "x"], mode="elevated")
    with pytest.raises(PolicyError, match="DELETION_NOT_ALLOWED"):
        process_tools.process_start("git.exe", ["clean", "-fd"], cwd=str(work))
    with pytest.raises(PolicyError, match="DELETION_NOT_ALLOWED"):
        process_tools.process_start("sc.exe", ["delete", "x"], cwd=str(work), mode="elevated")


def test_operator_overlay_can_lift_the_policy_locally(isolated_state, native_overlay):
    native_overlay(deny_deletion=False)
    deletion_policy.deny_deletion("Remove-Item x")
