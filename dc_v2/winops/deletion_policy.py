"""Tool-level "no deletion" policy for shell-like launches.

The operator runs the v2 server with local-administrator rights but wants it to be unable to delete anything.
Windows cannot enforce "admin without delete" at OS level, so this is a TOOL-LEVEL control: every
PowerShell / cmd / shell-executable launch is scanned for deletion verbs, dynamic code construction
(which could hide a verb) and well-known destructive utilities, and refused before any approval is requested.

Honest limit (also in KNOWN_LIMITATIONS.md): this is a best-effort text policy. An approved interpreter
(python/node/...) or an installer can still delete files because they run arbitrary code; those stay
behind a per-run operator approval that shows the exact parameters.
"""
from __future__ import annotations

import re

from personal_dc.policy import PolicyError

from .common import audit, native_config

_VERBS = (
    r"remove-item(?:property)?|remove-\w+|uninstall-\w+|clear-recyclebin|clear-disk|format-volume|initialize-disk|"
    r"del|erase|rd|rmdir|rm|ri|rmdir|deltree|"
    r"format\s+[a-z]:|diskpart|cipher|sdelete|sdelete64|shred|"
    r"vssadmin|wbadmin|bcdedit|wevtutil|fsutil|deletefile|deletefolder|"
    r"git\s+clean|git\s+branch\s+-d|git\s+push\s+\S+\s+--delete|git\s+reset\s+--hard|git\s+checkout\s+--|git\s+stash\s+(?:drop|clear)|"
    r"reg(?:\.exe)?\s+delete|sc(?:\.exe)?\s+delete|schtasks(?:\.exe)?\s+/delete|net\s+user\s+.*?/delete|"
    r"net\s+share\s+.*?/delete|netsh\s+.*?\bdelete\b|msiexec(?:\.exe)?\s+.*?/(?:x|uninstall)\b|"
    r"wmic\s+.*?\bdelete\b|robocopy\s+.*?/(?:mir|purge|mov)\b|xcopy\s+.*?/(?:y\s+)?/?move"
)
_DELETION = re.compile(r"(?i)(?<![\w.-])(?:" + _VERBS + r")(?![\w-])")
_DYNAMIC = re.compile(
    r"(?i)(invoke-expression|\biex\b|invoke-command|\bicm\b|add-type|\.delete(?:file|folder)?\s*\(|\[(?:system\.)?io\.(?:file|directory|path)\]|"
    r"\[(?:system\.)?management\.automation|frombase64string|-enc(?:odedcommand)?\b|"
    r"new-object\s+-?com|\bwscript\b|\bcscript\b|\bmshta\b|\brundll32\b|"
    r"&\s*\(|&\s*\$|\.\s*\()")


def deny_deletion(text: str, *, source: str = "command") -> None:
    """Raise ``DELETION_NOT_ALLOWED`` when the text contains a deletion verb or hides one behind dynamic code."""
    if not native_config().get("deny_deletion", True):
        return
    if not isinstance(text, str):
        return
    hit = _DELETION.search(text)
    reason = "DELETION_VERB"
    if hit is None:
        hit = _DYNAMIC.search(text)
        reason = "DYNAMIC_CODE_COULD_HIDE_DELETION"
    if hit is None:
        return
    audit("deletion.policy", "DENIED", source=source, reason=reason, matched=hit.group(0)[:40])
    raise PolicyError("DELETION_NOT_ALLOWED:" + reason + ":" + hit.group(0).strip()[:30])


SHELL_EXECUTABLES = {"powershell.exe", "pwsh.exe", "cmd.exe"}
DESTRUCTIVE_EXECUTABLES = {"diskpart.exe", "format.com", "cipher.exe", "sdelete.exe", "sdelete64.exe", "vssadmin.exe",
                           "wbadmin.exe", "bcdedit.exe", "wevtutil.exe", "wmic.exe", "robocopy.exe", "xcopy.exe",
                           "sc.exe", "reg.exe", "schtasks.exe", "netsh.exe", "net.exe", "net1.exe", "fsutil.exe",
                           "mshta.exe", "rundll32.exe"}


def deny_deletion_argv(exe_name: str, args: list[str]) -> None:
    """Check an argument vector. Shell executables are scanned as text; utilities that can delete are scanned verb-wise."""
    name = exe_name.casefold()
    joined = " ".join(str(a) for a in args)
    if name in SHELL_EXECUTABLES:
        deny_deletion(joined, source=name)
    elif name in DESTRUCTIVE_EXECUTABLES:
        deny_deletion(name.rsplit(".", 1)[0] + " " + joined, source=name)
    elif name == "git.exe":
        deny_deletion("git " + joined, source=name)
    elif name == "msiexec.exe":
        deny_deletion("msiexec " + joined, source=name)
