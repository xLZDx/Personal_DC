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


_GIT_SEGMENT = re.compile(r"(?i)(?<![\w.-])git(?:\.exe)?(?![\w-])([^|;&\r\n]*)")


def git_deletes(args: list[str]) -> str | None:
    """Structured check of one git argument vector (``args`` exclude ``git``); returns the offending form or None.

    Covers destructive ref/work-tree/history operations including long-option aliases and combined short flags.
    """
    tokens = [str(a).strip("\"'") for a in args]
    # skip leading global options (-C <dir>, -c k=v, --no-pager, ...): the subcommand is the first bare word
    i, sub = 0, ""
    while i < len(tokens):
        t = tokens[i]
        if t in ("-C", "-c", "--git-dir", "--work-tree", "--namespace"):
            i += 2
            continue
        if t.startswith("-"):
            i += 1
            continue
        sub = t.casefold()
        break
    rest = [t.casefold() for t in tokens[i + 1:]]
    flags = [t for t in rest if t.startswith("-")]
    words = [t for t in rest if not t.startswith("-")]
    short = "".join(f[1:] for f in flags if not f.startswith("--"))
    longs = {f.split("=", 1)[0] for f in flags if f.startswith("--")}
    long_delete = any(len(l) >= 5 and "--delete".startswith(l) for l in longs)      # --del, --dele, ... abbreviations
    if sub == "branch" and ("d" in short or long_delete):
        return "branch delete"
    if sub == "tag" and ("d" in short or long_delete):
        return "tag delete"
    if sub == "remote" and words[:1] and words[0] in ("remove", "rm", "prune"):
        return "remote " + words[0]
    if sub == "stash" and words[:1] and words[0] in ("drop", "clear"):
        return "stash " + words[0]
    if sub == "reset" and ({"--hard", "--merge", "--keep"} & longs):
        return "reset --hard"
    if sub in ("clean", "rm", "filter-branch", "filter-repo", "prune"):
        return sub
    if sub == "restore" and "--staged" not in longs and "S" not in short.upper():
        return "restore (discards work)"
    if sub == "checkout" and ("--" in rest or "." in words or "f" in short or "--force" in longs or "--ours" in longs):
        return "checkout (discards work)"
    if sub == "switch" and ("--discard-changes" in longs or "f" in short or "--force" in longs or "C" in "".join(
            f[1:] for f in tokens[i + 1:] if f.startswith("-") and not f.startswith("--"))):
        return "switch force"
    if sub == "push" and ({"--delete", "--prune", "--mirror"} & longs or "d" in short
                          or any(w.startswith(":") for w in words)):
        return "push delete"
    if sub == "worktree" and words[:1] and words[0] in ("remove", "prune"):
        return "worktree " + words[0]
    if sub == "gc" and any(f.startswith("--prune") for f in flags):
        return "gc --prune"
    if sub == "reflog" and words[:1] and words[0] in ("expire", "delete"):
        return "reflog " + words[0]
    if sub == "update-ref" and ("d" in short or "--delete" in longs):
        return "update-ref -d"
    if sub == "submodule" and words[:1] and words[0] in ("deinit",):
        return "submodule deinit"
    return None


def _deny_git_in_text(text: str, source: str) -> None:
    for match in _GIT_SEGMENT.finditer(text):
        found = git_deletes(match.group(1).split())
        if found:
            audit("deletion.policy", "DENIED", source=source, reason="GIT_DELETION", matched=found[:40])
            raise PolicyError("DELETION_NOT_ALLOWED:GIT_DELETION:" + found)


def deny_deletion(text: str, *, source: str = "command") -> None:
    """Raise ``DELETION_NOT_ALLOWED`` when the text contains a deletion verb or hides one behind dynamic code."""
    if not native_config().get("deny_deletion", True):
        return
    if not isinstance(text, str):
        return
    _deny_git_in_text(text, source)
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
