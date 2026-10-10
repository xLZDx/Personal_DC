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


def _abbrev(flag: str, full: str, minimum: int = 2) -> bool:
    """git accepts any unambiguous prefix of a long option (``--har`` is ``--hard``). Being conservative, every prefix of
    at least ``minimum`` characters of ``full`` counts as that option (``flag`` is the name without leading dashes)."""
    return len(flag) >= minimum and (full.startswith(flag) or flag.startswith(full))     # also --force-with-lease


def git_deletes(args: list[str]) -> str | None:
    """Structured check of one git argument vector (``args`` exclude ``git``); returns the offending form or None.

    Covers destructive ref/work-tree/history/object operations including long-option abbreviations (``--har``,
    ``--for``), combined short flags, restore of the work tree, destructive housekeeping and force pushes.
    """
    tokens = [str(a).strip("\"'") for a in args]
    # skip leading global options (-C <dir>, -c k=v, --no-pager, ...): the subcommand is the first bare word
    i, sub = 0, ""
    while i < len(tokens):
        t = tokens[i]
        if t == "-c" and i + 1 < len(tokens) and tokens[i + 1].casefold().startswith("alias."):
            return "alias override (can hide a destructive command)"
        if t in ("-C", "-c", "--git-dir", "--work-tree", "--namespace"):
            i += 2
            continue
        if t.startswith("-"):
            i += 1
            continue
        sub = t.casefold()
        break
    rest_raw = tokens[i + 1:]
    rest = [t.casefold() for t in rest_raw]
    flags = [t for t in rest if t.startswith("-") and t != "--"]
    words = [t for t in rest if not t.startswith("-")]
    short = "".join(f[1:] for f in flags if not f.startswith("--"))
    short_cs = "".join(f[1:] for f in rest_raw if f.startswith("-") and not f.startswith("--"))     # case-sensitive
    longs = {f.split("=", 1)[0][2:] for f in flags if f.startswith("--")}                          # names without dashes

    def has_long(full: str, minimum: int = 2) -> bool:
        return any(_abbrev(name, full, minimum) for name in longs)

    if sub == "branch" and ("d" in short or has_long("delete", 3)):
        return "branch delete"
    if sub == "tag" and ("d" in short or has_long("delete", 3)):
        return "tag delete"
    if sub == "remote" and words[:1] and words[0] in ("remove", "rm", "prune"):
        return "remote " + words[0]
    if sub == "stash" and words[:1] and words[0] in ("drop", "clear"):
        return "stash " + words[0]
    if sub == "reset" and (has_long("hard") or has_long("merge") or has_long("keep")):
        return "reset --hard"
    if sub in ("clean", "rm", "filter-branch", "filter-repo", "prune", "prune-packed", "repack", "gc", "maintenance"):
        return sub                                  # irreversible object/work-tree removal (gc prunes unreachable objects)
    if sub == "restore" and (has_long("worktree") or "W" in short_cs or not (has_long("staged", 3) or "S" in short_cs)):
        return "restore (discards work)"
    if sub == "checkout" and ("--" in rest or "." in words or "f" in short or has_long("force") or has_long("ours", 2)
                              or has_long("theirs", 3)):
        return "checkout (discards work)"
    if sub == "switch" and (has_long("discard-changes") or has_long("force") or "f" in short or "C" in short_cs):
        return "switch force"
    if sub == "push" and (has_long("delete", 3) or has_long("prune") or has_long("mirror") or has_long("force")
                          or "d" in short or "f" in short or any(w.startswith((":", "+")) for w in words)):
        return "push delete/force"
    if sub == "worktree" and words[:1] and words[0] in ("remove", "prune"):
        return "worktree " + words[0]
    if sub == "reflog" and words[:1] and words[0] in ("expire", "delete"):
        return "reflog " + words[0]
    if sub == "update-ref" and ("d" in short or has_long("delete", 3)):
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
