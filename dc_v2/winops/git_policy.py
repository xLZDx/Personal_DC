"""Structured, per-subcommand policy for approval-free git.

A subcommand name alone is not a safe trust boundary: several "local" subcommands can launch an external
program (editor, external diff/textconv, clean/smudge filter, pager, credential/ssh helper) or delete refs.
Approval-free execution therefore requires ALL of:

1. the subcommand is in the configured free set;
2. its arguments match that subcommand's explicit allowlist below (anything else needs an operator approval);
3. neither the repository config nor the user git config defines a program-launching setting
   (editor, external diff, textconv, filters, pager, alias, credential helpers, hooks, fsmonitor, ...).

Everything that does not qualify is not "denied": it returns APPROVAL_REQUIRED showing the exact vector.
"""
from __future__ import annotations

import os
import re
from collections.abc import Callable
from pathlib import Path

# Any section with these names is a program-launching surface (filter drivers, aliases, credential helpers, ...).
_RISKY_SECTIONS = {"filter", "alias", "credential", "include", "includeif", "url", "difftool", "mergetool", "pager",
                   "uploadpack", "gpg"}
# Individual keys ("section.key" or "section.subsection.key") that make git run a program.
_RISKY_KEY = re.compile(
    r"(?i)^(core\.(editor|pager|fsmonitor|hookspath|sshcommand|askpass|gitproxy|attributesfile|worktree|alternaterefscommand)|"
    r"sequence\.editor|diff\.(external|tool|guitool)|diff\..*\.(textconv|command)|merge\.tool|merge\..*\.driver|"
    r"commit\.gpgsign|web\.browser|help\.browser|http\.(proxy|sslcommand|cookiefile)|"
    r"credential\..*|protocol\..*\.allow)$")

_UNTRUSTED_SCOPES = {"local", "worktree", "command"}
_READ_ONLY = {"status", "diff", "log", "show", "rev-parse", "ls-files", "blame", "describe", "shortlog"}
# Listing-only options for ``git branch``; every other form (create/delete/rename/edit/upstream) needs approval.
_BRANCH_LIST = {"-a", "-r", "-v", "-vv", "--all", "--remotes", "--list", "-l", "--show-current", "--verbose",
                "--no-color", "--color", "--contains", "--no-contains", "--merged", "--no-merged", "--sort",
                "--format", "--points-at"}
_ADD_FORBIDDEN = {"--interactive", "--patch", "--edit"}
_COMMIT_FORBIDDEN = {"--edit", "--template", "--file", "--reuse-message", "--reedit-message", "--fixup", "--squash",
                     "--amend", "--interactive", "--patch", "--all-from"}


def _norm(path: str) -> str:
    return os.path.normcase(os.path.normpath(path))


def trusted_config_origins(env: dict[str, str], git_exe: Path | None) -> set[str]:
    """Exact config files the administrator/user owns (never reachable through workspace tools or a repository)."""
    home = env.get("USERPROFILE", "")
    candidates = []
    if home:
        candidates += [Path(home) / ".gitconfig", Path(home) / ".config" / "git" / "config"]
    for var in ("ProgramFiles", "ProgramFiles(x86)"):
        if env.get(var):
            candidates.append(Path(env[var]) / "Git" / "etc" / "gitconfig")
    if env.get("ProgramData"):
        candidates.append(Path(env["ProgramData"]) / "Git" / "config")
    if git_exe is not None:
        for root in {git_exe.parent.parent, git_exe.parent.parent.parent}:
            candidates += [root / "etc" / "gitconfig", root / "mingw64" / "etc" / "gitconfig"]
    return {_norm(str(c)) for c in candidates}


def config_risk_from_listing(listing: str, trusted_origins: set[str] | None = None) -> str | None:
    """First program-launching key in ``git config --list --show-scope --show-origin`` output, or None.

    Each line is ``scope<TAB>origin<TAB>key=value``. The listing is produced by git itself for the real working
    directory, so repository discovery (parent directories, worktrees, gitfile redirects) and includes are resolved
    by git rather than re-implemented here. A program-launching key is tolerated only when BOTH its scope is not
    repository-controlled (local/worktree/command) AND its origin file is one of ``trusted_origins`` (e.g. Git for
    Windows ships ``filter.lfs`` and ``credential.helper`` in its system gitconfig). Origin matters because a global
    ``include``/``includeIf`` can pull a repository-writable file into global scope. Unknown provenance is risky.
    """
    trusted = trusted_origins if trusted_origins is not None else set()
    for raw in listing.splitlines():
        parts = raw.split(chr(9), 2)
        if len(parts) == 3:
            scope, origin, entry = parts
        else:                                              # no provenance columns: judge conservatively
            scope, origin, entry = "local", "", raw
        key = entry.split("=", 1)[0].strip()
        if not key:
            continue
        if not (key.split(".", 1)[0].casefold() in _RISKY_SECTIONS or _RISKY_KEY.match(key)):
            continue
        path = origin[5:] if origin.startswith("file:") else ""
        if scope.strip() in _UNTRUSTED_SCOPES or not path or _norm(path) not in trusted:
            return key
    return None


def _long_flags(args: list[str]) -> set[str]:
    return {a.split("=", 1)[0] for a in args if a.startswith("--") and a != "--"}


def _short_letters(args: list[str]) -> str:
    out = ""
    for a in args:
        if a == "--":
            break
        if a.startswith("-") and not a.startswith("--") and len(a) > 1:
            out += a[1:]
    return out


def args_allowed_for_free(sub: str, args: list[str]) -> bool:
    """Per-subcommand allowlist for approval-free use (``args`` exclude the subcommand itself)."""
    if sub in _READ_ONLY:
        return True
    if sub == "branch":
        flags = [a.split("=", 1)[0] for a in args if a.startswith("-")]
        positional = [a for a in args if not a.startswith("-")]
        pattern_flags = {"--contains", "--no-contains", "--merged", "--no-merged", "--points-at", "--list", "-l"}
        if not all(f in _BRANCH_LIST for f in flags):
            return False
        return not positional or any(f in pattern_flags for f in flags)      # a bare name would CREATE a branch
    if sub == "remote":
        return args in ([], ["-v"], ["--verbose"]) or (len(args) == 2 and args[0] == "get-url")
    if sub == "add":
        return not (_long_flags(args) & _ADD_FORBIDDEN) and not (set(_short_letters(args)) & set("ipe"))
    if sub == "commit":
        has_message = any(a in ("-m", "--message") or a.startswith("--message=") or (a.startswith("-m") and len(a) > 2)
                          for a in args)
        short_bad = set(_short_letters(args).split("m")[0]) & set("eFCctip")
        return has_message and not (_long_flags(args) & _COMMIT_FORBIDDEN) and not short_bad
    return False                                  # switch/checkout/restore/... may run filters or discard work


def git_is_free(sub: str, args: list[str], cwd: Path | None, free_set: set[str],
                config_probe: Callable[[Path], str | None] | None = None) -> tuple[bool, str]:
    """Approval-free eligibility; returns (free, reason-when-not).

    Without a ``config_probe`` the effective git configuration cannot be inspected, so nothing is free."""
    if sub not in free_set:
        return False, "SUBCOMMAND_NOT_IN_FREE_SET"
    if not args_allowed_for_free(sub, args):
        return False, "ARGUMENTS_NOT_IN_FREE_ALLOWLIST"
    if cwd is None or config_probe is None:
        return False, "EFFECTIVE_GIT_CONFIG_UNKNOWN"
    risky = config_probe(cwd)
    if risky:
        return False, "CONFIG_LAUNCHES_PROGRAMS:" + risky
    return True, ""
