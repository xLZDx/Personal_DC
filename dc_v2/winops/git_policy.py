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

import re
from pathlib import Path

# Any section with these names is a program-launching surface (filter drivers, aliases, credential helpers, ...).
_RISKY_SECTIONS = {"filter", "alias", "credential", "include", "includeif", "url", "difftool", "mergetool", "pager",
                   "uploadpack", "gpg"}
# Individual keys ("section.key" or "section.subsection.key") that make git run a program.
_RISKY_KEY = re.compile(
    r"(?i)^(core\.(editor|pager|fsmonitor|hookspath|sshcommand|askpass|gitproxy|attributesfile)|"
    r"sequence\.editor|diff\.(external|tool|guitool)|diff\..*\.(textconv|command)|merge\.tool|merge\..*\.driver|"
    r"commit\.gpgsign|web\.browser|help\.browser|http\.(proxy|sslcommand|cookiefile)|"
    r"credential\..*|protocol\..*\.allow)$")

_READ_ONLY = {"status", "diff", "log", "show", "rev-parse", "ls-files", "blame", "describe", "shortlog"}
# Listing-only options for ``git branch``; every other form (create/delete/rename/edit/upstream) needs approval.
_BRANCH_LIST = {"-a", "-r", "-v", "-vv", "--all", "--remotes", "--list", "-l", "--show-current", "--verbose",
                "--no-color", "--color", "--contains", "--no-contains", "--merged", "--no-merged", "--sort",
                "--format", "--points-at"}
_ADD_FORBIDDEN = {"--interactive", "--patch", "--edit"}
_COMMIT_FORBIDDEN = {"--edit", "--template", "--file", "--reuse-message", "--reedit-message", "--fixup", "--squash",
                     "--amend", "--interactive", "--patch", "--all-from"}


def _config_files(cwd: Path) -> list[Path]:
    files = [Path.home() / ".gitconfig", Path.home() / ".config" / "git" / "config"]
    git = cwd / ".git"
    if git.is_dir():
        files.append(git / "config")
    return files


def config_launches_programs(cwd: Path) -> str | None:
    """Return the first program-launching setting found in the repo/user git config, or None."""
    if (cwd / ".git").is_file():                 # gitfile redirect (worktree/submodule): real config location unknown
        return "GITFILE_REDIRECT"
    for path in _config_files(cwd):
        try:
            if not path.is_file():
                continue
            if path.stat().st_size > 512 * 1024:
                return "CONFIG_TOO_LARGE"
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return "CONFIG_UNREADABLE"
        section = ""
        for raw in text.splitlines():
            line = raw.strip()
            if line.startswith("[") and "]" in line:
                header = line[1:line.index("]")].strip()
                match = re.match(r'^([A-Za-z0-9.-]+)\s+"(.*)"$', header)
                name, sub = (match.group(1), match.group(2)) if match else (header, "")
                if name.casefold() in _RISKY_SECTIONS:
                    return name
                section = name + ("." + sub if sub else "")
            elif "=" in line and not line.startswith(("#", ";")) and section:
                key = line.split("=", 1)[0].strip()
                if _RISKY_KEY.match(f"{section}.{key}"):
                    return f"{section}.{key}"
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


def git_is_free(sub: str, args: list[str], cwd: Path | None, free_set: set[str]) -> tuple[bool, str]:
    """Approval-free eligibility; returns (free, reason-when-not)."""
    if sub not in free_set:
        return False, "SUBCOMMAND_NOT_IN_FREE_SET"
    if not args_allowed_for_free(sub, args):
        return False, "ARGUMENTS_NOT_IN_FREE_ALLOWLIST"
    if cwd is not None:
        risky = config_launches_programs(cwd)
        if risky:
            return False, "CONFIG_LAUNCHES_PROGRAMS:" + risky
    return True, ""
