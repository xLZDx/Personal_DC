"""GPT review round 2: F01 (git trust boundary), F05 (EDMX), F09 (descendants), ND01 (git deletion), PS01 (scripts)."""
from __future__ import annotations

import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from personal_dc.policy import PolicyError

from dc_v2.winops import command_tools as ct
from dc_v2.winops import deletion_policy, onec_tools, procs, sysrun
from dc_v2.winops import process_tools as pt


def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


@pytest.fixture()
def repo(work):
    _git(work, "init", "-q")
    return work


@pytest.fixture()
def clean_home(monkeypatch, tmp_path):
    home = tmp_path / "home_dir"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    return home


# ------------------------------------------------------------------ F01
@pytest.mark.parametrize("args, free", [
    (["branch"], True), (["branch", "-a"], True), (["branch", "--list", "feat*"], True),
    (["branch", "newbranch"], False), (["branch", "--edit-description"], False), (["branch", "-m", "x"], False),
    (["branch", "-d", "x"], False), (["branch", "--delete", "x"], False),
    (["remote"], True), (["remote", "-v"], True), (["remote", "get-url", "origin"], True),
    (["remote", "update"], False), (["remote", "remove", "origin"], False), (["remote", "add", "x", "y"], False),
    (["add", "a.txt"], True), (["add", "-p"], False), (["add", "--interactive"], False), (["add", "-e"], False),
    (["commit", "-m", "msg"], True), (["commit"], False), (["commit", "--amend", "-m", "x"], False),
    (["commit", "-e", "-m", "x"], False), (["commit", "-F", "f.txt"], False),
    (["switch", "main"], False), (["status"], True), (["log", "-n", "3"], True),
])
def test_git_free_set_is_argument_aware(args, free, repo, clean_home):
    assert pt.guard_git_args(args, repo)[1] is free, args


@pytest.mark.parametrize("line", [
    "[core]\n\teditor = calc.exe\n", "[diff]\n\texternal = calc.exe\n", "[diff \"x\"]\n\ttextconv = calc.exe\n",
    "[filter \"lfs\"]\n\tclean = calc.exe\n", "[alias]\n\tst = !calc.exe\n", "[core]\n\tpager = calc.exe\n",
    "[core]\n\tfsmonitor = calc.exe\n",
])
def test_repo_config_that_launches_programs_disables_free_git(line, repo, clean_home):
    assert pt.guard_git_args(["status"], repo)[1] is True
    config = repo / ".git" / "config"
    config.write_text(config.read_text(encoding="utf-8") + line, encoding="utf-8")
    assert pt.guard_git_args(["status"], repo)[1] is False
    assert pt.guard_git_args(["add", "x"], repo)[1] is False


def test_user_level_config_counts_too(repo, clean_home):
    (clean_home / ".gitconfig").write_text("[core]\n\teditor = notepad.exe\n", encoding="utf-8")
    assert pt.guard_git_args(["status"], repo)[1] is False


# ------------------------------------------------------------------ ND01
@pytest.mark.parametrize("command", [
    "git branch --delete feature", "git branch -D feature", "git branch -d feature", "git branch --del x",
    "git branch -fd x", "git remote remove origin", "git remote rm origin", "git remote prune origin",
    "git reset --hard", "git reset --hard HEAD~1", "git clean -fd", "git rm a.txt", "git tag -d v1",
    "git tag --delete v1", "git stash drop", "git stash clear", "git push origin --delete x", "git push origin :x",
    "git push --prune", "git checkout -- .", "git restore a.txt", "git worktree remove x", "git gc --prune=now",
    "git reflog expire --all", "git update-ref -d refs/heads/x", "git -C repo branch --delete x",
    "git.exe branch --delete x", "git submodule deinit x",
])
def test_destructive_git_forms_are_denied(command):
    with pytest.raises(PolicyError, match="DELETION_NOT_ALLOWED"):
        deletion_policy.deny_deletion(command)
    with pytest.raises(PolicyError, match="DELETION_NOT_ALLOWED"):
        deletion_policy.deny_deletion_argv("git.exe", command.split()[1:])


@pytest.mark.parametrize("command", ["git status", "git log -n 5", "git branch -a", "git commit -m x", "git add -A",
                                     "git diff --stat", "git restore --staged a.txt", "git push origin main"])
def test_benign_git_forms_are_not_denied(command):
    deletion_policy.deny_deletion(command)


# ------------------------------------------------------------------ F05
EDMX = "http://schemas.microsoft.com/ado/2007/06/edmx"


@pytest.mark.parametrize("body, ok", [
    (b"<html></html>", False),
    (b"<root><EntityType/><EntitySet Name='a'/></root>", False),
    (b"<edmx:Edmx xmlns:edmx='urn:evil'><edmx:DataServices><Schema><EntityContainer/></Schema></edmx:DataServices></edmx:Edmx>", False),
    (f"<edmx:Edmx xmlns:edmx='{EDMX}'/>".encode(), False),
    (f"<edmx:Edmx xmlns:edmx='{EDMX}'><edmx:DataServices/></edmx:Edmx>".encode(), False),
    (f"<edmx:Edmx xmlns:edmx='{EDMX}'><edmx:DataServices><Schema/></edmx:DataServices></edmx:Edmx>".encode(), False),
    (f"<edmx:Edmx xmlns:edmx='{EDMX}'><edmx:DataServices><Schema><EntityContainer Name='C'/></Schema>"
     f"</edmx:DataServices></edmx:Edmx>".encode(), True),
])
def test_edmx_structure_is_validated(body, ok):
    error = onec_tools._edmx_structure_error(onec_tools._parse_xml_safe(body))
    assert (error is None) is ok, error


# ------------------------------------------------------------------ F09
def test_more_than_100_descendants_are_tracked_and_overflow_is_flagged(monkeypatch):
    monkeypatch.setattr(procs, "creation_time", lambda pid: pid * 7)
    managed = SimpleNamespace(meta={"pid": 1, "orphans": []}, lock=threading.RLock(), save=lambda: None)
    assert pt._record_descendants(managed, list(range(1000, 1130))) is True
    assert len(managed.meta["orphans"]) == 130 and "orphans_truncated" not in managed.meta
    monkeypatch.setattr(pt, "MAX_TRACKED_DESCENDANTS", 135)
    assert pt._record_descendants(managed, list(range(2000, 2010))) is True
    assert len(managed.meta["orphans"]) == 135 and managed.meta["orphans_truncated"] is True


def test_record_descendants_skips_root_and_duplicates(monkeypatch):
    monkeypatch.setattr(procs, "creation_time", lambda pid: pid + 1)
    managed = SimpleNamespace(meta={"pid": 5, "orphans": []}, lock=threading.RLock(), save=lambda: None)
    assert pt._record_descendants(managed, [5, 6, 6]) is True
    assert [o["pid"] for o in managed.meta["orphans"]] == [6]
    assert pt._record_descendants(managed, [5, 6]) is False


# ------------------------------------------------------------------ PS01
def test_unapproved_powershell_never_persists_a_script(isolated_state, work, approvals_ready):
    for i in range(30):
        result = ct.command_execute(f"Write-Output {i}", shell="powershell", cwd=str(work), mode="workspace_write")
        assert result["status"] == "APPROVAL_REQUIRED"
    scripts = isolated_state / "scripts"
    assert not scripts.exists() or not list(scripts.glob("*.ps1"))


def test_script_file_is_hash_verified_before_launch(isolated_state):
    text = "Write-Output approved"
    path = sysrun.script_file(text)
    sysrun.verify_script_file(path, text)
    path.write_bytes(path.read_bytes() + b"\r\nWrite-Output tampered")
    with pytest.raises(PolicyError, match="SCRIPT_FILE_CHANGED_BEFORE_LAUNCH"):
        sysrun.verify_script_file(path, text)


def test_script_cache_is_bounded(isolated_state, monkeypatch):
    monkeypatch.setattr(sysrun, "SCRIPT_MAX_FILES", 10)
    for i in range(30):
        sysrun._PRUNE_STATE["last"] = 0.0
        sysrun.script_file(f"Write-Output {i}")
    assert len(list((isolated_state / "scripts").glob("*.ps1"))) <= 11
