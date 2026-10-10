"""GPT review round 2: F01 (git trust boundary), F05 (EDMX), F09 (descendants), ND01 (git deletion), PS01 (scripts)."""
from __future__ import annotations

import os
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from personal_dc.policy import PolicyError

from dc_v2.winops import command_tools as ct
from dc_v2.winops import deletion_policy, git_policy, onec_tools, procs, sysrun
from dc_v2.winops import process_tools as pt


def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


@pytest.fixture()
def repo(work):
    _git(work, "init", "-q")
    return work


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
def test_git_free_set_is_argument_aware(args, free, repo):
    assert pt.guard_git_args(args, repo)[1] is free, args


@pytest.mark.parametrize("line", [
    "[core]\n\teditor = calc.exe\n", "[diff]\n\texternal = calc.exe\n", "[diff \"x\"]\n\ttextconv = calc.exe\n",
    "[filter \"lfs\"]\n\tclean = calc.exe\n", "[alias]\n\tst = !calc.exe\n", "[core]\n\tpager = calc.exe\n",
    "[core]\n\tfsmonitor = calc.exe\n",
])
def test_repo_config_that_launches_programs_disables_free_git(line, repo):
    assert pt.guard_git_args(["status"], repo)[1] is True
    config = repo / ".git" / "config"
    config.write_text(config.read_text(encoding="utf-8") + line, encoding="utf-8")
    assert pt.guard_git_args(["status"], repo)[1] is False
    assert pt.guard_git_args(["add", "x"], repo)[1] is False


def test_listing_trusts_only_repository_independent_scope_from_an_owned_file():
    owned = {git_policy._norm("C:/Program Files/Git/etc/gitconfig"), git_policy._norm("C:/Users/u/.gitconfig")}
    sysf, home, evil = "file:C:/Program Files/Git/etc/gitconfig", "file:C:/Users/u/.gitconfig", "file:D:/work/repo/evil.cfg"
    tab = chr(9)
    ok = (f"system{tab}{sysf}{tab}filter.lfs.clean=git-lfs clean\nglobal{tab}{sysf}{tab}credential.helper=manager\n"
          f"global{tab}{home}{tab}filter.lfs.smudge=git-lfs smudge\nlocal{tab}file:D:/work/repo/.git/config{tab}core.bare=false\n")
    assert git_policy.config_risk_from_listing(ok, owned) is None
    # same key, global scope, but pulled in from a repository-writable file through include/includeIf
    assert git_policy.config_risk_from_listing(ok + f"global{tab}{evil}{tab}filter.x.clean=calc.exe\n", owned) == "filter.x.clean"
    assert git_policy.config_risk_from_listing(f"local{tab}{sysf}{tab}core.editor=calc.exe\n", owned) == "core.editor"
    assert git_policy.config_risk_from_listing(f"command{tab}command line:{tab}core.editor=calc.exe\n", owned) == "core.editor"
    assert git_policy.config_risk_from_listing(f"global{tab}file:C:/Users/u/.gitconfig2{tab}alias.x=!calc\n", owned) == "alias.x"
    assert git_policy.config_risk_from_listing("filter.lfs.clean=x\n", owned) == "filter.lfs.clean"   # no provenance: risky
    assert git_policy.config_risk_from_listing(f"global{tab}{sysf}{tab}filter.lfs.clean=x\n") == "filter.lfs.clean"  # no trusted set


def test_real_git_for_windows_system_config_does_not_disable_free_git(repo):
    assert pt.guard_git_args(["status"], repo)[1] is True


@pytest.mark.parametrize("conditional", [False, True])
def test_global_include_of_a_repository_writable_file_is_untrusted_and_never_runs(conditional, repo, tmp_path, monkeypatch):
    sentinel = repo / "filter-ran.txt"
    script = repo / "filt.cmd"
    script.write_text(f'@echo ran> "{sentinel}"\r\n@more\r\n', encoding="utf-8")
    evil = repo / "evil.gitconfig"
    evil.write_text(f'[filter "x"]\n\tclean = {script.as_posix()}\n', encoding="utf-8")
    (repo / ".gitattributes").write_text("* filter=x\n", encoding="utf-8")
    (repo / "f.txt").write_text("data\n", encoding="utf-8")
    home = tmp_path / "userhome"
    home.mkdir()
    header = f'[includeIf "gitdir/i:{repo.as_posix()}/"]' if conditional else "[include]"
    (home / ".gitconfig").write_text(f"{header}\n\tpath = {evil.as_posix()}\n", encoding="utf-8")
    monkeypatch.setenv("USERPROFILE", str(home))
    assert pt.git_config_risk(repo) == "filter.x.clean"
    assert pt.guard_git_args(["add", "f.txt"], repo)[1] is False
    via_exec = ct.command_execute("", shell="exec", argv=["git.exe", "add", "f.txt"], cwd=str(repo), mode="workspace_write")
    assert via_exec["status"] == "APPROVAL_REQUIRED"
    via_start = pt.process_start("git.exe", ["add", "f.txt"], cwd=str(repo), mode="workspace_write")
    assert via_start["status"] == "APPROVAL_REQUIRED"
    assert not sentinel.exists()


def test_filter_in_a_parent_repo_is_found_from_a_nested_directory_and_never_runs(repo):
    sentinel = repo / "filter-ran.txt"
    script = repo / "filt.cmd"
    script.write_text(f'@echo ran> "{sentinel}"\r\n@more\r\n', encoding="utf-8")
    config = repo / ".git" / "config"
    config.write_text(config.read_text(encoding="utf-8") + f'[filter "x"]\n\tclean = {script.as_posix()}\n', encoding="utf-8")
    (repo / ".gitattributes").write_text("* filter=x\n", encoding="utf-8")
    nested = repo / "a" / "b"
    nested.mkdir(parents=True)
    (nested / "f.txt").write_text("data\n", encoding="utf-8")
    assert pt.guard_git_args(["add", "f.txt"], nested)[1] is False
    assert pt.guard_git_args(["status"], nested)[1] is False
    via_exec = ct.command_execute("", shell="exec", argv=["git.exe", "add", "f.txt"], cwd=str(nested), mode="workspace_write")
    assert via_exec["status"] == "APPROVAL_REQUIRED"
    via_start = pt.process_start("git.exe", ["add", "f.txt"], cwd=str(nested), mode="workspace_write")
    assert via_start["status"] == "APPROVAL_REQUIRED"
    assert not sentinel.exists()


def test_core_worktree_pointing_outside_allowed_roots_is_never_free(repo, tmp_path):
    private = tmp_path / "private"                       # outside the allowed root (tmp_path/work)
    private.mkdir()
    (private / "private.txt").write_text("secret\n", encoding="utf-8")
    config = repo / ".git" / "config"
    config.write_text(config.read_text(encoding="utf-8") + f"[core]\n\tworktree = {private.as_posix()}\n", encoding="utf-8")
    for args in (["add", "-A"], ["status"], ["show", ":private.txt"], ["ls-files"]):
        assert pt.guard_git_args(args, repo)[1] is False, args
    via_exec = ct.command_execute("", shell="exec", argv=["git.exe", "add", "-A"], cwd=str(repo), mode="workspace_write")
    assert via_exec["status"] == "APPROVAL_REQUIRED"
    via_start = pt.process_start("git.exe", ["add", "-A"], cwd=str(repo), mode="workspace_write")
    assert via_start["status"] == "APPROVAL_REQUIRED"
    listed = subprocess.run(["git", "ls-files", "--cached"], cwd=repo, capture_output=True, text=True,
                            env={**os.environ, "GIT_WORK_TREE": str(repo)})
    assert "private.txt" not in listed.stdout            # nothing was staged from outside the roots


def test_gitdir_redirected_outside_allowed_roots_is_never_free(work, tmp_path):
    outside = tmp_path / "elsewhere" / "gd"
    outside.parent.mkdir()
    redirected = work / "r2"
    redirected.mkdir()
    subprocess.run(["git", "init", "-q", f"--separate-git-dir={outside}", str(redirected)], check=True, capture_output=True)
    assert (redirected / ".git").is_file()
    assert pt.guard_git_args(["status"], redirected)[1] is False


def test_core_worktree_pointing_outside_allowed_roots_is_never_free(repo, tmp_path):
    private = tmp_path / "private"                       # outside the allowed root (tmp_path/work)
    private.mkdir()
    (private / "private.txt").write_text("secret\n", encoding="utf-8")
    config = repo / ".git" / "config"
    config.write_text(config.read_text(encoding="utf-8") + f"[core]\n\tworktree = {private.as_posix()}\n", encoding="utf-8")
    for args in (["add", "-A"], ["status"], ["show", ":private.txt"], ["ls-files"]):
        assert pt.guard_git_args(args, repo)[1] is False, args
    via_exec = ct.command_execute("", shell="exec", argv=["git.exe", "add", "-A"], cwd=str(repo), mode="workspace_write")
    assert via_exec["status"] == "APPROVAL_REQUIRED"
    via_start = pt.process_start("git.exe", ["add", "-A"], cwd=str(repo), mode="workspace_write")
    assert via_start["status"] == "APPROVAL_REQUIRED"
    listed = subprocess.run(["git", "ls-files", "--cached"], cwd=repo, capture_output=True, text=True,
                            env={**os.environ, "GIT_WORK_TREE": str(repo)})
    assert "private.txt" not in listed.stdout            # nothing was staged from outside the roots


def test_gitdir_redirected_outside_allowed_roots_is_never_free(work, tmp_path):
    outside = tmp_path / "elsewhere" / "gd"
    outside.parent.mkdir()
    redirected = work / "r2"
    redirected.mkdir()
    subprocess.run(["git", "init", "-q", f"--separate-git-dir={outside}", str(redirected)], check=True, capture_output=True)
    assert (redirected / ".git").is_file()
    assert pt.guard_git_args(["status"], redirected)[1] is False


def _repo_with_commit(path):
    path.mkdir(parents=True)
    subprocess.run(["git", "init", "-q"], cwd=path, check=True, capture_output=True)
    (path / "secrets.txt").write_text("PRIVATE-OBJECT-SENTINEL\n", encoding="utf-8")
    ident = ["-c", "user.name=t", "-c", "user.email=t@example.com"]
    subprocess.run(["git", *ident, "add", "."], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", *ident, "commit", "-q", "-m", "x"], cwd=path, check=True, capture_output=True)
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=path, check=True, capture_output=True, text=True).stdout.strip()


def test_alternate_object_store_outside_allowed_roots_is_never_free(repo, tmp_path):
    outside = tmp_path / "private_repo"
    commit = _repo_with_commit(outside)
    alternates = repo / ".git" / "objects" / "info" / "alternates"
    alternates.parent.mkdir(parents=True, exist_ok=True)
    alternates.write_text(str((outside / ".git" / "objects")) + "\n", encoding="utf-8")
    for args in (["show", f"{commit}:secrets.txt"], ["log", "--all"], ["status"]):
        assert pt.guard_git_args(args, repo)[1] is False, args
    via_exec = ct.command_execute("", shell="exec", argv=["git.exe", "show", f"{commit}:secrets.txt"], cwd=str(repo),
                                  mode="workspace_write")
    assert via_exec["status"] == "APPROVAL_REQUIRED"
    via_start = pt.process_start("git.exe", ["show", f"{commit}:secrets.txt"], cwd=str(repo), mode="workspace_write")
    assert via_start["status"] == "APPROVAL_REQUIRED"


def test_alternates_chain_and_odd_forms_fail_closed_but_contained_ones_stay_free(work, tmp_path):
    inside_a = work / "a"
    inside_b = work / "b"
    for p in (inside_a, inside_b):
        p.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=p, check=True, capture_output=True)
    info = inside_a / ".git" / "objects" / "info"
    info.mkdir(parents=True, exist_ok=True)
    (info / "alternates").write_text(str(inside_b / ".git" / "objects") + "\n", encoding="utf-8")
    assert pt.guard_git_args(["status"], inside_a)[1] is True                    # contained alternate: still free
    (inside_b / ".git" / "objects" / "info").mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=outside, check=True, capture_output=True)
    (inside_b / ".git" / "objects" / "info" / "alternates").write_text(
        str(outside / ".git" / "objects") + "\n", encoding="utf-8")              # recursive alternate leaves the roots
    assert pt.guard_git_args(["status"], inside_a)[1] is False
    (info / "alternates").write_text("../../not-a-git-objects-dir\n", encoding="utf-8")
    assert pt.guard_git_args(["status"], inside_a)[1] is False
    (info / "alternates").unlink()
    (info / "http-alternates").write_text("http://example.invalid/objects\n", encoding="utf-8")
    assert pt.guard_git_args(["status"], inside_a)[1] is False


def test_objects_directory_redirected_by_a_junction_is_never_free(repo, tmp_path, make_junction):
    outside = tmp_path / "private_repo"
    commit = _repo_with_commit(outside)
    objects = repo / ".git" / "objects"
    for child in sorted(objects.rglob("*"), reverse=True):                   # empty the real store, then redirect it
        child.rmdir() if child.is_dir() else child.unlink()
    objects.rmdir()
    make_junction(objects, outside / ".git" / "objects")
    assert pt.guard_git_args(["status"], repo)[1] is False
    for args in (["show", f"{commit}:secrets.txt"], ["log", "--all"]):
        assert pt.guard_git_args(args, repo)[1] is False, args
    via_exec = ct.command_execute("", shell="exec", argv=["git.exe", "show", f"{commit}:secrets.txt"], cwd=str(repo),
                                  mode="workspace_write")
    assert via_exec["status"] == "APPROVAL_REQUIRED"
    via_start = pt.process_start("git.exe", ["show", f"{commit}:secrets.txt"], cwd=str(repo), mode="workspace_write")
    assert via_start["status"] == "APPROVAL_REQUIRED"


def test_worktree_junction_into_another_directory_is_never_free(repo, tmp_path, make_junction):
    private = tmp_path / "private_dir"
    private.mkdir()
    (private / "private.txt").write_text("secret\n", encoding="utf-8")
    assert pt.guard_git_args(["add", "-A"], repo)[1] is True
    make_junction(repo / "link", private)
    assert pt.guard_git_args(["add", "-A"], repo)[1] is False
    via_exec = ct.command_execute("", shell="exec", argv=["git.exe", "add", "-A"], cwd=str(repo), mode="workspace_write")
    assert via_exec["status"] == "APPROVAL_REQUIRED"
    listed = subprocess.run(["git", "ls-files", "--cached"], cwd=repo, capture_output=True, text=True)
    assert "private.txt" not in listed.stdout


def test_alternate_store_reached_through_a_junction_is_never_free(work, tmp_path, make_junction):
    inside_a, inside_b = work / "a", work / "b"
    for p in (inside_a, inside_b):
        p.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=p, check=True, capture_output=True)
    outside = tmp_path / "private_repo"
    _repo_with_commit(outside)
    objects_b = inside_b / ".git" / "objects"
    for child in sorted(objects_b.rglob("*"), reverse=True):
        child.rmdir() if child.is_dir() else child.unlink()
    objects_b.rmdir()
    make_junction(objects_b, outside / ".git" / "objects")
    info = inside_a / ".git" / "objects" / "info"
    info.mkdir(parents=True, exist_ok=True)
    (info / "alternates").write_text(str(objects_b) + "\n", encoding="utf-8")
    assert pt.guard_git_args(["status"], inside_a)[1] is False


def test_unreadable_git_config_means_not_free(tmp_path, monkeypatch):
    plain = tmp_path / "work" / "plain"                  # not a repository: git config --list still works (global)
    plain.mkdir(parents=True)
    monkeypatch.setattr(pt, "resolve_exe", lambda *a, **k: (_ for _ in ()).throw(PolicyError("EXECUTABLE_NOT_FOUND")))
    assert pt.guard_git_args(["status"], plain)[1] is False


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


EDM = "http://schemas.microsoft.com/ado/2009/11/edm"
GOOD = (f"<edmx:Edmx Version='1.0' xmlns:edmx='{EDMX}'><edmx:DataServices><Schema Namespace='N' xmlns='{EDM}'>"
        f"<EntityContainer Name='C'/></Schema></edmx:DataServices></edmx:Edmx>").encode()


@pytest.mark.parametrize("body, ok", [
    (b"<html></html>", False),
    (b"<root><EntityType/><EntitySet Name='a'/></root>", False),
    (b"<edmx:Edmx Version='1.0' xmlns:edmx='urn:evil'><edmx:DataServices><Schema Namespace='N'><EntityContainer Name='C'/>"
     b"</Schema></edmx:DataServices></edmx:Edmx>", False),
    (f"<edmx:Edmx Version='1.0' xmlns:edmx='{EDMX}'/>".encode(), False),
    (f"<edmx:Edmx Version='1.0' xmlns:edmx='{EDMX}'><edmx:DataServices/></edmx:Edmx>".encode(), False),
    (f"<edmx:Edmx Version='1.0' xmlns:edmx='{EDMX}'><edmx:DataServices><Schema xmlns='{EDM}' Namespace='N'/>"
     f"</edmx:DataServices></edmx:Edmx>".encode(), False),
    # wrapper is valid but Schema/EntityContainer carry no EDM namespace
    (f"<edmx:Edmx Version='1.0' xmlns:edmx='{EDMX}'><edmx:DataServices><Schema Namespace='N'><EntityContainer Name='C'/>"
     f"</Schema></edmx:DataServices></edmx:Edmx>".encode(), False),
    (GOOD.replace(b" Namespace='N'", b""), False),                          # schema without Namespace attribute
    (GOOD.replace(b"Name='C'", b""), False),                                # container without Name
    (GOOD.replace(b" Version='1.0'", b""), False),                          # Edmx without Version
    (GOOD.replace(b"'1.0'", b"'bogus'"), False),
    (GOOD.replace(b"'1.0'", b"'999.0'"), False),
    (GOOD.replace(b"'1.0'", b"'4.0'"), False),                              # V4 version in the legacy namespace
    (GOOD.replace(b"2009/11/edm", b"2008/09/edm"), True),                  # other legacy EDM namespace is fine
    (GOOD.replace(b"xmlns='" + EDM.encode() + b"'", b"xmlns='http://docs.oasis-open.org/odata/ns/edm'"), False),  # EDM/EDMX generation mismatch
    (b"<edmx:Edmx Version='5.0' xmlns:edmx='http://docs.oasis-open.org/odata/ns/edmx'><edmx:DataServices>"
     b"<Schema Namespace='N' xmlns='http://docs.oasis-open.org/odata/ns/edm'><EntityContainer Name='C'/></Schema>"
     b"</edmx:DataServices></edmx:Edmx>", False),
    (b"<edmx:Edmx Version='4.0' xmlns:edmx='http://docs.oasis-open.org/odata/ns/edmx'><edmx:DataServices>"
     b"<Schema Namespace='N' xmlns='" + EDM.encode() + b"'><EntityContainer Name='C'/></Schema>"
     b"</edmx:DataServices></edmx:Edmx>", False),
    (GOOD, True),
    (b"<edmx:Edmx Version='4.0' xmlns:edmx='http://docs.oasis-open.org/odata/ns/edmx'><edmx:DataServices>"
     b"<Schema Namespace='N' xmlns='http://docs.oasis-open.org/odata/ns/edm'><EntityContainer Name='C'/></Schema>"
     b"</edmx:DataServices></edmx:Edmx>", True),
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


def test_record_descendants_skips_root_and_duplicates_but_not_a_reused_pid(monkeypatch):
    created = {6: 100}
    monkeypatch.setattr(procs, "creation_time", lambda pid: created.get(pid, pid + 1))
    managed = SimpleNamespace(meta={"pid": 5, "orphans": []}, lock=threading.RLock(), save=lambda: None)
    assert pt._record_descendants(managed, [5, 6, 6]) is True
    assert [o["pid"] for o in managed.meta["orphans"]] == [6]
    assert pt._record_descendants(managed, [5, 6]) is False
    created[6] = 200                                       # same PID, new process: a different identity
    assert pt._record_descendants(managed, [6]) is True
    assert [(o["pid"], o["created"]) for o in managed.meta["orphans"]] == [(6, 100), (6, 200)]


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


def test_script_cache_quota_is_an_admission_limit_without_any_clock(isolated_state, monkeypatch):
    monkeypatch.setattr(sysrun, "SCRIPT_MAX_FILES", 10)
    for i in range(250):                                  # burst: no pruning clock to reset
        sysrun.script_file(f"Write-Output {i}")
        assert len(list((isolated_state / "scripts").glob("*.ps1"))) <= 10
    assert (isolated_state / "scripts" / (__import__("hashlib").sha256(b"\xef\xbb\xbf" + b"Write-Output 249").hexdigest()[:40] + ".ps1")).is_file()


def test_script_cache_byte_quota_and_full_rejection(isolated_state, monkeypatch):
    monkeypatch.setattr(sysrun, "SCRIPT_MAX_BYTES", 4000)
    for i in range(20):
        sysrun.script_file(f"# {i}\n" + "x" * 500)
        total = sum(p.stat().st_size for p in (isolated_state / "scripts").glob("*.ps1"))
        assert total <= 4000
    with pytest.raises(PolicyError, match="SCRIPT_TOO_LARGE"):
        sysrun.script_file("y" * 2000)
    monkeypatch.setattr(sysrun, "SCRIPT_MAX_FILES", 0)
    with pytest.raises(PolicyError, match="SCRIPT_CACHE_FULL"):
        sysrun.script_file("Write-Output new")
