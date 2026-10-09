"""Structural read-only allowlists, trust-mode gating and approval binding for command execution."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from personal_dc.policy import PolicyError

from dc_v2.winops import command_tools as ct
from dc_v2.winops import process_tools as pt

PY = sys.executable
SENT_PW = "Zq9-SENTINEL-argpw-5521"
SENT_BEARER = "bearerSENTINEL99887766"


def _requests(state):
    base = state / "approvals"
    return [json.loads(p.read_text(encoding="utf-8")) for p in base.glob("req-*.json")
            if not p.name.endswith(".grant.json")]


# ------------------------------------------------------- read-only PowerShell
@pytest.mark.parametrize("script", [
    "Get-Process", "Get-Service -Name Spooler", "Get-Process | Sort-Object CPU | Select-Object -First 5",
    "Get-CimInstance Win32_OperatingSystem | ConvertTo-Json", "Get-CimInstance -ClassName Win32_LogicalDisk",
    "Get-CimInstance -Class Win32_BIOS", "Get-CimInstance 'Win32_Processor'",
    "Get-Date", "get-date | Out-String",
])
def test_readonly_powershell_accepts_structural_allowlist(script):
    assert ct.validate_readonly_powershell(script) == script


@pytest.mark.parametrize("script", [
    "Remove-Item C:\\x", "Get-Process; whoami", "Get-Process | ForEach-Object { $_.Kill() }",
    "Get-Process $(whoami)", "Get-Service -ComputerName other", "Get-CimInstance Win32_Process",
    "Get-CimInstance -Namespace root Win32_Share", "Get-Process & calc", "Get-Process > out.txt",
    "get-content C:\\Windows\\win.ini", "Invoke-Expression 'x'", "Get-Process |", "", "x" * 1001,
    "Get-Process | Out-File x", "Get-Service -Name `n",
    "Get-Process (whoami)", "Get-Process -Name \"x\"", "Get-Process -Name 'a$b'", "Get-Process -Name 'a;b'",
    "Get-Process | | Sort-Object", "| Get-Process", "Get-Process | Get-Service",
    "Get-Process | Select-Object | Sort-Object | Sort-Object | Sort-Object | Sort-Object",
])
def test_readonly_powershell_rejects_everything_else(script):
    with pytest.raises(PolicyError):
        ct.validate_readonly_powershell(script)


@pytest.mark.parametrize("script", [
    "Get-Process\nGet-Service", "Get-Process\r\nwhoami", "Get-Process\twhoami", "Get-Process\x0bwhoami",
    "Get-Process\u2028whoami", "Get-Process\u0085whoami", "Get-Process\x00", "Get-Service -Name 'a\nb'",
    "Get-Process \u0405", "Get-Process\u00a0", "Get-Process\x1b[0m",
])
def test_readonly_powershell_newline_and_non_ascii_injection_rejected(script):
    with pytest.raises(PolicyError, match="READONLY_POWERSHELL_CONTROL_CHARACTERS_NOT_ALLOWED"):
        ct.validate_readonly_powershell(script)


@pytest.mark.parametrize("alias", ["gci C:\\", "ls", "dir C:\\", "gc C:\\x", "cat C:\\x", "type C:\\x", "gi C:\\",
                                   "iex 'x'", "gps", "gsv", "gcim Win32_BIOS", "ps", "sort", "select", "ft", "fl",
                                   "% { 1 }", "? { 1 }", "&", "."])
def test_readonly_powershell_aliases_are_not_cmdlets(alias):
    with pytest.raises(PolicyError):
        ct.validate_readonly_powershell(alias)


@pytest.mark.parametrize("param", ["-Comp", "-ComputerName", "-Computer", "-CimS", "-CimSession", "-Cred",
                                   "-Credential", "-Sess", "-Session", "-Asj", "-AsJob", "-Inc", "-IncludeUserName",
                                   "-Mod", "-Module", "-Fil", "-FileVersionInfo", "-Res", "-ResourceUri"])
def test_readonly_powershell_retargeting_parameters_blocked_by_prefix(param):
    """PowerShell accepts any unambiguous abbreviation, so every prefix of a forbidden parameter is refused."""
    with pytest.raises(PolicyError):
        ct.validate_readonly_powershell(f"Get-Service {param} remote-host")


@pytest.mark.parametrize("script", [
    "Get-CimInstance Win32_Process",                                    # not in the class allowlist
    "Get-CimInstance -ClassName Win32_Process",
    "Get-CimInstance -Filter 'Win32_OperatingSystem' Win32_Process",    # allowed name used as a decoy value
    "Get-CimInstance -ClassName Win32_Process Win32_OperatingSystem",
    "Get-CimInstance Win32_OperatingSystem -ClassName Win32_Process",   # allowed positional + denied bound class
    "Get-CimInstance -ClassName Win32_BIOS -ClassName Win32_Process",
    "Get-CimInstance -ClassName Win32_BIOS -Cl Win32_Process",
    "Get-CimInstance -ClassName Win32_BIOS Win32_BIOS",                 # ambiguous double binding
    "Get-CimInstance", "Get-CimInstance -ClassName",
    "Get-CimInstance Win32_OperatingSystem -Namespace root\\cimv2",
    "Get-CimInstance Win32_OperatingSystem -ComputerName other",
    "Get-CimInstance -Query 'select * from Win32_Process'",
])
def test_readonly_cim_decoys_rejected(script):
    with pytest.raises(PolicyError):
        ct.validate_readonly_powershell(script)


@pytest.mark.parametrize("script", ["Get-Service -Name Spooler", "Get-Process -Name explorer"])
def test_readonly_powershell_name_parameter_is_not_confused_with_namespace(script):
    """-Name is the everyday filter of Get-Service/Get-Process; it is a prefix of -Namespace only textually.

    Get-CimInstance's -Namespace is already refused where it matters (that cmdlet is checked separately),
    so rejecting every -Name* abbreviation would make the read-only profile unusable.
    """
    assert ct.validate_readonly_powershell(script) == script


def test_powershell_script_runs_from_a_content_addressed_file_never_encoded_or_interpolated(isolated_state):
    args = ct.powershell_file_args("Get-Date")
    assert "-EncodedCommand" not in args and "-Command" not in args and "Bypass" not in args
    assert args[args.index("-ExecutionPolicy") + 1] == "RemoteSigned" and args[-2] == "-File"
    path = Path(args[-1])
    raw = path.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf") and "Get-Date" in raw.decode("utf-8-sig")
    assert raw.decode("utf-8-sig").startswith("$ProgressPreference")
    assert path.parent == isolated_state / "scripts" and ct.powershell_file_args("Get-Date")[-1] == str(path)
    other = Path(ct.powershell_file_args("Get-Date; 1")[-1])
    assert other != path                                              # different text -> different file


# ---------------------------------------------------- read-only executables
SYS = pt.system32()


@pytest.mark.parametrize("exe, args", [
    ("whoami.exe", []), ("whoami.exe", ["/all"]), ("hostname.exe", []), ("ipconfig.exe", ["/all"]),
    ("tasklist.exe", ["/fo", "csv", "/nh"]), ("sc.exe", ["query", "state=", "all"]),
    ("sc.exe", ["QUERYEX", "Spooler"]), ("where.exe", ["notepad"]),
    ("fsutil.exe", ["volume", "diskfree", "C:"]), ("fsutil.exe", ["fsinfo", "drives"]),
    ("fsutil.exe", ["FSINFO", "NTFSINFO", "C:"]),
])
def test_readonly_exec_accepts_allowlisted_shapes(exe, args):
    ct._validate_readonly_exec(SYS / exe, args)


@pytest.mark.parametrize("exe, args, code", [
    ("whoami.exe", ["/all; calc"], "READONLY_ARGUMENT_NOT_ALLOWED"),
    ("whoami.exe", ["/all", "&", "calc"], "READONLY_ARGUMENT_NOT_ALLOWED"),
    ("whoami.exe", ["$(calc)"], "READONLY_ARGUMENT_NOT_ALLOWED"),
    ("tasklist.exe", ["/s", "other"], "READONLY_ARGUMENT_DENIED"),
    ("tasklist.exe", ["/S", "other"], "READONLY_ARGUMENT_DENIED"),
    ("systeminfo.exe", ["/u", "x"], "READONLY_ARGUMENT_DENIED"),
    ("sc.exe", ["stop", "x"], "READONLY_SUBCOMMAND_NOT_ALLOWED"),
    ("sc.exe", [], "READONLY_SUBCOMMAND_NOT_ALLOWED"),
    ("sc.exe", ["\\\\other", "query"], "READONLY_ARGUMENT_NOT_ALLOWED"),
    ("ipconfig.exe", ["/release"], "READONLY_ARGUMENT_DENIED"),
    ("ipconfig.exe", ["/FLUSHDNS"], "READONLY_ARGUMENT_DENIED"),
    ("where.exe", ["/r", "C:", "x"], "READONLY_ARGUMENT_DENIED"),
    ("where.exe", ["\\\\server\\share\\x"], "READONLY_ARGUMENT_NOT_ALLOWED"),
    ("where.exe", ["C:\\Windows"], "READONLY_ARGUMENT_NOT_ALLOWED"),
    ("netstat.exe", ["-ano", "\n"], "READONLY_ARGUMENT_NOT_ALLOWED"),
    ("fsutil.exe", ["file", "createnew", "x", "100"], "READONLY_SUBCOMMAND_NOT_ALLOWED"),
    ("fsutil.exe", ["volume", "dismount", "C:"], "READONLY_SUBCOMMAND_NOT_ALLOWED"),
    ("fsutil.exe", ["volume"], "READONLY_SUBCOMMAND_NOT_ALLOWED"),
    ("fsutil.exe", ["behavior", "set", "disablelastaccess", "1"], "READONLY_SUBCOMMAND_NOT_ALLOWED"),
    ("fsutil.exe", ["fsinfo", "drives\\\\x"], "READONLY_ARGUMENT_NOT_ALLOWED"),
    ("fsutil.exe", ["usn", "deletejournal", "C:"], "READONLY_SUBCOMMAND_NOT_ALLOWED"),
])
def test_readonly_exec_rejects_dangerous_shapes(exe, args, code):
    with pytest.raises(PolicyError, match=code):
        ct._validate_readonly_exec(SYS / exe, args)


@pytest.mark.parametrize("exe", ["cmd.exe", "powershell.exe", "python.exe", "reg.exe", "net.exe", "taskkill.exe"])
def test_readonly_exec_rejects_non_allowlisted_executables(exe):
    with pytest.raises(PolicyError, match="READONLY_EXECUTABLE_NOT_ALLOWED"):
        ct._validate_readonly_exec(SYS / exe, [])


def test_readonly_exec_requires_system32_parent_not_just_the_name(tmp_path):
    decoy = tmp_path / "whoami.exe"
    decoy.write_bytes(b"MZ")
    with pytest.raises(PolicyError, match="READONLY_EXECUTABLE_NOT_ALLOWED"):
        ct._validate_readonly_exec(decoy, [])


def test_readonly_exec_through_command_execute_never_launches_disallowed(work, isolated_state):
    for argv in (["cmd.exe", "/c", "dir"], [PY, "-c", "print(1)"], ["sc.exe", "stop", "x"],
                 ["ipconfig.exe", "/release"], ["tasklist.exe", "/s", "other"], ["whoami.exe", "/all; calc"]):
        with pytest.raises(PolicyError):
            ct.command_execute(shell="exec", argv=argv, mode="read_only")
    assert not list((isolated_state / "procs").glob("prc-*"))       # nothing was ever started


def test_readonly_mode_refuses_environment_and_cmd():
    with pytest.raises(PolicyError, match="ENV_NOT_ALLOWED_IN_READ_ONLY_MODE"):
        ct.command_execute(shell="exec", argv=["whoami.exe"], mode="read_only", env={"MY_FLAG": "1"})
    with pytest.raises(PolicyError, match="CMD_NOT_AVAILABLE_IN_READ_ONLY_MODE"):
        ct.command_execute("dir", shell="cmd", mode="read_only")


def test_unknown_catalog_alias_still_rejected_like_v1():
    with pytest.raises(PolicyError, match="COMMAND_NOT_IN_SAFE_ALLOWLIST"):
        ct.command_execute("powershell.exe -Command whoami")
    with pytest.raises(PolicyError, match="UNKNOWN_SHELL"):
        ct.command_execute("x", shell="bash")
    with pytest.raises(PolicyError, match="UNKNOWN_TRUST_MODE"):
        ct.command_execute("whoami", mode="root")


# ------------------------------------------------- workspace_write and approval
def test_shell_in_workspace_mode_needs_approval(work, approvals_ready):
    out = ct.command_execute("Write-Output hi", shell="powershell", cwd=str(work), mode="workspace_write")
    assert out["status"] == "APPROVAL_REQUIRED" and out["mode"] == "workspace_write"
    out = ct.command_execute("echo hi", shell="cmd", cwd=str(work), mode="workspace_write")
    assert out["status"] == "APPROVAL_REQUIRED"


@pytest.mark.parametrize("command", ["echo hi\r\ncalc", "echo hi\ncalc", "echo hi\rcalc", "echo\x00hi", "", "   "])
def test_cmd_newline_and_nul_injection_rejected(work, approvals_ready, command):
    with pytest.raises(PolicyError, match="INVALID_CMD_COMMAND"):
        ct.command_execute(command, shell="cmd", cwd=str(work), mode="workspace_write")


def test_exec_argument_vector_validation(work, approvals_ready):
    for argv, code in (([], "ARGV_REQUIRED"), (["x.exe"] * 101, "ARGV_REQUIRED"),
                       ([PY, "a\x00b"], "INVALID_ARGUMENTS"), ([PY, "x" * 9000], "INVALID_ARGUMENTS"),
                       ([PY, 5], "INVALID_ARGUMENTS")):
        with pytest.raises(PolicyError, match=code):
            ct.command_execute(shell="exec", argv=argv, cwd=str(work), mode="workspace_write")


def test_interpreters_require_approval_by_default(work, approvals_ready, isolated_state):
    out = ct.command_execute(shell="exec", argv=[PY, "-c", "print(1)"], cwd=str(work), mode="workspace_write")
    assert out["status"] == "APPROVAL_REQUIRED" and out["action"] == "exec.workspace_write"
    assert not list((isolated_state / "procs").glob("prc-*"))


@pytest.mark.parametrize("name", ["python.exe", "pythonw.exe", "py.exe", "node.exe", "npm.cmd", "npm.exe", "pip.exe",
                                  "pip3.exe", "dotnet.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "whoami.exe"])
def test_authorize_launch_trusts_git_only(name, approvals_ready):
    env = pt.build_env()
    folder = pt.trusted_dirs(env)[0]
    params = pt.launch_params(folder / name, [], folder, 30, None, "workspace_write")
    result = pt.authorize_launch("workspace_write", folder / name, env, params, None)
    assert isinstance(result, dict) and result["status"] == "APPROVAL_REQUIRED"
    git = pt.authorize_launch("workspace_write", folder / "git.exe", env,
                              pt.launch_params(folder / "git.exe", ["status"], folder, 30, None, "workspace_write"), None)
    assert git is None                                            # control: the trust list is really consulted


def test_trusted_name_in_untrusted_directory_still_needs_approval(tmp_path, work, approvals_ready):
    env = pt.build_env()
    fake = work / "git.exe"
    params = pt.launch_params(fake, ["status"], work, 30, None, "workspace_write")
    result = pt.authorize_launch("workspace_write", fake, env, params, None)
    assert result["status"] == "APPROVAL_REQUIRED"


def test_forced_approval_and_elevated_mode_ignore_dev_tool_trust(approvals_ready):
    env = pt.build_env()
    folder = pt.trusted_dirs(env)[0]
    params = pt.launch_params(folder / "git.exe", ["push"], folder, 30, None, "workspace_write")
    assert pt.authorize_launch("workspace_write", folder / "git.exe", env, params, None, force_approval=True)["status"] \
        == "APPROVAL_REQUIRED"
    params = pt.launch_params(folder / "git.exe", ["status"], folder, 30, None, "elevated")
    assert pt.authorize_launch("elevated", folder / "git.exe", env, params, None)["status"] == "APPROVAL_REQUIRED"
    with pytest.raises(PolicyError, match="UNKNOWN_TRUST_MODE"):
        pt.authorize_launch("root", folder / "git.exe", env, params, None)


def test_elevated_command_needs_approval_even_for_a_system_tool(work, approvals_ready, isolated_state):
    out = ct.command_execute(shell="exec", argv=["whoami.exe"], cwd=str(work), mode="elevated")
    assert out["status"] == "APPROVAL_REQUIRED" and out["action"] == "exec.elevated"
    assert not list((isolated_state / "procs").glob("prc-*"))


def test_approval_request_never_stores_bearer_or_flagged_argument_secrets(work, approvals_ready, isolated_state):
    ct.command_execute(f'Write-Output "Authorization: Bearer {SENT_BEARER}" # visible-ps-marker',
                       shell="powershell", cwd=str(work), mode="workspace_write")
    ct.command_execute(shell="exec", argv=[PY, "-c", "pass", "--password", SENT_PW, "visible-arg-marker"],
                       cwd=str(work), mode="workspace_write")
    raw = "\n".join(p.read_text(encoding="utf-8") for p in (isolated_state / "approvals").glob("req-*.json"))
    assert "visible-ps-marker" in raw and "visible-arg-marker" in raw           # positive control
    assert SENT_BEARER not in raw and SENT_PW not in raw
    audit_raw = (isolated_state / "audit" / "native-audit.jsonl").read_text(encoding="utf-8")
    assert SENT_BEARER not in audit_raw and SENT_PW not in audit_raw


def test_approval_digest_changes_with_every_launch_parameter(work, approvals_ready, isolated_state):
    def digest(**kw):
        args = dict(shell="exec", argv=[PY, "-c", "pass"], cwd=str(work), mode="workspace_write")
        args.update(kw)
        return ct.command_execute(**args)["digest"]
    base = digest()
    assert digest() == base
    assert digest(argv=[PY, "-c", "pass2"]) != base
    assert digest(timeout_s=31) != base
    assert digest(env={"MY_FLAG": "1"}) != digest(env={"MY_FLAG": "2"})        # env VALUES are bound, not just names
    assert digest(mode="elevated") != base
    (work / "sub").mkdir()
    assert digest(cwd=str(work / "sub")) != base


def test_cwd_outside_roots_rejected(tmp_path, approvals_ready):
    with pytest.raises(PolicyError, match="outside allowed roots"):
        ct.command_execute(shell="exec", argv=[PY, "-c", "pass"], cwd=str(tmp_path), mode="workspace_write")


def test_relative_cwd_resolves_against_process_cwd_then_is_contained(tmp_path, work, approvals_ready, isolated_state,
                                                                    monkeypatch):
    (work / "sub").mkdir()
    monkeypatch.chdir(work)
    out = ct.command_execute(shell="exec", argv=[PY, "-c", "pass"], cwd="sub", mode="workspace_write")
    assert out["status"] == "APPROVAL_REQUIRED"
    request = json.loads(_requests(isolated_state)[0]["params_display"])
    assert request["cwd"] == str((work / "sub").resolve())          # bound to the RESOLVED absolute directory
    monkeypatch.chdir(tmp_path)                                      # same relative text, different base
    with pytest.raises(PolicyError, match="outside allowed roots"):
        ct.command_execute(shell="exec", argv=[PY, "-c", "pass"], cwd="sub", mode="workspace_write")
    monkeypatch.chdir(work)
    with pytest.raises(PolicyError, match="outside allowed roots"):
        ct.command_execute(shell="exec", argv=[PY, "-c", "pass"], cwd="..", mode="workspace_write")


def test_empty_cwd_is_not_the_process_cwd(work, approvals_ready, monkeypatch):
    monkeypatch.chdir(work)
    with pytest.raises(PolicyError):
        ct.command_execute(shell="exec", argv=[PY, "-c", "pass"], cwd="", mode="workspace_write")


def test_cwd_must_be_a_directory(work, approvals_ready):
    (work / "f.txt").write_text("x", encoding="utf-8")
    with pytest.raises(PolicyError, match="CWD_NOT_A_DIRECTORY"):
        ct.command_execute(shell="exec", argv=[PY, "-c", "pass"], cwd=str(work / "f.txt"), mode="workspace_write")


def test_cwd_through_in_root_junction_rejected(work, approvals_ready, make_junction):
    real = work / "real"
    real.mkdir()
    link = make_junction(work / "link", real)
    with pytest.raises(PolicyError, match="REPARSE_POINT_IN_PATH"):
        ct.command_execute(shell="exec", argv=[PY, "-c", "pass"], cwd=str(link), mode="workspace_write")


# ------------------------------------------------------------ exe resolution
def test_bare_exe_never_resolves_from_cwd(work, monkeypatch):
    (work / "evil.exe").write_bytes(b"MZ")
    monkeypatch.chdir(work)
    env = pt.build_env()
    with pytest.raises(PolicyError, match="EXECUTABLE_NOT_FOUND"):
        pt.resolve_exe("evil.exe", env)
    with pytest.raises(PolicyError, match="EXECUTABLE_NOT_FOUND"):
        pt.resolve_exe("evil", env)
    with pytest.raises(PolicyError, match="RELATIVE_EXECUTABLE_NOT_ALLOWED"):
        pt.resolve_exe(".\\evil.exe", env)
    with pytest.raises(PolicyError, match="RELATIVE_EXECUTABLE_NOT_ALLOWED"):
        pt.resolve_exe("sub\\evil.exe", env)
    with pytest.raises(PolicyError, match="EXECUTABLE_NOT_FOUND"):
        ct.command_execute(shell="exec", argv=["evil.exe"], cwd=str(work), mode="workspace_write")


@pytest.mark.parametrize("exe", ["\\\\host\\share\\x.exe", "//host/share/x.exe", "", "a\x00b.exe"])
def test_unc_and_nul_executables_rejected(exe):
    with pytest.raises(PolicyError, match="INVALID_EXECUTABLE"):
        pt.resolve_exe(exe, pt.build_env())


def test_ads_executable_never_resolves():
    with pytest.raises(PolicyError):
        pt.resolve_exe(str(SYS / "cmd.exe") + ":evil", pt.build_env())


def test_bare_name_resolves_only_in_sanitised_path_dirs():
    found = pt.resolve_exe("whoami", pt.build_env())
    assert found.parent == SYS.resolve() and found.name.casefold() == "whoami.exe"


# --------------------------------------------------------------- environment
@pytest.mark.parametrize("name", ["PATH", "COMSPEC", "PDC_V2_BACKEND_KEY", "MY_TOKEN", "A B", "path", "PYTHONPATH",
                                  "NODE_OPTIONS", "GIT_SSH_COMMAND", "NPM_CONFIG_REGISTRY", "PIP_INDEX_URL",
                                  "HTTP_PROXY", "HTTPS_PROXY", "LD_PRELOAD", "DOTNET_STARTUP_HOOKS", "TEMP",
                                  "USERPROFILE", "APPDATA", "SYSTEMROOT", "MY_SECRET", "DB_PASSWORD", "X" * 50,
                                  "ONEC_BASE", "MSBUILD_X", "NUGET_X", "PSMODULEPATH", "JAVA_TOOL_OPTIONS",
                                  "SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "BAD_KEY_NAME",
                                  "SOME_PROXY_URL", "MY_REGISTRY", "MY_INDEX"])
def test_env_isolation_rejects_dangerous_names(name):
    with pytest.raises(PolicyError, match="ENV_VAR_NOT_ALLOWED"):
        pt.build_env({name: "x"})


def test_env_rejects_non_string_and_oversized_values():
    with pytest.raises(PolicyError, match="ENV_VAR_NOT_ALLOWED"):
        pt.build_env({"MY_FLAG": 1})
    with pytest.raises(PolicyError, match="ENV_VAR_NOT_ALLOWED"):
        pt.build_env({"MY_FLAG": "v" * 2049})


def test_env_accepts_harmless_names_and_fingerprint_covers_values():
    assert pt.build_env({"MY_FLAG": "1"})["MY_FLAG"] == "1"
    assert pt.env_fingerprint({"MY_FLAG": "1"}) != pt.env_fingerprint({"MY_FLAG": "2"})
    assert pt.env_fingerprint({"A": "1", "B": "2"}) == pt.env_fingerprint({"B": "2", "A": "1"})
    assert pt.env_fingerprint(None) == pt.env_fingerprint({})


def test_env_does_not_inherit_secrets(monkeypatch):
    monkeypatch.setenv("PDC_V2_BACKEND_KEY", "a" * 64)
    monkeypatch.setenv("CONTROL_PLANE_API_KEY", "k")
    monkeypatch.setenv("MY_VISIBLE_NOT_PASSED", "v")
    env = pt.build_env()
    assert "PDC_V2_BACKEND_KEY" not in env and "CONTROL_PLANE_API_KEY" not in env
    assert "MY_VISIBLE_NOT_PASSED" not in env                      # allowlist passthrough, not "everything but secrets"
    assert "SystemRoot" in env or "SYSTEMROOT" in {k.upper() for k in env}     # control: passthrough does work
    assert env["NoDefaultCurrentDirectoryInExePath"] == "1" and env["PYTHONUTF8"] == "1"


# ----------------------------------------------------------------------- git
@pytest.mark.parametrize("args", [
    ["push", "--force", "origin", "x"], ["push", "-f", "origin", "x"], ["push", "origin", "+main"],
    ["push", "--force-with-lease", "origin", "x"], ["push", "origin", ":main"], ["push", "--delete", "origin", "x"],
    ["push", "-d", "origin", "x"], ["push", "--mirror", "origin"], ["push", "--prune", "origin"],
    ["push", "-uf", "origin", "x"], ["push", "--force-if-includes", "origin", "x"],
    ["-c", "core.sshCommand=calc", "fetch"], ["--version"], ["-C", "x", "status"],
    ["fetch", "--upload-pack=calc"], ["fetch", "--upload-pack", "calc"], ["clone", "--receive-pack=x", "u"],
    ["diff", "--ext-diff"], ["log", "--textconv"], ["status", "--git-dir=x"], ["status", "--work-tree=x"],
    ["status", "--exec-path=x"], ["status", "-c", "x=y"], ["status", "--config-env=a=b"],
    ["config", "user.name", "x"], ["credential", "fill"], ["filter-branch"], ["daemon"], ["http-backend"], [],
])
def test_git_program_forcing_and_force_push_blocked(args):
    with pytest.raises(PolicyError):
        pt.guard_git_args(args)


@pytest.fixture()
def git_repo(work):
    import subprocess
    subprocess.run(["git", "init", "-q"], cwd=work, check=True, capture_output=True)
    return work


def test_git_hardening_and_auto_trust_classification(git_repo):
    hardened, trusted = pt.guard_git_args(["status"], git_repo)
    assert hardened[-1] == "status" and trusted is True
    joined = " ".join(hardened)
    assert "core.fsmonitor=false" in joined and "core.hooksPath=NUL" in joined and "protocol.ext.allow=never" in joined
    for sub in ("push", "fetch", "pull", "clone", "rebase", "reset", "checkout", "merge", "tag"):
        assert pt.guard_git_args([sub, "x"])[1] is False, sub
    assert "core.editor=false" in joined and "core.pager=cat" in joined and "sequence.editor=false" in joined
    for sub in ("status", "diff", "log", "show", "add", "branch", "remote"):
        assert pt.guard_git_args([sub], git_repo)[1] is True, sub
    assert pt.guard_git_args(["status"])[1] is False                         # no cwd: effective config unknown
    assert pt.guard_git_args(["commit"], git_repo)[1] is False                       # no -m: would open an editor
    assert pt.guard_git_args(["commit", "-m", "msg"], git_repo)[1] is True
    assert "--no-ext-diff" in pt.guard_git_args(["diff"], git_repo)[0] and "--no-textconv" in pt.guard_git_args(["log"], git_repo)[0]
    assert pt.guard_git_args(["push", "origin", "main"])[1] is False        # plain push is allowed but never free


def test_command_catalog_is_fixed_and_contains_no_shells():
    assert "whoami" in ct.CATALOG
    assert not [v for v in ct.CATALOG.values() if Path(v[0]).name.casefold() in ("cmd.exe", "powershell.exe")]


# ----------------------------------- git: output-file / no-index options (F01)
@pytest.mark.parametrize("args", [
    ["log", "--output=x.txt"], ["log", "--output", "x.txt"], ["diff", "--out=x.txt"], ["diff", "--ou=x"],
    ["log", "--outp=x"], ["log", "--outpu=x"], ["log", "--OUTPUT=x"], ["log", "--output-indicator-new=+"],
    ["diff", "-ox.txt"], ["diff", "-o", "x.txt"], ["log", "-Ox.txt"], ["grep", "-O", "less"],
    ["diff", "--no-index", "a", "b"], ["diff", "--no-i", "a", "b"], ["diff", "--no-ind", "a", "b"],
    ["diff", "--no-inde=1"], ["grep", "--open-files-in-pager"], ["grep", "--open-files-in-pager=calc"],
    ["grep", "--open-files-in-p=calc"], ["grep", "--ope", "x"],
], ids=lambda a: " ".join(a))
def test_git_output_file_and_noindex_options_denied(args):
    with pytest.raises(PolicyError, match="GIT_OUTPUT_OR_NOINDEX_OPTION_NOT_ALLOWED"):
        pt.guard_git_args(args)


@pytest.mark.parametrize("args", [
    ["log", "--oneline", "-n", "3"], ["status", "-s"], ["diff", "--stat"], ["diff", "--no-color"],
    ["log", "--format=%H", "--", "--output=x"], ["log", "--", "-o", "--no-index"],
])
def test_git_benign_options_and_args_after_double_dash_are_not_inspected(args, git_repo):
    hardened, trusted = pt.guard_git_args(args, git_repo)
    injected = {"--no-ext-diff", "--no-textconv"}              # the policy adds these after the subcommand
    assert trusted is True and [a for a in hardened if a not in injected][-len(args):] == args
