import pytest

from personal_dc.policy import Policy, PolicyError


def test_repo_root_is_allowed():
    path = Policy().resolve_path(r"D:\Repo\Personal_DC")
    assert str(path).casefold().startswith(r"d:\repo".casefold())


def test_windows_directory_is_denied():
    with pytest.raises(PolicyError):
        Policy().resolve_path(r"C:\Windows\System32\drivers\etc\hosts")


def test_git_internal_path_is_denied():
    with pytest.raises(PolicyError):
        Policy().resolve_path(r"D:\Repo\Personal_DC\.git\config")


def test_env_file_is_denied():
    with pytest.raises(PolicyError):
        Policy().resolve_path(r"D:\Repo\Personal_DC\.env")


def test_unknown_executable_is_denied():
    with pytest.raises(PolicyError):
        Policy().validate_command("powershell.exe", ["Get-ChildItem"])
