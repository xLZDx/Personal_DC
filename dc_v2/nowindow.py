"""Process-wide "never show a console window" for everything the Personal DC server launches (Windows only).

Operator request 2026-10-10: a PowerShell/console window flashed for a couple of seconds on every call. Every child process the
server starts (PowerShell, git, python, installers' helpers, ``subprocess.run`` anywhere in the code base, asyncio subprocesses which
use ``subprocess.Popen`` on Windows) now gets ``CREATE_NO_WINDOW`` unless the caller explicitly chose another console mode.
GUI programs are unaffected by the flag. Imported once at server start (``native_personal_mcp``) and by ``dc_v2.winops``.
"""
from __future__ import annotations

import os
import subprocess

CREATE_NEW_CONSOLE = 0x00000010
DETACHED_PROCESS = 0x00000008
CREATE_NO_WINDOW = 0x08000000
_EXPLICIT_CONSOLE_MODES = CREATE_NEW_CONSOLE | DETACHED_PROCESS | CREATE_NO_WINDOW


def with_no_window(kwargs: dict) -> dict:
    """Return kwargs with CREATE_NO_WINDOW added unless the caller already picked a console mode."""
    flags = int(kwargs.get("creationflags") or 0)
    if not flags & _EXPLICIT_CONSOLE_MODES:
        kwargs = {**kwargs, "creationflags": flags | CREATE_NO_WINDOW}
    return kwargs


def install() -> bool:
    """Patch ``subprocess.Popen.__init__`` once; returns True when the patch is (now) active."""
    if os.name != "nt":
        return False
    if getattr(subprocess.Popen, "_pdc_nowindow", False):
        return True
    original = subprocess.Popen.__init__

    def __init__(self, *args, **kwargs):          # noqa: N807 - mirrors the patched signature
        original(self, *args, **with_no_window(kwargs))

    subprocess.Popen.__init__ = __init__          # type: ignore[method-assign]
    subprocess.Popen._pdc_nowindow = True         # type: ignore[attr-defined]
    return True


install()
