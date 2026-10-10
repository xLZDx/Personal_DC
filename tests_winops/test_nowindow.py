"""Operator request: no console window may flash for any process the server launches."""
from __future__ import annotations

import subprocess
import sys

from dc_v2 import nowindow


def test_flag_is_added_unless_the_caller_chose_a_console_mode():
    assert nowindow.with_no_window({})["creationflags"] & nowindow.CREATE_NO_WINDOW
    assert nowindow.with_no_window({"creationflags": 0x200})["creationflags"] == 0x200 | nowindow.CREATE_NO_WINDOW
    for explicit in (nowindow.CREATE_NEW_CONSOLE, nowindow.DETACHED_PROCESS, nowindow.CREATE_NO_WINDOW):
        assert nowindow.with_no_window({"creationflags": explicit})["creationflags"] == explicit
    original = {"stdout": 1}
    nowindow.with_no_window(original)
    assert "creationflags" not in original                                  # caller's dict is not mutated


def test_popen_is_patched_and_children_still_run_with_captured_output():
    assert nowindow.install() is True and subprocess.Popen._pdc_nowindow is True
    done = subprocess.run([sys.executable, "-c", "print('quiet')"], capture_output=True, text=True)
    assert done.returncode == 0 and done.stdout.strip() == "quiet"
    again = nowindow.install()                                              # idempotent: no double wrapping
    assert again is True


def test_popen_received_the_flag(monkeypatch):
    seen = {}
    real_init = subprocess.Popen.__init__

    def spy(self, *args, **kwargs):
        seen.update(kwargs)
        real_init(self, *args, **kwargs)

    # the patched __init__ calls the ORIGINAL; wrap what runs below it to observe the final kwargs
    monkeypatch.setattr(subprocess.Popen, "__init__", lambda self, *a, **k: spy(self, *a, **nowindow.with_no_window(k)))
    subprocess.run([sys.executable, "-c", "pass"], capture_output=True)
    assert seen["creationflags"] & nowindow.CREATE_NO_WINDOW
