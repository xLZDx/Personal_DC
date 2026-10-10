"""Personal profile version is independent of the legacy v1 gateway."""
from __future__ import annotations

from personal_dc import __version__ as base_version
from personal_dc.server import health


def test_v1_default_version_not_changed(monkeypatch):
    monkeypatch.delenv("PERSONAL_DC_PRODUCT_VERSION", raising=False)
    assert base_version == "0.1.0"
    assert health()["version"] == "0.1.0"


def test_v2_native_health_reports_version_2(monkeypatch):
    monkeypatch.setenv("PERSONAL_DC_PRODUCT_VERSION", "2.0.0")
    assert health()["version"] == "2.0.0"
    assert health()["ok"] is True
