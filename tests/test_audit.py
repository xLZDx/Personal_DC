from personal_dc.audit import _redact


def test_redacts_secret_fields():
    value = {
        "token": "abc",
        "nested": {"api_key": "def", "safe": "ok"},
    }
    redacted = _redact(value)
    assert redacted["token"] == "***REDACTED***"
    assert redacted["nested"]["api_key"] == "***REDACTED***"
    assert redacted["nested"]["safe"] == "ok"
