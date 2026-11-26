from governed.redaction import redact_obj, redact_text


def test_redacts_secrets_and_pii():
    t = "login failed email=user42@example.com password=hunter2 key sk_test_51ABC Authorization: Bearer abc.def.ghi"
    out = redact_text(t)
    for leaked in ("hunter2", "user42@example.com", "sk_test_51ABC", "abc.def.ghi"):
        assert leaked not in out


def test_redacts_nested_and_sensitive_keys():
    out = redact_obj({"a": [{"api_key": "x", "note": "pw=1 token=abc"}], "phone": "+91123"})
    assert out["a"][0]["api_key"] == "[REDACTED]"
    assert "abc" not in out["a"][0]["note"]
    assert out["phone"] == "[REDACTED]"


def test_leaves_normal_text():
    assert redact_text("request completed status=200 duration_ms=41") == "request completed status=200 duration_ms=41"
