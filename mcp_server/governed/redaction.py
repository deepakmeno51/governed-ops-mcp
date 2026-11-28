"""Strip secrets and PII before data reaches the model or the audit log.
Mirrors redact_text() in the database. This is the second layer; the database views are the first."""
import re
from typing import Any

_RULES = [
    (re.compile(r"(password|passwd|pwd|secret|token|api[_-]?key)\s*[=:]\s*\S+", re.I), r"\1=[REDACTED]"),
    (re.compile(r"\b(sk|pk|rk)_(live|test)_\w+"), "[REDACTED_KEY]"),
    (re.compile(r"Bearer\s+[A-Za-z0-9._\-]+", re.I), "Bearer [REDACTED]"),
    # The lookbehind makes a match start only at the beginning of a word. Without it, a long run of ordinary
    # characters made this pattern quadratic: 100,000 characters took about 9 seconds.
    (re.compile(r"(?<![A-Za-z0-9._+\-])[A-Za-z0-9._+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"), "[REDACTED_EMAIL]"),
]

SENSITIVE_KEYS = {"password", "password_hash", "passwd", "secret", "token", "api_key", "apikey", "authorization", "phone"}


def redact_text(text: str) -> str:
    for pattern, repl in _RULES:
        text = pattern.sub(repl, text)
    return text


def redact_obj(obj: Any) -> Any:
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {
            k: "[REDACTED]" if str(k).lower() in SENSITIVE_KEYS else redact_obj(v)
            for k, v in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v) for v in obj]
    return obj
