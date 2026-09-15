"""Redact PHI-like and secret-like strings before any model context is built."""

from __future__ import annotations

import re

_REDACTED = "[REDACTED]"
_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bpatient(?:[_\s-]?id)?\s*[:=]?\s*\S*"),
    re.compile(r"(?i)\bmrn\s*[:=]?\s*\S*"),
    re.compile(r"(?i)\bssn\s*[:=]?\s*\S*"),
    re.compile(r"(?i)\bphi\b"),
    re.compile(r"(?i)api[_-]?key\s*[:=]\s*\S+"),
    re.compile(r"(?i)bearer\s+[a-z0-9._\-]+"),
    re.compile(r"(?i)secret\s*[:=]\s*\S+"),
)


def redact_text(value: str | None) -> tuple[str, bool]:
    """Return a bounded, redacted excerpt and whether anything was stripped."""
    if value is None:
        return "", False
    text = " ".join(value.split())
    changed = False
    for pattern in _PATTERNS:
        updated, count = pattern.subn(_REDACTED, text)
        if count:
            changed = True
            text = updated
    if len(text) > 400:
        text = text[:400].rstrip() + "…"
        changed = True
    return text, changed
