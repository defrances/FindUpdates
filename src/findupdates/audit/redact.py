"""Strip secrets and PHI-like strings from evidence payloads."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from findupdates.agents.redaction import redact_text

_SECRET_KEYS = frozenset(
    {
        "token",
        "access_token",
        "refresh_token",
        "authorization",
        "password",
        "secret",
        "api_key",
        "apikey",
    }
)


def redact_payload(value: object) -> tuple[object, bool]:
    """Return a redacted structure and whether anything was stripped."""
    changed = False
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if lowered in _SECRET_KEYS or "token" in lowered:
                out[str(key)] = "[REDACTED]"
                changed = True
                continue
            nested, nested_changed = redact_payload(item)
            changed = changed or nested_changed
            out[str(key)] = nested
        return out, changed
    if isinstance(value, list):
        rows = []
        for item in value:
            nested, nested_changed = redact_payload(item)
            changed = changed or nested_changed
            rows.append(nested)
        return rows, changed
    if isinstance(value, str):
        text, stripped = redact_text(value)
        return text, stripped
    return value, False
