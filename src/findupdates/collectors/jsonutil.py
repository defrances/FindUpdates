"""Helpers for vendor JSON that mixes PascalCase, camelCase and {Value: ...} wrappers."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any


def sha256_bytes(body: bytes) -> str:
    """Return a lowercase SHA-256 hex digest."""
    return hashlib.sha256(body).hexdigest()


def sha256_json(value: object) -> str:
    """Hash a JSON-serializable value with stable key order."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return sha256_bytes(encoded)


def mapping(value: object) -> Mapping[str, Any] | None:
    """Return a mapping or None when the node is missing or the wrong type."""
    if isinstance(value, Mapping):
        return value
    return None


def pick(obj: Mapping[str, Any] | None, *names: str) -> Any:
    """Return the first present key, matching names case-insensitively."""
    if obj is None:
        return None
    exact = {key: value for key, value in obj.items()}
    for name in names:
        if name in exact:
            return exact[name]
    lowered = {str(key).lower(): value for key, value in obj.items()}
    for name in names:
        found = lowered.get(name.lower())
        if found is not None or name.lower() in lowered:
            return lowered.get(name.lower())
    return None


def text_of(value: object) -> str | None:
    """Unwrap CVRF-style {Value: '...'} nodes and plain strings."""
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    nested = mapping(value)
    if nested is not None:
        inner = pick(nested, "Value", "value", "Text", "text")
        if inner is not None and inner is not value:
            return text_of(inner)
    return None


def list_of(value: object) -> list[Any]:
    """Normalize a scalar or list node into a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def parse_datetime(value: object) -> datetime | None:
    """Parse ISO-8601 timestamps; naive values are treated as UTC."""
    text = text_of(value) if not isinstance(value, datetime) else None
    if isinstance(value, datetime):
        parsed = value
    elif text is None:
        return None
    else:
        normalized = text.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
