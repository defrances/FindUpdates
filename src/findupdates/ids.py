"""Stable identifiers used to correlate records across pipeline stages."""

from __future__ import annotations

import hashlib


def stable_id(kind: str, *parts: str) -> str:
    """Return a deterministic identifier for a logical entity.

    The function intentionally contains no timestamps or random values so that repeated
    processing of the same logical input can be idempotent.
    """
    normalized_kind = kind.strip().lower().replace(" ", "-")
    if not normalized_kind:
        raise ValueError("kind must not be empty")
    if not parts or any(not part.strip() for part in parts):
        raise ValueError("all identifier parts must be non-empty")

    canonical = "\x1f".join(part.strip() for part in parts)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:20]
    return f"{normalized_kind}_{digest}"
