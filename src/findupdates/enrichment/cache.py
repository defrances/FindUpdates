"""In-memory enrichment cache that preserves last-known facts across outages."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Generic, TypeVar

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class CacheEntry(Generic[T]):
    value: T
    stored_at: datetime
    fingerprint: str

    def is_fresh(self, *, now: datetime, max_age: timedelta) -> bool:
        """Return whether the entry is within the configured freshness window."""
        if now.tzinfo is None or self.stored_at.tzinfo is None:
            return False
        if max_age <= timedelta(0):
            raise ValueError("max_age must be positive")
        return now - self.stored_at <= max_age


class MemoryCache(Generic[T]):
    """Process-local cache. Outages must read through this instead of deleting facts."""

    def __init__(self) -> None:
        self._entries: dict[str, CacheEntry[T]] = {}

    def get(self, key: str) -> CacheEntry[T] | None:
        """Return a cache entry if present."""
        return self._entries.get(key)

    def put(self, key: str, value: T, *, stored_at: datetime, fingerprint: str) -> CacheEntry[T]:
        """Store a value and return the new entry."""
        entry = CacheEntry(value=value, stored_at=stored_at, fingerprint=fingerprint)
        self._entries[key] = entry
        return entry
