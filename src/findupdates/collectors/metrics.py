"""Observable counters for a collector run."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CollectionMetrics:
    collected: int = 0
    changed: int = 0
    unchanged: int = 0
    failed: int = 0
    parse_error: int = 0

    def add(
        self,
        *,
        collected: int = 0,
        changed: int = 0,
        unchanged: int = 0,
        failed: int = 0,
        parse_error: int = 0,
    ) -> CollectionMetrics:
        """Return a new metrics object with incremented counters."""
        return CollectionMetrics(
            collected=self.collected + collected,
            changed=self.changed + changed,
            unchanged=self.unchanged + unchanged,
            failed=self.failed + failed,
            parse_error=self.parse_error + parse_error,
        )
