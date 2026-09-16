"""Incremental collection checkpoints. Hashes are the only payload retained."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class CollectionCheckpoint:
    """Resume watermark plus per-document hashes so unchanged polls stay idempotent."""

    source: str
    cursor: str | None
    document_hashes: tuple[tuple[str, str], ...]
    captured_at: datetime

    def hash_for(self, document_id: str) -> str | None:
        """Return the last seen SHA-256 for a vendor document id."""
        for item_id, digest in self.document_hashes:
            if item_id == document_id:
                return digest
        return None

    def hashes_as_dict(self) -> dict[str, str]:
        """Return a mutable copy of document hashes."""
        return dict(self.document_hashes)
