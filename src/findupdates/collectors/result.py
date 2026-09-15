"""Shared result types for vendor collectors."""

from __future__ import annotations

from dataclasses import dataclass

from findupdates.collectors.checkpoint import CollectionCheckpoint
from findupdates.collectors.metrics import CollectionMetrics
from findupdates.normalization.models import UpdateAdvisory


@dataclass(frozen=True, slots=True)
class CollectionResult:
    advisories: tuple[UpdateAdvisory, ...]
    metrics: CollectionMetrics
    checkpoint: CollectionCheckpoint
    errors: tuple[str, ...]
