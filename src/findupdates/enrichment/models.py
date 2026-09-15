"""Versioned CVE enrichment records from NVD and CISA KEV."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from findupdates.normalization.models import CvssRecord, TriState

SCHEMA_VERSION = "1.0"


class Freshness(StrEnum):
    FRESH = "fresh"
    STALE = "stale"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class CveEnrichment:
    """Independent vulnerability context for one CVE.

    NVD/KEV records are prioritization signals. They do not authorize deployment
    and must not overwrite vendor product-status/applicability evidence.
    """

    cve_id: str
    nvd_found: TriState
    nvd_cvss: tuple[CvssRecord, ...]
    nvd_cwes: tuple[str, ...]
    nvd_cpes: tuple[str, ...]
    nvd_last_modified: datetime | None
    nvd_retrieved_at: datetime | None
    nvd_raw_sha256: str | None
    nvd_stale: bool
    kev_listed: TriState
    kev_date_added: str | None
    kev_due_date: str | None
    kev_required_action: str | None
    kev_ransomware_use: TriState
    kev_catalog_version: str | None
    kev_retrieved_at: datetime | None
    kev_raw_sha256: str | None
    kev_stale: bool
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not self.cve_id.startswith("CVE-"):
            raise ValueError(f"invalid CVE identifier: {self.cve_id}")
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version}")


@dataclass(frozen=True, slots=True)
class EnrichmentMetrics:
    cache_hit: int = 0
    cache_miss: int = 0
    source_error: int = 0
    changed: int = 0
    unchanged: int = 0
    stale_served: int = 0

    def add(
        self,
        *,
        cache_hit: int = 0,
        cache_miss: int = 0,
        source_error: int = 0,
        changed: int = 0,
        unchanged: int = 0,
        stale_served: int = 0,
    ) -> EnrichmentMetrics:
        """Return incremented counters."""
        return EnrichmentMetrics(
            cache_hit=self.cache_hit + cache_hit,
            cache_miss=self.cache_miss + cache_miss,
            source_error=self.source_error + source_error,
            changed=self.changed + changed,
            unchanged=self.unchanged + unchanged,
            stale_served=self.stale_served + stale_served,
        )


def empty_enrichment(cve_id: str) -> CveEnrichment:
    """Unknown NVD/KEV context when no lookup has succeeded."""
    return CveEnrichment(
        cve_id=cve_id,
        nvd_found=TriState.UNKNOWN,
        nvd_cvss=(),
        nvd_cwes=(),
        nvd_cpes=(),
        nvd_last_modified=None,
        nvd_retrieved_at=None,
        nvd_raw_sha256=None,
        nvd_stale=False,
        kev_listed=TriState.UNKNOWN,
        kev_date_added=None,
        kev_due_date=None,
        kev_required_action=None,
        kev_ransomware_use=TriState.UNKNOWN,
        kev_catalog_version=None,
        kev_retrieved_at=None,
        kev_raw_sha256=None,
        kev_stale=False,
    )
