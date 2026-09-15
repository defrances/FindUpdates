"""Orchestrate NVD and KEV lookups with last-known-good cache."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

from findupdates.collectors.errors import SourceUnavailableError
from findupdates.enrichment.apply import apply_enrichment
from findupdates.enrichment.cache import CacheEntry, MemoryCache
from findupdates.enrichment.kev import KevCatalog, KevClient
from findupdates.enrichment.models import CveEnrichment, EnrichmentMetrics, empty_enrichment
from findupdates.enrichment.nvd import NvdClient, NvdFact
from findupdates.normalization.models import TriState, UpdateAdvisory

KEV_CACHE_KEY = "kev:catalog"


@dataclass(frozen=True, slots=True)
class EnrichmentOutcome:
    advisory: UpdateAdvisory
    records: tuple[CveEnrichment, ...]
    needs_reassessment: bool
    reassessment_reasons: tuple[str, ...]
    metrics: EnrichmentMetrics


class EnrichmentService:
    """Enrich advisories with NVD/KEV facts. Outages keep cached facts."""

    def __init__(
        self,
        *,
        nvd: NvdClient,
        kev: KevClient,
        max_age: timedelta,
        now: datetime | None = None,
        nvd_cache: MemoryCache[NvdFact] | None = None,
        kev_cache: MemoryCache[KevCatalog] | None = None,
    ) -> None:
        if max_age <= timedelta(0):
            raise ValueError("max_age must be positive")
        self._nvd = nvd
        self._kev = kev
        self._max_age = max_age
        self._now = now
        self._nvd_cache = nvd_cache or MemoryCache[NvdFact]()
        self._kev_cache = kev_cache or MemoryCache[KevCatalog]()

    def enrich(self, advisory: UpdateAdvisory) -> EnrichmentOutcome:
        """Lookup every CVE on the advisory and apply enrichment signals."""
        retrieved_at = self._now or datetime.now(UTC)
        previous_kev = self._kev_cache.get(KEV_CACHE_KEY)
        catalog, metrics = self._load_kev(retrieved_at, EnrichmentMetrics())
        records: list[CveEnrichment] = []
        reasons: list[str] = []
        for cve_id in advisory.cve_ids:
            previous_nvd = self._nvd_cache.get(_nvd_key(cve_id))
            previous_listed = _previous_kev_listing(previous_kev, cve_id)
            fact, metrics = self._load_nvd(cve_id, retrieved_at, metrics)
            record = _combine(fact, catalog, cve_id)
            records.append(record)
            if previous_nvd is not None and previous_nvd.fingerprint != fact.raw_sha256:
                reasons.append(f"{cve_id}:nvd_changed")
                metrics = metrics.add(changed=1)
            elif previous_nvd is None:
                metrics = metrics.add(changed=1 if fact.found is not TriState.UNKNOWN else 0)
            else:
                metrics = metrics.add(unchanged=1)
            new_listed = record.kev_listed
            if previous_listed is not TriState.TRUE and new_listed is TriState.TRUE:
                reasons.append(f"{cve_id}:entered_kev")
        updated = apply_enrichment(advisory, tuple(records))
        unique_reasons = tuple(dict.fromkeys(reasons))
        return EnrichmentOutcome(
            advisory=updated,
            records=tuple(records),
            needs_reassessment=bool(unique_reasons),
            reassessment_reasons=unique_reasons,
            metrics=metrics,
        )

    def _load_nvd(
        self, cve_id: str, retrieved_at: datetime, metrics: EnrichmentMetrics
    ) -> tuple[NvdFact, EnrichmentMetrics]:
        key = _nvd_key(cve_id)
        cached = self._nvd_cache.get(key)
        if cached is not None and cached.is_fresh(now=retrieved_at, max_age=self._max_age):
            return cached.value, metrics.add(cache_hit=1)
        try:
            fact = self._nvd.lookup(cve_id, retrieved_at=retrieved_at)
        except SourceUnavailableError:
            if cached is not None:
                stale = replace(cached.value, stale=True)
                return stale, metrics.add(source_error=1, stale_served=1, cache_hit=1)
            unknown = NvdFact(
                cve_id=cve_id,
                found=TriState.UNKNOWN,
                cvss=(),
                cwes=(),
                cpes=(),
                last_modified=None,
                retrieved_at=retrieved_at,
                raw_sha256="0" * 64,
                stale=False,
            )
            return unknown, metrics.add(source_error=1, cache_miss=1)
        self._nvd_cache.put(key, fact, stored_at=retrieved_at, fingerprint=fact.raw_sha256)
        return fact, metrics.add(cache_miss=1)

    def _load_kev(
        self, retrieved_at: datetime, metrics: EnrichmentMetrics
    ) -> tuple[KevCatalog | None, EnrichmentMetrics]:
        cached = self._kev_cache.get(KEV_CACHE_KEY)
        if cached is not None and cached.is_fresh(now=retrieved_at, max_age=self._max_age):
            return cached.value, metrics.add(cache_hit=1)
        try:
            catalog = self._kev.load(retrieved_at=retrieved_at)
        except SourceUnavailableError:
            if cached is not None:
                stale = replace(cached.value, stale=True)
                return stale, metrics.add(source_error=1, stale_served=1, cache_hit=1)
            return None, metrics.add(source_error=1, cache_miss=1)
        self._kev_cache.put(
            KEV_CACHE_KEY, catalog, stored_at=retrieved_at, fingerprint=catalog.raw_sha256
        )
        return catalog, metrics.add(cache_miss=1)


def _combine(
    fact: NvdFact,
    catalog: KevCatalog | None,
    cve_id: str,
) -> CveEnrichment:
    base = empty_enrichment(cve_id)
    entry = catalog.entries.get(cve_id) if catalog is not None else None
    kev_listed = catalog.listing(cve_id) if catalog is not None else TriState.UNKNOWN
    return replace(
        base,
        nvd_found=fact.found,
        nvd_cvss=fact.cvss,
        nvd_cwes=fact.cwes,
        nvd_cpes=fact.cpes,
        nvd_last_modified=fact.last_modified,
        nvd_retrieved_at=fact.retrieved_at,
        nvd_raw_sha256=fact.raw_sha256,
        nvd_stale=fact.stale,
        kev_listed=kev_listed,
        kev_date_added=entry.date_added if entry else None,
        kev_due_date=entry.due_date if entry else None,
        kev_required_action=entry.required_action if entry else None,
        kev_ransomware_use=entry.ransomware_use if entry else TriState.UNKNOWN,
        kev_catalog_version=catalog.version if catalog is not None else None,
        kev_retrieved_at=catalog.retrieved_at if catalog is not None else None,
        kev_raw_sha256=catalog.raw_sha256 if catalog is not None else None,
        kev_stale=catalog.stale if catalog is not None else False,
    )


def _nvd_key(cve_id: str) -> str:
    return f"nvd:{cve_id}"


def _previous_kev_listing(entry: CacheEntry[KevCatalog] | None, cve_id: str) -> TriState:
    if entry is None:
        return TriState.UNKNOWN
    return entry.value.listing(cve_id)
