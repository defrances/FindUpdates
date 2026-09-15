"""Construct enrichment clients from non-secret settings plus env-only secrets."""

from __future__ import annotations

import os
from datetime import datetime, timedelta

from findupdates.collectors.http import ByteTransport, HttpClient
from findupdates.config import Settings
from findupdates.enrichment.kev import KevClient
from findupdates.enrichment.nvd import NvdClient
from findupdates.enrichment.service import EnrichmentService

NVD_API_KEY_ENV = "FINDUPDATES_NVD_API_KEY"


def enrichment_service_from_settings(
    settings: Settings,
    *,
    nvd_api_key: str | None = None,
    nvd_transport: ByteTransport | None = None,
    kev_transport: ByteTransport | None = None,
    now: datetime | None = None,
) -> EnrichmentService:
    """Build an enrichment service.

    The NVD API key is read from the environment (or an explicit argument) and is
    attached only to the NVD HTTP client so it is never sent to CISA.
    """
    key = nvd_api_key if nvd_api_key is not None else os.getenv(NVD_API_KEY_ENV)
    nvd_headers = {"apiKey": key} if key else None
    nvd_http = HttpClient(
        timeout_seconds=settings.http_timeout_seconds,
        max_retries=settings.http_max_retries,
        min_interval_seconds=settings.http_min_interval_seconds,
        extra_headers=nvd_headers,
        transport=nvd_transport,
    )
    kev_http = HttpClient(
        timeout_seconds=settings.http_timeout_seconds,
        max_retries=settings.http_max_retries,
        min_interval_seconds=settings.http_min_interval_seconds,
        transport=kev_transport,
    )
    return EnrichmentService(
        nvd=NvdClient(client=nvd_http, base_url=settings.nvd_base_url),
        kev=KevClient(client=kev_http, url=settings.kev_url),
        max_age=timedelta(hours=settings.enrichment_cache_max_age_hours),
        now=now,
    )
