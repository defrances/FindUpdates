"""JSON serialization for enrichment records."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from findupdates.enrichment.models import SCHEMA_VERSION, CveEnrichment
from findupdates.normalization.models import CvssRecord


def enrichment_to_dict(record: CveEnrichment) -> dict[str, Any]:
    """Convert a CVE enrichment record to a schema-compatible mapping."""
    return {
        "schema_version": SCHEMA_VERSION,
        "cve_id": record.cve_id,
        "nvd_found": record.nvd_found.value,
        "nvd_cvss": [_cvss(item) for item in record.nvd_cvss],
        "nvd_cwes": list(record.nvd_cwes),
        "nvd_cpes": list(record.nvd_cpes),
        "nvd_last_modified": _optional_datetime(record.nvd_last_modified),
        "nvd_retrieved_at": _optional_datetime(record.nvd_retrieved_at),
        "nvd_raw_sha256": record.nvd_raw_sha256,
        "nvd_stale": record.nvd_stale,
        "kev_listed": record.kev_listed.value,
        "kev_date_added": record.kev_date_added,
        "kev_due_date": record.kev_due_date,
        "kev_required_action": record.kev_required_action,
        "kev_ransomware_use": record.kev_ransomware_use.value,
        "kev_catalog_version": record.kev_catalog_version,
        "kev_retrieved_at": _optional_datetime(record.kev_retrieved_at),
        "kev_raw_sha256": record.kev_raw_sha256,
        "kev_stale": record.kev_stale,
    }


def _cvss(item: CvssRecord) -> dict[str, str | float | None]:
    return {
        "version": item.version.value,
        "vector": item.vector,
        "base_score": item.base_score,
        "source": item.source,
    }


def _optional_datetime(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat().replace("+00:00", "Z")
