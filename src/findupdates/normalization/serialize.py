"""Deterministic serialization used for hashing and schema validation."""

from __future__ import annotations

import json
from datetime import datetime
from enum import StrEnum
from typing import Any

from findupdates.normalization.models import (
    SCHEMA_VERSION,
    AffectedProduct,
    Conflict,
    CvssRecord,
    FieldProvenance,
    PackageId,
    Provenance,
    Remediation,
    UpdateAdvisory,
)


def canonical_json(advisory: UpdateAdvisory) -> str:
    """Return a stable JSON document for hashing and evidence."""
    return json.dumps(
        advisory_to_dict(advisory),
        ensure_ascii=True,
        indent=None,
        separators=(",", ":"),
        sort_keys=True,
    )


def advisory_to_dict(advisory: UpdateAdvisory) -> dict[str, Any]:
    """Convert an advisory to a JSON-Schema-compatible mapping."""
    return {
        "schema_version": SCHEMA_VERSION,
        "advisory_id": advisory.advisory_id,
        "vendor": advisory.vendor.value,
        "source": advisory.source,
        "vendor_advisory_id": advisory.vendor_advisory_id,
        "title": advisory.title,
        "description": advisory.description,
        "published_at": _datetime(advisory.published_at),
        "revised_at": _optional_datetime(advisory.revised_at),
        "collected_at": _datetime(advisory.collected_at),
        "parser_version": advisory.parser_version,
        "cve_ids": list(advisory.cve_ids),
        "package_ids": [_package(item) for item in advisory.package_ids],
        "references": list(advisory.references),
        "vendor_severity": advisory.vendor_severity.value,
        "cvss": [_cvss(item) for item in advisory.cvss],
        "update_category": advisory.update_category.value,
        "reboot_requirement": advisory.reboot_requirement.value,
        "known_exploited": advisory.known_exploited.value,
        "exploitability": advisory.exploitability.value,
        "affected_products": [_product(item) for item in advisory.affected_products],
        "remediations": [_remediation(item) for item in advisory.remediations],
        "prerequisites": list(advisory.prerequisites),
        "supersedes": list(advisory.supersedes),
        "superseded_by": list(advisory.superseded_by),
        "known_issues": list(advisory.known_issues),
        "vendor_recommendation": advisory.vendor_recommendation,
        "completeness": advisory.completeness.value,
        "incomplete_fields": list(advisory.incomplete_fields),
        "normalization_confidence": advisory.normalization_confidence.value,
        "conflicts": [_conflict(item) for item in advisory.conflicts],
        "field_provenance": [_provenance_field(item) for item in advisory.field_provenance],
        "provenance": _source_provenance(advisory.provenance),
    }


def _package(item: PackageId) -> dict[str, str]:
    return {"kind": item.kind.value, "value": item.value}


def _cvss(item: CvssRecord) -> dict[str, str | float | None]:
    return {
        "version": item.version.value,
        "vector": item.vector,
        "base_score": item.base_score,
        "source": item.source,
    }


def _product(item: AffectedProduct) -> dict[str, Any]:
    return {
        "vendor": item.vendor,
        "product": item.product,
        "version_range": item.version_range,
        "builds": list(item.builds),
        "architectures": [_enum(value) for value in item.architectures],
        "vendor_product_id": item.vendor_product_id,
        "cpe": item.cpe,
        "status": item.status.value,
    }


def _remediation(item: Remediation) -> dict[str, Any]:
    return {
        "kind": item.kind.value,
        "description": item.description,
        "fixed_version": item.fixed_version,
        "package_id": _package(item.package_id) if item.package_id else None,
    }


def _conflict(item: Conflict) -> dict[str, str]:
    return {"field_path": item.field_path, "reason": item.reason}


def _provenance_field(item: FieldProvenance) -> dict[str, str]:
    return {"field_path": item.field_path, "source": item.source}


def _source_provenance(item: Provenance) -> dict[str, str | None]:
    return {
        "source_url": item.source_url,
        "raw_sha256": item.raw_sha256,
        "retrieved_at": _datetime(item.retrieved_at),
        "content_type": item.content_type,
    }


def _datetime(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _optional_datetime(value: datetime | None) -> str | None:
    return None if value is None else _datetime(value)


def _enum(value: StrEnum) -> str:
    return value.value
