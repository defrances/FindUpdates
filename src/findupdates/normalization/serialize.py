"""Deterministic serialization used for hashing and schema validation."""

from __future__ import annotations

import json
from datetime import datetime
from enum import StrEnum
from typing import Any

from findupdates.normalization.models import (
    SCHEMA_VERSION,
    AffectedProduct,
    Architecture,
    Completeness,
    Confidence,
    Conflict,
    CvssRecord,
    CvssVersion,
    Exploitability,
    FieldProvenance,
    PackageId,
    PackageKind,
    ProductStatus,
    Provenance,
    RebootRequirement,
    Remediation,
    RemediationKind,
    TriState,
    UpdateAdvisory,
    UpdateCategory,
    Vendor,
    VendorSeverity,
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


def dict_to_advisory(payload: dict[str, Any]) -> UpdateAdvisory:
    """Parse collector/canonical advisory JSON. Unknown fields are ignored."""
    provenance_raw = payload["provenance"]
    if not isinstance(provenance_raw, dict):
        raise ValueError("provenance must be an object")
    return UpdateAdvisory(
        advisory_id=str(payload["advisory_id"]),
        vendor=Vendor(str(payload["vendor"])),
        source=str(payload["source"]),
        vendor_advisory_id=_optional_text(payload.get("vendor_advisory_id")),
        title=str(payload["title"]),
        description=_optional_text(payload.get("description")),
        published_at=_parse_datetime(str(payload["published_at"])),
        revised_at=_parse_optional_datetime(payload.get("revised_at")),
        collected_at=_parse_datetime(str(payload["collected_at"])),
        parser_version=str(payload["parser_version"]),
        cve_ids=tuple(str(item) for item in payload.get("cve_ids", [])),
        package_ids=tuple(_parse_package(item) for item in payload.get("package_ids", [])),
        references=tuple(str(item) for item in payload.get("references", [])),
        vendor_severity=VendorSeverity(str(payload["vendor_severity"])),
        cvss=tuple(_parse_cvss(item) for item in payload.get("cvss", [])),
        update_category=UpdateCategory(str(payload["update_category"])),
        reboot_requirement=RebootRequirement(str(payload["reboot_requirement"])),
        known_exploited=TriState(str(payload["known_exploited"])),
        exploitability=Exploitability(str(payload["exploitability"])),
        affected_products=tuple(
            _parse_product(item) for item in payload.get("affected_products", [])
        ),
        remediations=tuple(_parse_remediation(item) for item in payload.get("remediations", [])),
        prerequisites=tuple(str(item) for item in payload.get("prerequisites", [])),
        supersedes=tuple(str(item) for item in payload.get("supersedes", [])),
        superseded_by=tuple(str(item) for item in payload.get("superseded_by", [])),
        known_issues=tuple(str(item) for item in payload.get("known_issues", [])),
        vendor_recommendation=_optional_text(payload.get("vendor_recommendation")),
        completeness=Completeness(str(payload["completeness"])),
        incomplete_fields=tuple(str(item) for item in payload.get("incomplete_fields", [])),
        normalization_confidence=Confidence(str(payload["normalization_confidence"])),
        conflicts=tuple(_parse_conflict(item) for item in payload.get("conflicts", [])),
        field_provenance=tuple(
            _parse_field_provenance(item) for item in payload.get("field_provenance", [])
        ),
        provenance=Provenance(
            source_url=_optional_text(provenance_raw.get("source_url")),
            raw_sha256=str(provenance_raw["raw_sha256"]),
            retrieved_at=_parse_datetime(str(provenance_raw["retrieved_at"])),
            content_type=_optional_text(provenance_raw.get("content_type")),
        ),
        schema_version=str(payload.get("schema_version", SCHEMA_VERSION)),
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


def _parse_package(item: object) -> PackageId:
    if not isinstance(item, dict):
        raise ValueError("package_id must be an object")
    return PackageId(PackageKind(str(item["kind"])), str(item["value"]))


def _parse_cvss(item: object) -> CvssRecord:
    if not isinstance(item, dict):
        raise ValueError("cvss record must be an object")
    score = item.get("base_score")
    if score is not None and not isinstance(score, int | float):
        raise ValueError("cvss.base_score must be a number")
    return CvssRecord(
        version=CvssVersion(str(item["version"])),
        vector=_optional_text(item.get("vector")),
        base_score=None if score is None else float(score),
        source=str(item["source"]),
    )


def _parse_product(item: object) -> AffectedProduct:
    if not isinstance(item, dict):
        raise ValueError("affected_product must be an object")
    architectures = tuple(Architecture(str(value)) for value in item.get("architectures", []))
    return AffectedProduct(
        vendor=str(item["vendor"]),
        product=str(item["product"]),
        version_range=_optional_text(item.get("version_range")),
        builds=tuple(str(value) for value in item.get("builds", [])),
        architectures=architectures,
        vendor_product_id=_optional_text(item.get("vendor_product_id")),
        cpe=_optional_text(item.get("cpe")),
        status=ProductStatus(str(item["status"])),
    )


def _parse_remediation(item: object) -> Remediation:
    if not isinstance(item, dict):
        raise ValueError("remediation must be an object")
    package = item.get("package_id")
    return Remediation(
        kind=RemediationKind(str(item["kind"])),
        description=_optional_text(item.get("description")),
        fixed_version=_optional_text(item.get("fixed_version")),
        package_id=None if package is None else _parse_package(package),
    )


def _parse_conflict(item: object) -> Conflict:
    if not isinstance(item, dict):
        raise ValueError("conflict must be an object")
    return Conflict(str(item["field_path"]), str(item["reason"]))


def _parse_field_provenance(item: object) -> FieldProvenance:
    if not isinstance(item, dict):
        raise ValueError("field_provenance must be an object")
    return FieldProvenance(str(item["field_path"]), str(item["source"]))


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return parsed


def _parse_optional_datetime(value: object) -> datetime | None:
    if value is None:
        return None
    return _parse_datetime(str(value))
