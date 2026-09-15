"""Vendor-neutral normalized update advisory domain model."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True, slots=True)
class AffectedProduct:
    """A vendor product identifier associated with an advisory."""

    product_id: str
    name: str | None = None
    architecture: str | None = None
    version: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Render the product in the JSON-schema representation."""
        return {
            "product_id": self.product_id,
            "name": self.name,
            "architecture": self.architecture,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class UpdateAdvisory:
    """Canonical advisory consumed by applicability, enrichment, and risk stages."""

    advisory_id: str
    source_advisory_id: str
    vendor: str
    source: str
    title: str
    description: str | None
    published_at: datetime
    revised_at: datetime | None
    cve_ids: tuple[str, ...]
    kb_ids: tuple[str, ...]
    vendor_severity: str | None
    affected_products: tuple[AffectedProduct, ...]
    fixed_versions: tuple[str, ...]
    reboot_required: bool | None
    known_issues: tuple[str, ...]
    prerequisites: tuple[str, ...]
    workarounds: tuple[str, ...]
    references: tuple[str, ...]
    raw_sha256: str
    collected_at: datetime
    parser_version: str

    def __post_init__(self) -> None:
        for field_name, value in (
            ("advisory_id", self.advisory_id),
            ("source_advisory_id", self.source_advisory_id),
            ("vendor", self.vendor),
            ("source", self.source),
            ("title", self.title),
            ("raw_sha256", self.raw_sha256),
            ("parser_version", self.parser_version),
        ):
            if not value.strip():
                raise ValueError(f"{field_name} must not be empty")
        if self.published_at.tzinfo is None or self.collected_at.tzinfo is None:
            raise ValueError("advisory timestamps must be timezone-aware")
        if self.revised_at is not None and self.revised_at.tzinfo is None:
            raise ValueError("revised_at must be timezone-aware when present")

    def to_dict(self) -> dict[str, object]:
        """Render a deterministic JSON-compatible representation."""
        return {
            "schema_version": "1.0",
            "advisory_id": self.advisory_id,
            "source_advisory_id": self.source_advisory_id,
            "vendor": self.vendor,
            "source": self.source,
            "title": self.title,
            "description": self.description,
            "published_at": _iso8601(self.published_at),
            "revised_at": _iso8601(self.revised_at),
            "cve_ids": list(self.cve_ids),
            "kb_ids": list(self.kb_ids),
            "vendor_severity": self.vendor_severity,
            "affected_products": [product.to_dict() for product in self.affected_products],
            "fixed_versions": list(self.fixed_versions),
            "reboot_required": self.reboot_required,
            "known_issues": list(self.known_issues),
            "prerequisites": list(self.prerequisites),
            "workarounds": list(self.workarounds),
            "references": list(self.references),
            "raw_sha256": self.raw_sha256,
            "collected_at": _iso8601(self.collected_at),
            "parser_version": self.parser_version,
        }


def _iso8601(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
