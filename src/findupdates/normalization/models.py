"""Canonical UpdateAdvisory domain model and source-record contract."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum

from findupdates.ids import stable_id

PARSER_VERSION = "1.0"
SCHEMA_VERSION = "1.0"

SAFETY_RELEVANT_FIELDS = (
    "vendor_severity",
    "reboot_requirement",
    "known_exploited",
    "exploitability",
    "affected_products",
    "update_category",
)


class Vendor(StrEnum):
    MICROSOFT = "microsoft"
    INTEL = "intel"
    OTHER = "other"


class VendorSeverity(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class UpdateCategory(StrEnum):
    OS = "os"
    DRIVER = "driver"
    FIRMWARE = "firmware"
    BIOS = "bios"
    MICROCODE = "microcode"
    APPLICATION = "application"
    ADVISORY = "advisory"
    OTHER = "other"
    UNKNOWN = "unknown"


class RebootRequirement(StrEnum):
    REQUIRED = "required"
    MAYBE = "maybe"
    NO = "no"
    UNKNOWN = "unknown"


class TriState(StrEnum):
    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"


class Exploitability(StrEnum):
    NONE = "none"
    LOW = "low"
    HIGH = "high"
    UNKNOWN = "unknown"


class ProductStatus(StrEnum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    FIXED = "fixed"
    UNKNOWN = "unknown"


class Completeness(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class PackageKind(StrEnum):
    KB = "kb"
    DRIVER = "driver"
    FIRMWARE = "firmware"
    BIOS = "bios"
    MICROCODE = "microcode"
    OTHER = "other"
    UNKNOWN = "unknown"


class RemediationKind(StrEnum):
    VENDOR_FIX = "vendor_fix"
    WORKAROUND = "workaround"
    MITIGATION = "mitigation"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class CvssVersion(StrEnum):
    V2_0 = "2.0"
    V3_0 = "3.0"
    V3_1 = "3.1"
    V4_0 = "4.0"
    UNKNOWN = "unknown"


class Architecture(StrEnum):
    X64 = "x64"
    X86 = "x86"
    ARM64 = "arm64"
    OTHER = "other"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class PackageId:
    kind: PackageKind
    value: str

    def __post_init__(self) -> None:
        _require_text("package_id.value", self.value)


@dataclass(frozen=True, slots=True)
class CvssRecord:
    version: CvssVersion
    vector: str | None
    base_score: float | None
    source: str

    def __post_init__(self) -> None:
        _require_text("cvss.source", self.source)
        if self.base_score is not None and not 0 <= self.base_score <= 10:
            raise ValueError("cvss.base_score must be between 0 and 10")


@dataclass(frozen=True, slots=True)
class AffectedProduct:
    vendor: str
    product: str
    version_range: str | None
    builds: tuple[str, ...]
    architectures: tuple[Architecture, ...]
    vendor_product_id: str | None
    cpe: str | None
    status: ProductStatus

    def __post_init__(self) -> None:
        _require_text("affected_product.vendor", self.vendor)
        _require_text("affected_product.product", self.product)


@dataclass(frozen=True, slots=True)
class Remediation:
    kind: RemediationKind
    description: str | None
    fixed_version: str | None
    package_id: PackageId | None


@dataclass(frozen=True, slots=True)
class FieldProvenance:
    field_path: str
    source: str

    def __post_init__(self) -> None:
        _require_text("field_provenance.field_path", self.field_path)
        _require_text("field_provenance.source", self.source)


@dataclass(frozen=True, slots=True)
class Conflict:
    field_path: str
    reason: str

    def __post_init__(self) -> None:
        _require_text("conflict.field_path", self.field_path)
        _require_text("conflict.reason", self.reason)


@dataclass(frozen=True, slots=True)
class Provenance:
    source_url: str | None
    raw_sha256: str
    retrieved_at: datetime
    content_type: str | None

    def __post_init__(self) -> None:
        if len(self.raw_sha256) != 64 or any(
            ch not in "0123456789abcdef" for ch in self.raw_sha256
        ):
            raise ValueError("provenance.raw_sha256 must be a lowercase hex SHA-256 digest")
        if self.retrieved_at.tzinfo is None:
            raise ValueError("provenance.retrieved_at must be timezone-aware")


@dataclass(frozen=True, slots=True)
class UpdateAdvisory:
    """Vendor-neutral advisory used by enrichment, applicability and risk stages."""

    advisory_id: str
    vendor: Vendor
    source: str
    vendor_advisory_id: str | None
    title: str
    description: str | None
    published_at: datetime
    revised_at: datetime | None
    collected_at: datetime
    parser_version: str
    cve_ids: tuple[str, ...]
    package_ids: tuple[PackageId, ...]
    references: tuple[str, ...]
    vendor_severity: VendorSeverity
    cvss: tuple[CvssRecord, ...]
    update_category: UpdateCategory
    reboot_requirement: RebootRequirement
    known_exploited: TriState
    exploitability: Exploitability
    affected_products: tuple[AffectedProduct, ...]
    remediations: tuple[Remediation, ...]
    prerequisites: tuple[str, ...]
    supersedes: tuple[str, ...]
    superseded_by: tuple[str, ...]
    known_issues: tuple[str, ...]
    vendor_recommendation: str | None
    completeness: Completeness
    incomplete_fields: tuple[str, ...]
    normalization_confidence: Confidence
    conflicts: tuple[Conflict, ...]
    field_provenance: tuple[FieldProvenance, ...]
    provenance: Provenance
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_text("advisory_id", self.advisory_id)
        _require_text("source", self.source)
        _require_text("title", self.title)
        _require_text("parser_version", self.parser_version)
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version}")
        for timestamp in (self.published_at, self.collected_at):
            if timestamp.tzinfo is None:
                raise ValueError("advisory timestamps must be timezone-aware")
        if self.revised_at is not None and self.revised_at.tzinfo is None:
            raise ValueError("revised_at must be timezone-aware")
        for cve_id in self.cve_ids:
            if not cve_id.startswith("CVE-"):
                raise ValueError(f"invalid CVE identifier: {cve_id}")


@dataclass(frozen=True, slots=True)
class NormalizedSourceRecord:
    """Collector output before canonical identity, completeness and defaulting."""

    vendor: Vendor
    source: str
    vendor_advisory_id: str | None
    title: str
    published_at: datetime
    provenance: Provenance
    description: str | None = None
    revised_at: datetime | None = None
    collected_at: datetime | None = None
    parser_version: str = PARSER_VERSION
    cve_ids: tuple[str, ...] = ()
    package_ids: tuple[PackageId, ...] = ()
    references: tuple[str, ...] = ()
    vendor_severity: VendorSeverity = VendorSeverity.UNKNOWN
    cvss: tuple[CvssRecord, ...] = ()
    update_category: UpdateCategory = UpdateCategory.UNKNOWN
    reboot_requirement: RebootRequirement = RebootRequirement.UNKNOWN
    known_exploited: TriState = TriState.UNKNOWN
    exploitability: Exploitability = Exploitability.UNKNOWN
    affected_products: tuple[AffectedProduct, ...] = ()
    remediations: tuple[Remediation, ...] = ()
    prerequisites: tuple[str, ...] = ()
    supersedes: tuple[str, ...] = ()
    superseded_by: tuple[str, ...] = ()
    known_issues: tuple[str, ...] = ()
    vendor_recommendation: str | None = None
    field_provenance: tuple[FieldProvenance, ...] = ()
    normalization_confidence: Confidence = Confidence.UNKNOWN

    def __post_init__(self) -> None:
        _require_text("source", self.source)
        _require_text("title", self.title)
        if self.published_at.tzinfo is None:
            raise ValueError("published_at must be timezone-aware")
        if self.collected_at is not None and self.collected_at.tzinfo is None:
            raise ValueError("collected_at must be timezone-aware")
        if self.revised_at is not None and self.revised_at.tzinfo is None:
            raise ValueError("revised_at must be timezone-aware")


def logical_advisory_key(
    *,
    vendor: Vendor,
    vendor_advisory_id: str | None,
    cve_ids: tuple[str, ...],
    raw_sha256: str,
) -> str:
    """Return a stable logical identity shared by revisions of the same advisory."""
    if vendor_advisory_id and vendor_advisory_id.strip():
        return stable_id("advisory", vendor.value, vendor_advisory_id.strip())
    unique_cves = tuple(sorted({cve_id.strip() for cve_id in cve_ids if cve_id.strip()}))
    if unique_cves:
        return stable_id("advisory", vendor.value, *unique_cves)
    return stable_id("advisory", vendor.value, raw_sha256)


def incomplete_fields_for(advisory: UpdateAdvisory) -> tuple[str, ...]:
    """List safety-relevant fields that are unknown or empty rather than asserted."""
    missing: list[str] = []
    if advisory.vendor_severity is VendorSeverity.UNKNOWN:
        missing.append("vendor_severity")
    if advisory.reboot_requirement is RebootRequirement.UNKNOWN:
        missing.append("reboot_requirement")
    if advisory.known_exploited is TriState.UNKNOWN:
        missing.append("known_exploited")
    if advisory.exploitability is Exploitability.UNKNOWN:
        missing.append("exploitability")
    if not advisory.affected_products:
        missing.append("affected_products")
    elif any(product.status is ProductStatus.UNKNOWN for product in advisory.affected_products):
        missing.append("affected_products.status")
    if advisory.update_category is UpdateCategory.UNKNOWN:
        missing.append("update_category")
    return tuple(missing)


def completeness_for(missing: tuple[str, ...]) -> Completeness:
    """Unknown-heavy records are partial; empty missing-set is complete."""
    if not missing:
        return Completeness.COMPLETE
    if set(missing) >= set(SAFETY_RELEVANT_FIELDS):
        return Completeness.UNKNOWN
    return Completeness.PARTIAL


def normalize_source_record(record: NormalizedSourceRecord) -> UpdateAdvisory:
    """Map a collector record onto the canonical advisory without inventing facts."""
    collected_at = record.collected_at or record.provenance.retrieved_at
    advisory_id = logical_advisory_key(
        vendor=record.vendor,
        vendor_advisory_id=record.vendor_advisory_id,
        cve_ids=record.cve_ids,
        raw_sha256=record.provenance.raw_sha256,
    )
    draft = UpdateAdvisory(
        advisory_id=advisory_id,
        vendor=record.vendor,
        source=record.source,
        vendor_advisory_id=_optional_text(record.vendor_advisory_id),
        title=record.title.strip(),
        description=_optional_text(record.description),
        published_at=record.published_at,
        revised_at=record.revised_at,
        collected_at=collected_at,
        parser_version=record.parser_version,
        cve_ids=_unique_sorted(record.cve_ids),
        package_ids=_unique_packages(record.package_ids),
        references=_unique_sorted(record.references),
        vendor_severity=record.vendor_severity,
        cvss=record.cvss,
        update_category=record.update_category,
        reboot_requirement=record.reboot_requirement,
        known_exploited=record.known_exploited,
        exploitability=record.exploitability,
        affected_products=record.affected_products,
        remediations=record.remediations,
        prerequisites=_unique_sorted(record.prerequisites),
        supersedes=_unique_sorted(record.supersedes),
        superseded_by=_unique_sorted(record.superseded_by),
        known_issues=record.known_issues,
        vendor_recommendation=_optional_text(record.vendor_recommendation),
        completeness=Completeness.UNKNOWN,
        incomplete_fields=(),
        normalization_confidence=record.normalization_confidence,
        conflicts=(),
        field_provenance=record.field_provenance,
        provenance=record.provenance,
    )
    missing = incomplete_fields_for(draft)
    return replace(
        draft,
        incomplete_fields=missing,
        completeness=completeness_for(missing),
        normalization_confidence=_confidence_for(record.normalization_confidence, missing),
    )


def merge_advisories(existing: UpdateAdvisory, incoming: UpdateAdvisory) -> UpdateAdvisory:
    """Merge two observations of the same logical advisory.

    Conflicting asserted values fall back to unknown instead of picking a winner.
    Unknown never overwrites a previously asserted value.
    """
    if existing.advisory_id != incoming.advisory_id:
        raise ValueError("cannot merge advisories with different identities")
    newer, older = _order_by_revision(existing, incoming)
    conflicts: list[Conflict] = list(existing.conflicts) + list(incoming.conflicts)
    vendor_severity, severity_conflict = _merge_enum(
        existing.vendor_severity,
        incoming.vendor_severity,
        VendorSeverity.UNKNOWN,
        "vendor_severity",
    )
    reboot_requirement, reboot_conflict = _merge_enum(
        existing.reboot_requirement,
        incoming.reboot_requirement,
        RebootRequirement.UNKNOWN,
        "reboot_requirement",
    )
    known_exploited, exploited_conflict = _merge_enum(
        existing.known_exploited,
        incoming.known_exploited,
        TriState.UNKNOWN,
        "known_exploited",
    )
    exploitability, exploit_conflict = _merge_enum(
        existing.exploitability,
        incoming.exploitability,
        Exploitability.UNKNOWN,
        "exploitability",
    )
    update_category, category_conflict = _merge_enum(
        existing.update_category,
        incoming.update_category,
        UpdateCategory.UNKNOWN,
        "update_category",
    )
    for maybe_conflict in (
        severity_conflict,
        reboot_conflict,
        exploited_conflict,
        exploit_conflict,
        category_conflict,
    ):
        if maybe_conflict is not None:
            conflicts.append(maybe_conflict)

    merged = UpdateAdvisory(
        advisory_id=existing.advisory_id,
        vendor=existing.vendor,
        source=newer.source,
        vendor_advisory_id=newer.vendor_advisory_id or older.vendor_advisory_id,
        title=newer.title,
        description=newer.description or older.description,
        published_at=min(existing.published_at, incoming.published_at),
        revised_at=_latest_optional(existing.revised_at, incoming.revised_at),
        collected_at=max(existing.collected_at, incoming.collected_at),
        parser_version=newer.parser_version,
        cve_ids=_unique_sorted((*existing.cve_ids, *incoming.cve_ids)),
        package_ids=_unique_packages((*existing.package_ids, *incoming.package_ids)),
        references=_unique_sorted((*existing.references, *incoming.references)),
        vendor_severity=vendor_severity,
        cvss=_unique_cvss((*existing.cvss, *incoming.cvss)),
        update_category=update_category,
        reboot_requirement=reboot_requirement,
        known_exploited=known_exploited,
        exploitability=exploitability,
        affected_products=_unique_products(
            (*existing.affected_products, *incoming.affected_products)
        ),
        remediations=(*older.remediations, *newer.remediations)
        if older.remediations != newer.remediations
        else newer.remediations,
        prerequisites=_unique_sorted((*existing.prerequisites, *incoming.prerequisites)),
        supersedes=_unique_sorted((*existing.supersedes, *incoming.supersedes)),
        superseded_by=_unique_sorted((*existing.superseded_by, *incoming.superseded_by)),
        known_issues=_unique_sorted((*existing.known_issues, *incoming.known_issues)),
        vendor_recommendation=newer.vendor_recommendation or older.vendor_recommendation,
        completeness=Completeness.UNKNOWN,
        incomplete_fields=(),
        normalization_confidence=Confidence.UNKNOWN,
        conflicts=_unique_conflicts(tuple(conflicts)),
        field_provenance=_unique_provenance(
            (*existing.field_provenance, *incoming.field_provenance)
        ),
        provenance=newer.provenance,
    )
    missing = incomplete_fields_for(merged)
    confidence = (
        Confidence.LOW
        if merged.conflicts
        else _confidence_for(newer.normalization_confidence, missing)
    )
    return replace(
        merged,
        incomplete_fields=missing,
        completeness=completeness_for(missing),
        normalization_confidence=confidence,
    )


def _confidence_for(declared: Confidence, missing: tuple[str, ...]) -> Confidence:
    if declared is not Confidence.UNKNOWN:
        return declared
    if not missing:
        return Confidence.HIGH
    if len(missing) <= 2:
        return Confidence.MEDIUM
    return Confidence.LOW


def _order_by_revision(
    left: UpdateAdvisory, right: UpdateAdvisory
) -> tuple[UpdateAdvisory, UpdateAdvisory]:
    left_revision = left.revised_at or left.collected_at
    right_revision = right.revised_at or right.collected_at
    if right_revision >= left_revision:
        return right, left
    return left, right


def _merge_enum[T: StrEnum](
    left: T, right: T, unknown: T, field_path: str
) -> tuple[T, Conflict | None]:
    if left == right:
        return left, None
    if left == unknown:
        return right, None
    if right == unknown:
        return left, None
    return unknown, Conflict(
        field_path=field_path,
        reason=f"conflicting asserted values {left.value} and {right.value}",
    )


def _latest_optional(left: datetime | None, right: datetime | None) -> datetime | None:
    values = [value for value in (left, right) if value is not None]
    return max(values) if values else None


def _unique_sorted(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted({value.strip() for value in values if value.strip()}))


def _unique_packages(values: tuple[PackageId, ...]) -> tuple[PackageId, ...]:
    unique: dict[tuple[str, str], PackageId] = {}
    for package in values:
        unique[(package.kind.value, package.value)] = package
    return tuple(unique[key] for key in sorted(unique))


def _unique_cvss(values: tuple[CvssRecord, ...]) -> tuple[CvssRecord, ...]:
    unique: dict[tuple[str, str | None, str], CvssRecord] = {}
    for record in values:
        unique[(record.version.value, record.vector, record.source)] = record

    def _cvss_sort_key(item: tuple[str, str | None, str]) -> str:
        version, vector, source = item
        return version + (vector or "") + source

    return tuple(unique[key] for key in sorted(unique, key=_cvss_sort_key))


def _unique_products(values: tuple[AffectedProduct, ...]) -> tuple[AffectedProduct, ...]:
    unique: dict[tuple[str, str, str | None, str], AffectedProduct] = {}
    for product in values:
        key = (product.vendor, product.product, product.version_range, product.status.value)
        unique[key] = product
    return tuple(unique[key] for key in sorted(unique))


def _unique_conflicts(values: tuple[Conflict, ...]) -> tuple[Conflict, ...]:
    unique: dict[tuple[str, str], Conflict] = {}
    for conflict in values:
        unique[(conflict.field_path, conflict.reason)] = conflict
    return tuple(unique[key] for key in sorted(unique))


def _unique_provenance(values: tuple[FieldProvenance, ...]) -> tuple[FieldProvenance, ...]:
    unique: dict[tuple[str, str], FieldProvenance] = {}
    for item in values:
        unique[(item.field_path, item.source)] = item
    return tuple(unique[key] for key in sorted(unique))


def _optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _require_text(field_name: str, value: str) -> None:
    if not value.strip():
        raise ValueError(f"{field_name} must not be empty")
