"""Versioned applicability result for one advisory-device pair."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from findupdates.normalization.models import Confidence

SCHEMA_VERSION = "1.0"


class ApplicabilityVerdict(StrEnum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    POSSIBLY_AFFECTED = "possibly_affected"
    UNKNOWN = "unknown"


class ReasonCode(StrEnum):
    VERSION_IN_RANGE = "VERSION_IN_RANGE"
    VERSION_OUT_OF_RANGE = "VERSION_OUT_OF_RANGE"
    PRODUCT_ID_MATCH = "PRODUCT_ID_MATCH"
    CPE_MATCH = "CPE_MATCH"
    PURL_MATCH = "PURL_MATCH"
    PRODUCT_FAMILY_MATCH = "PRODUCT_FAMILY_MATCH"
    ARCHITECTURE_MISMATCH = "ARCHITECTURE_MISMATCH"
    VENDOR_NOT_AFFECTED = "VENDOR_NOT_AFFECTED"
    VENDOR_AFFECTED = "VENDOR_AFFECTED"
    VENDOR_FIXED = "VENDOR_FIXED"
    MISSING_VERSION = "MISSING_VERSION"
    STALE_INVENTORY = "STALE_INVENTORY"
    FRESHNESS_UNKNOWN = "FRESHNESS_UNKNOWN"
    UNVERIFIED_INVENTORY = "UNVERIFIED_INVENTORY"
    EMPTY_AFFECTED_PRODUCTS = "EMPTY_AFFECTED_PRODUCTS"
    NAME_AMBIGUOUS = "NAME_AMBIGUOUS"
    NO_DETERMINISTIC_MATCH = "NO_DETERMINISTIC_MATCH"
    ADVISORY_INCOMPLETE = "ADVISORY_INCOMPLETE"


class IdentityStrength(StrEnum):
    NONE = "none"
    FAMILY = "family"
    PURL = "purl"
    CPE = "cpe"
    PRODUCT_ID = "product_id"


class VersionRelation(StrEnum):
    IN_RANGE = "in_range"
    OUT_OF_RANGE = "out_of_range"
    BELOW_FIXED = "below_fixed"
    AT_OR_ABOVE_FIXED = "at_or_above_fixed"
    MISSING = "missing"
    UNPARSED = "unparsed"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, slots=True)
class ApplicabilityEvidence:
    reason_code: ReasonCode
    detail: str
    source_fields: tuple[str, ...]
    inventory_fields: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.detail.strip():
            raise ValueError("evidence.detail must not be empty")


@dataclass(frozen=True, slots=True)
class MatchObservation:
    matcher: str
    identity: IdentityStrength
    version_relation: VersionRelation
    architecture_match: bool | None
    reason_codes: tuple[ReasonCode, ...]
    source_fields: tuple[str, ...]
    inventory_fields: tuple[str, ...]
    detail: str
    product_status_value: str


@dataclass(frozen=True, slots=True)
class ApplicabilityResult:
    """Deterministic, auditable applicability decision. Never produced by an LLM."""

    result_id: str
    advisory_id: str
    device_id: str
    verdict: ApplicabilityVerdict
    confidence: Confidence
    blocks_automatic_deployment: bool
    evidence: tuple[ApplicabilityEvidence, ...]
    source_fields: tuple[str, ...]
    inventory_fields: tuple[str, ...]
    missing_data: tuple[str, ...]
    input_fingerprint: str
    evaluated_at: datetime
    needs_reassessment: bool
    previous_fingerprint: str | None
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not self.evidence:
            raise ValueError("applicability result requires evidence")
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version}")
        if self.evaluated_at.tzinfo is None:
            raise ValueError("evaluated_at must be timezone-aware")


def blocks_automatic_deployment(
    verdict: ApplicabilityVerdict,
    confidence: Confidence,
    *,
    inventory_fresh: bool,
) -> bool:
    """Unknown, weak, or stale results cannot authorize production deployment."""
    if not inventory_fresh:
        return True
    if verdict in {ApplicabilityVerdict.UNKNOWN, ApplicabilityVerdict.POSSIBLY_AFFECTED}:
        return True
    return confidence in {Confidence.LOW, Confidence.UNKNOWN}
