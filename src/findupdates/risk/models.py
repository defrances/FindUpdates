"""Versioned risk assessment and policy outcomes."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

SCHEMA_VERSION = "1.0"

_POLICY_RANK = {
    "ALLOW_ANALYSIS": 0,
    "REQUIRE_VALIDATION": 1,
    "REQUIRE_APPROVAL": 2,
    "HOLD": 3,
    "BLOCK": 4,
}


class SeverityBand(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    EMERGENCY = "EMERGENCY"


class PolicyResult(StrEnum):
    ALLOW_ANALYSIS = "ALLOW_ANALYSIS"
    REQUIRE_VALIDATION = "REQUIRE_VALIDATION"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    HOLD = "HOLD"
    BLOCK = "BLOCK"


class RiskReason(StrEnum):
    CVSS = "CVSS"
    VENDOR_SEVERITY = "VENDOR_SEVERITY"
    CLINICAL_CRITICALITY = "CLINICAL_CRITICALITY"
    NETWORK_EXPOSURE = "NETWORK_EXPOSURE"
    KEV = "KEV"
    EXPLOITABILITY_HIGH = "EXPLOITABILITY_HIGH"
    NETWORK_NO_AUTH = "NETWORK_NO_AUTH"
    REBOOT_REQUIRED = "REBOOT_REQUIRED"
    FIRMWARE_OR_BIOS = "FIRMWARE_OR_BIOS"
    KNOWN_ISSUES = "KNOWN_ISSUES"
    NO_WORKAROUND = "NO_WORKAROUND"
    MISSING_CVSS = "MISSING_CVSS"
    NOT_AFFECTED = "NOT_AFFECTED"
    UNKNOWN_APPLICABILITY = "UNKNOWN_APPLICABILITY"
    POSSIBLY_AFFECTED = "POSSIBLY_AFFECTED"
    STALE_INVENTORY = "STALE_INVENTORY"
    UNKNOWN_CLINICAL_CRITICALITY = "UNKNOWN_CLINICAL_CRITICALITY"
    UNKNOWN_NETWORK_EXPOSURE = "UNKNOWN_NETWORK_EXPOSURE"
    FIRMWARE_CRITICAL_UNKNOWN_OEM = "FIRMWARE_CRITICAL_UNKNOWN_OEM"
    LOW_CONFIDENCE_AFFECTED = "LOW_CONFIDENCE_AFFECTED"
    SCORE_BAND = "SCORE_BAND"


@dataclass(frozen=True, slots=True)
class ScoreContribution:
    code: str
    points: float
    detail: str

    def __post_init__(self) -> None:
        if not self.code.strip() or not self.detail.strip():
            raise ValueError("contribution code and detail must not be empty")


@dataclass(frozen=True, slots=True)
class PolicyDocument:
    """Validated, versioned ruleset. Draft status is not production approval."""

    version: str
    status: str
    score_cap: int
    weights: dict[str, float]
    modifiers: dict[str, float]
    bands: dict[SeverityBand, tuple[int, int]]
    band_policy: dict[SeverityBand, PolicyResult]
    hard_gates: dict[str, PolicyResult]
    source_sha256: str

    def __post_init__(self) -> None:
        if not self.version.strip():
            raise ValueError("policy version must not be empty")
        if self.score_cap != 100:
            raise ValueError("score_cap must be 100")


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """Deterministic policy decision. Never produced by an LLM."""

    assessment_id: str
    advisory_id: str
    device_id: str
    policy_version: str
    score: int
    severity: SeverityBand
    policy_result: PolicyResult
    reason_codes: tuple[str, ...]
    contributions: tuple[ScoreContribution, ...]
    hard_gates_applied: tuple[str, ...]
    input_fingerprint: str
    assessed_at: datetime
    needs_reassessment: bool
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not self.reason_codes or not self.contributions:
            raise ValueError("risk assessment requires reason codes and contributions")
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version}")
        if self.assessed_at.tzinfo is None:
            raise ValueError("assessed_at must be timezone-aware")
        if not 0 <= self.score <= 100:
            raise ValueError("score must be between 0 and 100")


def stricter_result(left: PolicyResult, right: PolicyResult) -> PolicyResult:
    """Return the more restrictive of two policy outcomes."""
    if _POLICY_RANK[right.value] > _POLICY_RANK[left.value]:
        return right
    return left
