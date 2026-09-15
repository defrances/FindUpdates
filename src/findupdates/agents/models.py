"""Versioned, non-authoritative AI analysis contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

SCHEMA_VERSION = "1.0"
PROMPT_VERSION = "1.0"
TEMPLATE_VERSION = "1.0"


class ClaimKind(StrEnum):
    FACT = "fact"
    INFERENCE = "inference"


class AnalysisConfidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    UNKNOWN = "unknown"


class AgentRole(StrEnum):
    UPDATE_INTELLIGENCE = "update_intelligence"
    APPLICABILITY_REVIEW = "applicability_review"
    RISK_EXPLANATION = "risk_explanation"
    CHANGE_PLANNING = "change_planning"


@dataclass(frozen=True, slots=True)
class ModelIdentity:
    provider: str
    name: str
    version: str

    def __post_init__(self) -> None:
        for field_name, value in (
            ("provider", self.provider),
            ("name", self.name),
            ("version", self.version),
        ):
            if not value.strip():
                raise ValueError(f"model.{field_name} must not be empty")


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    evidence_id: str
    kind: str
    source_field: str
    value: str

    def __post_init__(self) -> None:
        if not self.evidence_id.strip() or not self.kind.strip() or not self.source_field.strip():
            raise ValueError("evidence identity fields must not be empty")
        if not self.value.strip():
            raise ValueError("evidence value must not be empty")


@dataclass(frozen=True, slots=True)
class AuthoritativeSnapshot:
    """Deterministic pipeline facts. AI may echo these but cannot change them."""

    advisory_id: str
    device_id: str
    applicability_verdict: str
    applicability_confidence: str
    risk_score: int
    risk_severity: str
    policy_result: str
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if not 0 <= self.risk_score <= 100:
            raise ValueError("risk_score must be between 0 and 100")


@dataclass(frozen=True, slots=True)
class Claim:
    claim_id: str
    kind: ClaimKind
    text: str
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.claim_id.strip() or not self.text.strip():
            raise ValueError("claim id and text must not be empty")
        if not self.evidence_ids:
            raise ValueError("every claim must cite at least one evidence id")


@dataclass(frozen=True, slots=True)
class AgentSection:
    role: AgentRole
    summary: str
    claim_ids: tuple[str, ...]
    needs_human_review: bool

    def __post_init__(self) -> None:
        if not self.summary.strip():
            raise ValueError("section summary must not be empty")


@dataclass(frozen=True, slots=True)
class AgentAnalysis:
    """Reviewer-facing analysis. Never an authorization or deployment signal."""

    analysis_id: str
    advisory_id: str
    device_id: str
    model: ModelIdentity
    prompt_version: str
    template_version: str
    used_fallback: bool
    provider_available: bool
    needs_human_review: bool
    confidence: AnalysisConfidence
    validation_errors: tuple[str, ...]
    authoritative: AuthoritativeSnapshot
    claims: tuple[Claim, ...]
    sections: tuple[AgentSection, ...]
    rejected_actions: tuple[str, ...]
    input_fingerprint: str
    generated_at: datetime
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version}")
        if self.generated_at.tzinfo is None:
            raise ValueError("generated_at must be timezone-aware")
        if len(self.sections) != 4:
            raise ValueError("analysis requires exactly four agent sections")
        roles = tuple(item.role for item in self.sections)
        if roles != tuple(AgentRole):
            raise ValueError("sections must appear in AgentRole order")
