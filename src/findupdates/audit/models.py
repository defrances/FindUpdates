"""Append-only evidence records and exported bundles."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

SCHEMA_VERSION = "1.0"
GENESIS_HASH = "0" * 64


class EvidenceStage(StrEnum):
    SOURCE_ADVISORY = "source_advisory"
    NORMALIZED_ADVISORY = "normalized_advisory"
    ENRICHMENT = "enrichment"
    INVENTORY_SNAPSHOT = "inventory_snapshot"
    APPLICABILITY = "applicability"
    RISK_POLICY = "risk_policy"
    AI_ANALYSIS = "ai_analysis"
    CHANGE_APPROVAL = "change_approval"
    VALIDATION = "validation"
    PACKAGE_IDENTITY = "package_identity"
    ROLLOUT_PLAN = "rollout_plan"
    DEPLOYMENT_RESULT = "deployment_result"
    HEALTH_OBSERVATION = "health_observation"
    PAUSE_RESUME_ROLLBACK = "pause_resume_rollback"
    CLOSURE = "closure"


class Provenance(StrEnum):
    VENDOR_FACT = "vendor_fact"
    DETERMINISTIC = "deterministic"
    AI_INTERPRETATION = "ai_interpretation"
    HUMAN_DECISION = "human_decision"


@dataclass(frozen=True, slots=True)
class ToolVersions:
    schema: str
    parser: str
    policy: str
    prompt: str | None
    template: str | None

    def __post_init__(self) -> None:
        for value in (self.schema, self.parser, self.policy):
            if not value.strip():
                raise ValueError("schema, parser and policy versions must not be empty")


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    record_id: str
    correlation_id: str
    sequence: int
    stage: EvidenceStage
    provenance: Provenance
    payload_id: str
    content_sha256: str
    prev_integrity_hash: str
    integrity_hash: str
    actor: str
    reason: str
    recorded_at: datetime
    redacted: bool
    supersedes: str | None
    versions: ToolVersions
    authoritative: bool
    workflow_run_id: str | None = None
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version}")
        if self.sequence < 1:
            raise ValueError("sequence must start at 1")
        if self.recorded_at.tzinfo is None:
            raise ValueError("recorded_at must be timezone-aware")
        if not self.actor.strip() or not self.reason.strip():
            raise ValueError("actor and reason must not be empty")
        if len(self.content_sha256) != 64 or len(self.integrity_hash) != 64:
            raise ValueError("hashes must be SHA-256 digests")
        if self.provenance is Provenance.AI_INTERPRETATION and self.authoritative:
            raise ValueError("AI interpretation cannot be marked authoritative")


@dataclass(frozen=True, slots=True)
class EvidenceAttachment:
    name: str
    sha256: str
    media_type: str
    body: str

    def __post_init__(self) -> None:
        if not self.name.strip() or len(self.sha256) != 64:
            raise ValueError("attachment name and sha256 are required")


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    bundle_id: str
    correlation_id: str
    created_at: datetime
    retention_days: int
    chain_tip: str
    manifest_sha256: str
    records: tuple[EvidenceRecord, ...]
    attachments: tuple[EvidenceAttachment, ...]
    narrative: str
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version}")
        if not self.records:
            raise ValueError("evidence bundle requires at least one record")
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        if self.retention_days < 1:
            raise ValueError("retention_days must be positive")
