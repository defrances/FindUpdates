"""Operational control-plane types: alerts, metrics, freshness and kill switch."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

SCHEMA_VERSION = "1.0"


class PipelineStage(StrEnum):
    COLLECT = "collect"
    NORMALIZE = "normalize"
    ENRICH = "enrich"
    INVENTORY = "inventory"
    APPLICABILITY = "applicability"
    RISK = "risk"
    CHANGE = "change"
    NOTIFICATION = "notification"
    VALIDATION = "validation"
    DEPLOYMENT = "deployment"
    HEALTH = "health"
    EVIDENCE = "evidence"


class AlertCode(StrEnum):
    SOURCE_STALE = "source_stale"
    SOURCE_UNOBSERVED = "source_unobserved"
    COLLECTOR_FAILED = "collector_failed"
    DEPLOYMENT_FAILED = "deployment_failed"
    DEPLOYMENT_DISABLED = "deployment_disabled"
    OBSERVABILITY_MISSING = "observability_missing"
    DEAD_LETTER = "dead_letter"
    SCANNER_BLOCK = "scanner_block"


class FreshnessState(StrEnum):
    FRESH = "fresh"
    STALE = "stale"
    UNOBSERVED = "unobserved"


@dataclass(frozen=True, slots=True)
class MetricSample:
    correlation_id: str
    advisory_id: str
    stage: PipelineStage
    name: str
    value: int
    recorded_at: datetime

    def __post_init__(self) -> None:
        if not self.correlation_id.strip() or not self.name.strip():
            raise ValueError("metric correlation_id and name must not be empty")
        if self.recorded_at.tzinfo is None:
            raise ValueError("metric timestamp must be timezone-aware")


@dataclass(frozen=True, slots=True)
class Alert:
    code: AlertCode
    correlation_id: str
    summary: str
    source: str | None
    advisory_id: str | None
    recorded_at: datetime
    healthy: bool = False

    def __post_init__(self) -> None:
        if self.recorded_at.tzinfo is None:
            raise ValueError("alert timestamp must be timezone-aware")
        if self.healthy:
            raise ValueError("operational alerts cannot be marked healthy")


@dataclass(frozen=True, slots=True)
class SourceObservation:
    source: str
    last_success_at: datetime | None
    last_error: str | None
    observed_at: datetime

    def __post_init__(self) -> None:
        if not self.source.strip():
            raise ValueError("source name must not be empty")
        if self.observed_at.tzinfo is None:
            raise ValueError("observation timestamp must be timezone-aware")
        if self.last_success_at is not None and self.last_success_at.tzinfo is None:
            raise ValueError("last_success_at must be timezone-aware")


@dataclass(frozen=True, slots=True)
class FreshnessVerdict:
    source: str
    state: FreshnessState
    window_hours: int
    healthy: bool


@dataclass(frozen=True, slots=True)
class PipelineEvent:
    event_id: str
    correlation_id: str
    stage: PipelineStage
    payload: dict[str, str]
    attempts: int = 0
    last_error: str | None = None
    poisoned: bool = False


@dataclass(frozen=True, slots=True)
class ScannerFinding:
    severity: str
    identifier: str
    location: str
