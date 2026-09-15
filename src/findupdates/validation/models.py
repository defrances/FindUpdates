"""Validation plans, per-case outcomes and promotion blocking."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

SCHEMA_VERSION = "1.0"


class TestDomain(StrEnum):
    BOOT = "boot"
    OS_HEALTH = "os_health"
    DRIVER_FIRMWARE = "driver_firmware"
    MEDICAL_APPLICATION = "medical_application"
    CONNECTIVITY = "connectivity"
    RESOURCES = "resources"
    CRITICAL_SERVICE = "critical_service"
    DEVICE_IO = "device_io"
    ROLLBACK = "rollback"
    KNOWN_ISSUE = "known_issue"


class TestOutcome(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True, slots=True)
class ValidationCase:
    case_id: str
    domain: TestDomain
    title: str
    mandatory: bool
    automatable: bool
    clinical: bool
    timeout_seconds: int

    def __post_init__(self) -> None:
        if not self.case_id.strip() or not self.title.strip():
            raise ValueError("validation case id and title must not be empty")
        if self.timeout_seconds < 1:
            raise ValueError("timeout_seconds must be positive")


@dataclass(frozen=True, slots=True)
class ValidationPlan:
    profile_id: str
    profile_version: str
    device_model: str
    baseline_id: str
    cases: tuple[ValidationCase, ...]
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version}")
        if not self.cases:
            raise ValueError("validation plan requires at least one case")


@dataclass(frozen=True, slots=True)
class VersionSnapshot:
    os_version: str
    app_version: str
    driver_version: str
    firmware_version: str

    def __post_init__(self) -> None:
        for value in (
            self.os_version,
            self.app_version,
            self.driver_version,
            self.firmware_version,
        ):
            if not value.strip():
                raise ValueError("version snapshot fields must not be empty")


@dataclass(frozen=True, slots=True)
class CaseResult:
    case_id: str
    domain: TestDomain
    mandatory: bool
    clinical: bool
    automatable: bool
    outcome: TestOutcome
    detail: str
    log_sha256: str

    def __post_init__(self) -> None:
        if len(self.log_sha256) != 64:
            raise ValueError("log_sha256 must be a SHA-256 hex digest")
        if not self.detail.strip():
            raise ValueError("case detail must not be empty")


@dataclass(frozen=True, slots=True)
class Artifact:
    name: str
    sha256: str

    def __post_init__(self) -> None:
        if not self.name.strip() or len(self.sha256) != 64:
            raise ValueError("artifact name and sha256 are required")


@dataclass(frozen=True, slots=True)
class ValidationResult:
    result_id: str
    profile_id: str
    profile_version: str
    device_model: str
    baseline_id: str
    overall: TestOutcome
    blocks_promotion: bool
    baseline: VersionSnapshot
    after: VersionSnapshot
    cases: tuple[CaseResult, ...]
    artifacts: tuple[Artifact, ...]
    generated_at: datetime
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version}")
        if self.generated_at.tzinfo is None:
            raise ValueError("generated_at must be timezone-aware")
        if not self.cases:
            raise ValueError("validation result requires case outcomes")


def overall_outcome(cases: tuple[CaseResult, ...]) -> TestOutcome:
    """Mandatory FAIL/BLOCKED/INCONCLUSIVE is never a PASS."""
    mandatory = [item for item in cases if item.mandatory]
    if any(item.outcome is TestOutcome.FAIL for item in mandatory):
        return TestOutcome.FAIL
    if any(item.outcome is TestOutcome.BLOCKED for item in mandatory):
        return TestOutcome.BLOCKED
    if any(item.outcome is TestOutcome.INCONCLUSIVE for item in mandatory):
        return TestOutcome.INCONCLUSIVE
    return TestOutcome.PASS


def blocks_promotion(result: ValidationResult) -> bool:
    """Canary/production cannot proceed unless every required case passed."""
    return result.overall is not TestOutcome.PASS
