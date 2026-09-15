"""JSON serialization for validation plans and results."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from findupdates.validation.models import (
    SCHEMA_VERSION,
    Artifact,
    CaseResult,
    TestDomain,
    TestOutcome,
    ValidationPlan,
    ValidationResult,
    VersionSnapshot,
)


def plan_to_dict(plan: ValidationPlan) -> dict[str, Any]:
    """Schema-compatible validation plan mapping."""
    return {
        "schema_version": SCHEMA_VERSION,
        "profile_id": plan.profile_id,
        "profile_version": plan.profile_version,
        "device_model": plan.device_model,
        "baseline_id": plan.baseline_id,
        "cases": [
            {
                "case_id": item.case_id,
                "domain": item.domain.value,
                "title": item.title,
                "mandatory": item.mandatory,
                "automatable": item.automatable,
                "clinical": item.clinical,
                "timeout_seconds": item.timeout_seconds,
            }
            for item in plan.cases
        ],
    }


def result_to_dict(result: ValidationResult) -> dict[str, Any]:
    """Schema-compatible validation result mapping."""
    return {
        "schema_version": SCHEMA_VERSION,
        "result_id": result.result_id,
        "profile_id": result.profile_id,
        "profile_version": result.profile_version,
        "device_model": result.device_model,
        "baseline_id": result.baseline_id,
        "overall": result.overall.value,
        "blocks_promotion": result.blocks_promotion,
        "baseline": _snapshot(result.baseline),
        "after": _snapshot(result.after),
        "cases": [_case(item) for item in result.cases],
        "artifacts": [{"name": item.name, "sha256": item.sha256} for item in result.artifacts],
        "generated_at": _datetime(result.generated_at),
    }


def canonical_result_json(result: ValidationResult) -> str:
    """Stable JSON for evidence hashing."""
    return json.dumps(
        result_to_dict(result),
        ensure_ascii=True,
        indent=None,
        separators=(",", ":"),
        sort_keys=True,
    )


def dict_to_result(payload: dict[str, Any]) -> ValidationResult:
    """Parse a stored validation result. Used by the promotion gate."""
    cases = tuple(_parse_case(item) for item in payload["cases"])
    return ValidationResult(
        result_id=str(payload["result_id"]),
        profile_id=str(payload["profile_id"]),
        profile_version=str(payload["profile_version"]),
        device_model=str(payload["device_model"]),
        baseline_id=str(payload["baseline_id"]),
        overall=TestOutcome(str(payload["overall"])),
        blocks_promotion=bool(payload["blocks_promotion"]),
        baseline=_parse_snapshot(payload["baseline"]),
        after=_parse_snapshot(payload["after"]),
        cases=cases,
        artifacts=tuple(
            Artifact(str(item["name"]), str(item["sha256"]))
            for item in payload.get("artifacts", [])
        ),
        generated_at=_parse_datetime(str(payload["generated_at"])),
    )


def _case(item: CaseResult) -> dict[str, object]:
    return {
        "case_id": item.case_id,
        "domain": item.domain.value,
        "mandatory": item.mandatory,
        "clinical": item.clinical,
        "automatable": item.automatable,
        "outcome": item.outcome.value,
        "detail": item.detail,
        "log_sha256": item.log_sha256,
    }


def _parse_case(value: object) -> CaseResult:
    if not isinstance(value, dict):
        raise ValueError("case result must be an object")
    return CaseResult(
        case_id=str(value["case_id"]),
        domain=TestDomain(str(value["domain"])),
        mandatory=bool(value["mandatory"]),
        clinical=bool(value["clinical"]),
        automatable=bool(value["automatable"]),
        outcome=TestOutcome(str(value["outcome"])),
        detail=str(value["detail"]),
        log_sha256=str(value["log_sha256"]),
    )


def _snapshot(item: VersionSnapshot) -> dict[str, str]:
    return {
        "os_version": item.os_version,
        "app_version": item.app_version,
        "driver_version": item.driver_version,
        "firmware_version": item.firmware_version,
    }


def _parse_snapshot(value: object) -> VersionSnapshot:
    if not isinstance(value, dict):
        raise ValueError("snapshot must be an object")
    return VersionSnapshot(
        os_version=str(value["os_version"]),
        app_version=str(value["app_version"]),
        driver_version=str(value["driver_version"]),
        firmware_version=str(value["firmware_version"]),
    )


def _datetime(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("generated_at must be timezone-aware")
    return parsed
