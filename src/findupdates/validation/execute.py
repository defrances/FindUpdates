"""Run a validation plan against a lab target and produce evidence."""

from __future__ import annotations

from datetime import datetime

from findupdates.agents.redaction import redact_text
from findupdates.collectors.jsonutil import sha256_bytes
from findupdates.ids import stable_id
from findupdates.normalization.models import UpdateAdvisory
from findupdates.validation.models import (
    Artifact,
    CaseResult,
    TestOutcome,
    ValidationCase,
    ValidationPlan,
    ValidationResult,
    VersionSnapshot,
    overall_outcome,
)
from findupdates.validation.simulator import SimulatedTarget, evaluate_case


def run_validation(
    plan: ValidationPlan,
    target: SimulatedTarget,
    *,
    now: datetime,
    advisory: UpdateAdvisory | None = None,
    human_sign_off: frozenset[str] = frozenset(),
) -> ValidationResult:
    """Apply the synthetic update and evaluate every profile case."""
    if plan.device_model != target.device_model:
        raise ValueError("validation profile does not match lab target model")
    known_issues = advisory.known_issues if advisory is not None else ()
    cases = tuple(_run_case(item, target, known_issues, human_sign_off) for item in plan.cases)
    overall = overall_outcome(cases)
    report = _report_bytes(plan, target.baseline, target.after_update, cases)
    artifacts = (
        Artifact("validation-report.json", sha256_bytes(report)),
        Artifact("baseline-versions.json", sha256_bytes(_snapshot_bytes(target.baseline))),
        Artifact("after-versions.json", sha256_bytes(_snapshot_bytes(target.after_update))),
    )
    return ValidationResult(
        result_id=stable_id("validation", plan.profile_id, plan.baseline_id, artifacts[0].sha256),
        profile_id=plan.profile_id,
        profile_version=plan.profile_version,
        device_model=plan.device_model,
        baseline_id=plan.baseline_id,
        overall=overall,
        blocks_promotion=overall is not TestOutcome.PASS,
        baseline=target.baseline,
        after=target.after_update,
        cases=cases,
        artifacts=artifacts,
        generated_at=now,
    )


def _run_case(
    case: ValidationCase,
    target: SimulatedTarget,
    known_issues: tuple[str, ...],
    signed_off: frozenset[str],
) -> CaseResult:
    outcome_name, detail = evaluate_case(
        case, target, signed_off=signed_off, known_issues=known_issues
    )
    safe_detail, _changed = redact_text(detail)
    log = f"{case.case_id}:{outcome_name}:{safe_detail}".encode()
    return CaseResult(
        case_id=case.case_id,
        domain=case.domain,
        mandatory=case.mandatory,
        clinical=case.clinical,
        automatable=case.automatable,
        outcome=TestOutcome(outcome_name),
        detail=safe_detail or "no detail",
        log_sha256=sha256_bytes(log),
    )


def _report_bytes(
    plan: ValidationPlan,
    baseline: VersionSnapshot,
    after: VersionSnapshot,
    cases: tuple[CaseResult, ...],
) -> bytes:
    lines = [
        plan.profile_id,
        plan.baseline_id,
        baseline.os_version,
        after.os_version,
        *[f"{item.case_id}={item.outcome.value}" for item in cases],
    ]
    return "\n".join(lines).encode("utf-8")


def _snapshot_bytes(snapshot: VersionSnapshot) -> bytes:
    return (
        f"{snapshot.os_version}|{snapshot.app_version}|"
        f"{snapshot.driver_version}|{snapshot.firmware_version}"
    ).encode()
