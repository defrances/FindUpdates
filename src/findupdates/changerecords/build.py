"""Build versioned change records from deterministic pipeline outputs."""

from __future__ import annotations

from datetime import datetime

from findupdates.agents.models import AgentAnalysis
from findupdates.applicability.models import ApplicabilityResult
from findupdates.changerecords.models import ChangeRecord, LifecycleState
from findupdates.ids import stable_id
from findupdates.inventory.models import DeviceInventory
from findupdates.normalization.models import UpdateAdvisory
from findupdates.risk.models import PolicyResult, RiskAssessment


def idempotency_key(advisory_id: str, deployment_group: str) -> str:
    """Stable key so repeated scans update one GitHub Issue per advisory/scope."""
    return stable_id("change", advisory_id, deployment_group)


def build_change_record(
    advisory: UpdateAdvisory,
    devices: tuple[DeviceInventory, ...],
    applicability: tuple[ApplicabilityResult, ...],
    risk: tuple[RiskAssessment, ...],
    *,
    now: datetime,
    analysis: AgentAnalysis | None = None,
    github_issue_number: int | None = None,
) -> ChangeRecord:
    """Create or refresh the assessed change record for one advisory scope."""
    if not devices or not risk:
        raise ValueError("change record requires at least one device and risk assessment")
    groups = {item.deployment_group for item in devices}
    if len(groups) != 1:
        raise ValueError("one change record covers a single deployment group")
    group = devices[0].deployment_group
    scores = [item.score for item in risk]
    worst = max(risk, key=lambda item: _policy_rank(item.policy_result))
    if max(scores) != worst.score and worst.policy_result not in {
        PolicyResult.HOLD,
        PolicyResult.BLOCK,
    }:
        worst = max(risk, key=lambda item: item.score)
    lifecycle = _lifecycle_for(worst.policy_result)
    evidence = [
        f"advisory:{advisory.advisory_id}",
        *[f"device:{item.device_id}" for item in devices],
        *[f"applicability:{item.result_id}" for item in applicability],
        *[f"risk:{item.assessment_id}" for item in risk],
    ]
    if analysis is not None:
        evidence.append(f"analysis:{analysis.analysis_id}")
    return ChangeRecord(
        change_id=stable_id("change-id", idempotency_key(advisory.advisory_id, group)),
        idempotency_key=idempotency_key(advisory.advisory_id, group),
        lifecycle=lifecycle,
        advisory_ids=(advisory.advisory_id,),
        device_ids=tuple(item.device_id for item in devices),
        deployment_group=group,
        risk_score=max(scores),
        severity=max(risk, key=lambda item: item.score).severity.value,
        policy_result=worst.policy_result.value,
        vendor=advisory.vendor.value,
        evidence_links=tuple(evidence),
        validation_plan=_validation_plan(worst.policy_result, analysis),
        rollout_plan=_rollout_plan(worst.policy_result),
        overrides=(),
        github_issue_number=github_issue_number,
        updated_at=now,
    )


def labels_for(record: ChangeRecord) -> tuple[str, ...]:
    """GitHub labels encoding severity, vendor, lifecycle and policy."""
    return (
        f"severity:{record.severity}",
        f"vendor:{record.vendor}",
        f"lifecycle:{record.lifecycle.value}",
        f"policy:{record.policy_result}",
        "findupdates-change",
        record.idempotency_key,
    )


def _lifecycle_for(policy: PolicyResult) -> LifecycleState:
    if policy is PolicyResult.BLOCK:
        return LifecycleState.FAILED
    if policy is PolicyResult.HOLD:
        return LifecycleState.HELD
    if policy is PolicyResult.ALLOW_ANALYSIS:
        return LifecycleState.ASSESSED
    if policy is PolicyResult.REQUIRE_VALIDATION:
        return LifecycleState.VALIDATION_REQUESTED
    return LifecycleState.AWAITING_APPROVAL


def _policy_rank(policy: PolicyResult) -> int:
    return {
        PolicyResult.ALLOW_ANALYSIS: 0,
        PolicyResult.REQUIRE_VALIDATION: 1,
        PolicyResult.REQUIRE_APPROVAL: 2,
        PolicyResult.HOLD: 3,
        PolicyResult.BLOCK: 4,
    }[policy]


def _validation_plan(policy: PolicyResult, analysis: AgentAnalysis | None) -> str:
    if analysis is not None:
        planning = next(
            (item.summary for item in analysis.sections if item.role.value == "change_planning"),
            "",
        )
        if planning:
            return planning
    if policy in {PolicyResult.HOLD, PolicyResult.BLOCK}:
        return "Validation is not scheduled while policy is HOLD or BLOCK."
    return "Run lab validation against the listed devices before requesting approval."


def _rollout_plan(policy: PolicyResult) -> str:
    if policy in {PolicyResult.HOLD, PolicyResult.BLOCK}:
        return "No rollout. Policy forbids promotion to canary or production."
    return (
        "After validation and required GitHub Environment approval: lab, then canary, "
        "then staged rollout. MVP handoff is simulated/non-production only."
    )
