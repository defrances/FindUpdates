"""Deterministic risk scoring and policy evaluation."""

from __future__ import annotations

from datetime import datetime

from findupdates.applicability.models import ApplicabilityResult, ApplicabilityVerdict
from findupdates.ids import stable_id
from findupdates.inventory.models import DeviceInventory
from findupdates.normalization.models import UpdateAdvisory
from findupdates.risk.gates import apply_hard_gates
from findupdates.risk.models import (
    PolicyDocument,
    PolicyResult,
    RiskAssessment,
    SeverityBand,
    stricter_result,
)
from findupdates.risk.policy import load_policy
from findupdates.risk.score import clamp_score, score_contributions


def assess(
    advisory: UpdateAdvisory,
    device: DeviceInventory,
    applicability: ApplicabilityResult,
    *,
    now: datetime,
    policy: PolicyDocument | None = None,
    previous_fingerprint: str | None = None,
) -> RiskAssessment:
    """Produce a versioned risk assessment. AI is not consulted."""
    rules = policy or load_policy()
    contributions = score_contributions(advisory, device, rules)
    score = clamp_score(contributions, rules.score_cap)
    severity = _band_for(score, rules)
    band_result = rules.band_policy[severity]
    if applicability.verdict is ApplicabilityVerdict.NOT_AFFECTED:
        policy_result = PolicyResult.ALLOW_ANALYSIS
        gates: tuple[str, ...] = ()
    else:
        policy_result, gates = apply_hard_gates(
            advisory=advisory,
            device=device,
            applicability=applicability,
            policy=rules,
            band_result=band_result,
        )
        if applicability.blocks_automatic_deployment:
            policy_result = stricter_result(policy_result, PolicyResult.REQUIRE_VALIDATION)
    fingerprint = input_fingerprint(advisory, device, applicability, rules)
    reasons = [item.code for item in contributions]
    reasons.append("SCORE_BAND")
    reasons.extend(gates)
    if applicability.verdict is ApplicabilityVerdict.NOT_AFFECTED:
        reasons.append("NOT_AFFECTED")
    return RiskAssessment(
        assessment_id=stable_id("risk", fingerprint),
        advisory_id=advisory.advisory_id,
        device_id=device.device_id,
        policy_version=rules.version,
        score=score,
        severity=severity,
        policy_result=policy_result,
        reason_codes=tuple(dict.fromkeys(reasons)),
        contributions=contributions,
        hard_gates_applied=gates,
        input_fingerprint=fingerprint,
        assessed_at=now,
        needs_reassessment=previous_fingerprint is not None and previous_fingerprint != fingerprint,
    )


def input_fingerprint(
    advisory: UpdateAdvisory,
    device: DeviceInventory,
    applicability: ApplicabilityResult,
    policy: PolicyDocument,
) -> str:
    """Hash inputs that must trigger reassessment, including policy identity."""
    revised = advisory.revised_at or advisory.published_at
    return stable_id(
        "risk-input",
        policy.version,
        policy.source_sha256,
        advisory.advisory_id,
        revised.isoformat(),
        advisory.provenance.raw_sha256,
        device.device_id,
        device.inventory_timestamp.isoformat(),
        applicability.input_fingerprint,
        applicability.verdict.value,
        applicability.confidence.value,
    )


def _band_for(score: int, policy: PolicyDocument) -> SeverityBand:
    for band, (low, high) in policy.bands.items():
        if low <= score <= high:
            return band
    raise ValueError(f"score {score} is outside configured bands")
