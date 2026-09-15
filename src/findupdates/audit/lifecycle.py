"""Record a full update lifecycle as an append-only evidence chain."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from findupdates.audit.export import export_bundle
from findupdates.audit.models import (
    EvidenceBundle,
    EvidenceRecord,
    EvidenceStage,
    Provenance,
    ToolVersions,
)
from findupdates.audit.store import EvidenceStore
from findupdates.ids import stable_id


@dataclass(frozen=True, slots=True)
class LifecycleFacts:
    """Facts needed to reconstruct why a device was or was not updated."""

    advisory_id: str
    source_revision: str
    source_hash: str
    parser_version: str
    device_id: str
    inventory_hash: str
    applicability_verdict: str
    applicability_confidence: str
    risk_score: int
    policy_result: str
    policy_version: str
    original_policy_result: str
    ai_used: bool
    ai_prompt_version: str | None
    ai_template_version: str | None
    ai_model: str | None
    ai_text: str | None
    change_id: str
    approver: str
    approval_reason: str
    workflow_run_id: str
    override_reason: str | None
    validation_overall: str
    package_id: str
    package_sha256: str
    ring: str
    ring_members: tuple[str, ...]
    deployment_id: str | None
    deployment_status: str
    health_overall: str
    ops_event: str | None
    closure: str


def default_versions(facts: LifecycleFacts) -> ToolVersions:
    return ToolVersions(
        schema="1.0",
        parser=facts.parser_version,
        policy=facts.policy_version,
        prompt=facts.ai_prompt_version,
        template=facts.ai_template_version,
    )


def record_lifecycle(
    store: EvidenceStore,
    facts: LifecycleFacts,
    *,
    now: datetime,
    correlation_id: str | None = None,
) -> tuple[str, tuple[EvidenceRecord, ...]]:
    """Append all 15 chain stages. Overrides add a new human record; they do not rewrite policy."""
    corr = correlation_id or stable_id("lifecycle", facts.advisory_id, facts.device_id)
    versions = default_versions(facts)
    deployed = facts.deployment_status in {"succeeded", "rolled_back"} and facts.deployment_id

    def _add(
        stage: EvidenceStage,
        provenance: Provenance,
        payload: dict[str, Any],
        *,
        actor: str,
        reason: str,
        authoritative: bool,
        workflow_run_id: str | None = None,
        supersedes: str | None = None,
    ) -> EvidenceRecord:
        return store.append(
            correlation_id=corr,
            stage=stage,
            provenance=provenance,
            payload=payload,
            actor=actor,
            reason=reason,
            now=now,
            versions=versions,
            authoritative=authoritative,
            workflow_run_id=workflow_run_id,
            supersedes=supersedes,
        )

    _add(
        EvidenceStage.SOURCE_ADVISORY,
        Provenance.VENDOR_FACT,
        {
            "advisory_id": facts.advisory_id,
            "source_revision": facts.source_revision,
            "source_hash": facts.source_hash,
        },
        actor="collector",
        reason="ingest vendor advisory revision",
        authoritative=True,
    )
    _add(
        EvidenceStage.NORMALIZED_ADVISORY,
        Provenance.DETERMINISTIC,
        {"advisory_id": facts.advisory_id, "parser_version": facts.parser_version},
        actor="normalizer",
        reason="canonical UpdateAdvisory",
        authoritative=True,
    )
    _add(
        EvidenceStage.ENRICHMENT,
        Provenance.VENDOR_FACT,
        {"advisory_id": facts.advisory_id, "note": "NVD/KEV are prioritization only"},
        actor="enrichment",
        reason="attach CVSS/KEV without overwriting vendor product status",
        authoritative=True,
    )
    _add(
        EvidenceStage.INVENTORY_SNAPSHOT,
        Provenance.DETERMINISTIC,
        {"device_id": facts.device_id, "inventory_hash": facts.inventory_hash},
        actor="inventory",
        reason="freeze the target snapshot used for this decision",
        authoritative=True,
    )
    _add(
        EvidenceStage.APPLICABILITY,
        Provenance.DETERMINISTIC,
        {
            "device_id": facts.device_id,
            "verdict": facts.applicability_verdict,
            "confidence": facts.applicability_confidence,
        },
        actor="applicability-engine",
        reason="deterministic match; unknown is never not_affected",
        authoritative=True,
    )
    policy = _add(
        EvidenceStage.RISK_POLICY,
        Provenance.DETERMINISTIC,
        {
            "device_id": facts.device_id,
            "score": facts.risk_score,
            "policy_result": facts.original_policy_result,
            "policy_version": facts.policy_version,
        },
        actor="risk-engine",
        reason="deterministic score and hard gates",
        authoritative=True,
    )
    if facts.ai_used:
        _add(
            EvidenceStage.AI_ANALYSIS,
            Provenance.AI_INTERPRETATION,
            {
                "model": facts.ai_model,
                "prompt_version": facts.ai_prompt_version,
                "template_version": facts.ai_template_version,
                "text": facts.ai_text,
                "authoritative": False,
            },
            actor="analysis-agent",
            reason="non-authoritative explanation only",
            authoritative=False,
        )
    else:
        _add(
            EvidenceStage.AI_ANALYSIS,
            Provenance.DETERMINISTIC,
            {"ai_used": False},
            actor="analysis-agent",
            reason="AI was not used for this lifecycle",
            authoritative=True,
        )
    _add(
        EvidenceStage.CHANGE_APPROVAL,
        Provenance.HUMAN_DECISION,
        {
            "change_id": facts.change_id,
            "approver": facts.approver,
            "policy_result_at_approval": facts.policy_result,
        },
        actor=facts.approver,
        reason=facts.approval_reason,
        authoritative=True,
        workflow_run_id=facts.workflow_run_id,
    )
    if facts.override_reason:
        _add(
            EvidenceStage.CHANGE_APPROVAL,
            Provenance.HUMAN_DECISION,
            {
                "change_id": facts.change_id,
                "override": True,
                "original_record_id": policy.record_id,
                "original_policy_result": facts.original_policy_result,
                "note": "override is additive; original automated decision is unchanged",
            },
            actor=facts.approver,
            reason=facts.override_reason,
            authoritative=True,
            workflow_run_id=facts.workflow_run_id,
        )
    _add(
        EvidenceStage.VALIDATION,
        Provenance.DETERMINISTIC,
        {"device_id": facts.device_id, "overall": facts.validation_overall},
        actor="validation-lab",
        reason="lab evidence; installer success is not a clinical pass",
        authoritative=True,
    )
    _add(
        EvidenceStage.PACKAGE_IDENTITY,
        Provenance.DETERMINISTIC,
        {"package_id": facts.package_id, "sha256": facts.package_sha256},
        actor="deployment-prepare",
        reason="pin package identity before execution",
        authoritative=True,
    )
    _add(
        EvidenceStage.ROLLOUT_PLAN,
        Provenance.DETERMINISTIC,
        {"ring": facts.ring, "members": list(facts.ring_members)},
        actor="rollout",
        reason="frozen ring membership at authorization",
        authoritative=True,
    )
    _add(
        EvidenceStage.DEPLOYMENT_RESULT,
        Provenance.DETERMINISTIC,
        {
            "deployment_id": facts.deployment_id,
            "status": facts.deployment_status,
            "device_id": facts.device_id,
            "updated": bool(deployed),
        },
        actor="deployment-adapter",
        reason="backend result for the authorized target set",
        authoritative=True,
    )
    _add(
        EvidenceStage.HEALTH_OBSERVATION,
        Provenance.DETERMINISTIC,
        {"device_id": facts.device_id, "overall": facts.health_overall},
        actor="monitoring",
        reason="post-deploy health; missing telemetry is not healthy",
        authoritative=True,
    )
    rollback = bool(facts.ops_event and "rollback" in facts.ops_event)
    _add(
        EvidenceStage.PAUSE_RESUME_ROLLBACK,
        Provenance.HUMAN_DECISION if rollback else Provenance.DETERMINISTIC,
        {"device_id": facts.device_id, "event": facts.ops_event or "none"},
        actor=facts.approver if rollback else "monitoring",
        reason=facts.ops_event or "no pause or rollback",
        authoritative=True,
        workflow_run_id=facts.workflow_run_id if facts.ops_event else None,
    )
    _add(
        EvidenceStage.CLOSURE,
        Provenance.HUMAN_DECISION,
        {
            "device_id": facts.device_id,
            "closure": facts.closure,
            "updated": bool(deployed and facts.applicability_verdict == "affected"),
            "why": _why(facts),
        },
        actor=facts.approver,
        reason=facts.closure,
        authoritative=True,
        workflow_run_id=facts.workflow_run_id,
    )
    return corr, store.records(corr)


def render_narrative(facts: LifecycleFacts, correlation_id: str) -> str:
    """Human-readable reconstruction. AI text is labeled non-authoritative."""
    updated = facts.deployment_status == "succeeded" and facts.applicability_verdict == "affected"
    outcome = "updated" if updated else "not updated"
    lines = [
        f"# Evidence package `{correlation_id}`",
        "",
        f"Device `{facts.device_id}` was **{outcome}**.",
        "",
        "## Authoritative deterministic decisions",
        (
            f"- Source advisory `{facts.advisory_id}` revision `{facts.source_revision}` "
            f"hash `{facts.source_hash}`."
        ),
        f"- Inventory snapshot `{facts.inventory_hash}`.",
        (
            f"- Applicability `{facts.applicability_verdict}` "
            f"(confidence `{facts.applicability_confidence}`)."
        ),
        (
            f"- Original policy `{facts.original_policy_result}` score `{facts.risk_score}` "
            f"(policy {facts.policy_version})."
        ),
        f"- Validation `{facts.validation_overall}`.",
        f"- Package `{facts.package_id}` sha256 `{facts.package_sha256}`.",
        f"- Ring `{facts.ring}` members: {', '.join(facts.ring_members)}.",
        f"- Deployment `{facts.deployment_id or 'none'}` status `{facts.deployment_status}`.",
        f"- Health `{facts.health_overall}`; ops `{facts.ops_event or 'none'}`.",
        "",
        "## Human decisions",
        (
            f"- Approver `{facts.approver}`: {facts.approval_reason} "
            f"(workflow `{facts.workflow_run_id}`)."
        ),
        f"- Closure: {facts.closure}.",
    ]
    if facts.override_reason:
        lines.append(
            f"- Additive override recorded: {facts.override_reason}. "
            f"Original automated policy `{facts.original_policy_result}` remains in the chain."
        )
    lines.extend(["", "## AI interpretation (not authoritative)"])
    if facts.ai_used:
        lines.append(
            f"- Model `{facts.ai_model}` prompt `{facts.ai_prompt_version}` "
            f"template `{facts.ai_template_version}`."
        )
        lines.append(f"- {facts.ai_text or '(empty)'}")
        lines.append("- This text cannot change applicability, score, policy, approval or targets.")
    else:
        lines.append("- AI was not used.")
    lines.extend(["", "## Why this device", _why(facts)])
    return "\n".join(lines) + "\n"


def bundle_lifecycle(
    store: EvidenceStore,
    facts: LifecycleFacts,
    *,
    now: datetime,
) -> EvidenceBundle:
    correlation_id, _records = record_lifecycle(store, facts, now=now)
    return export_bundle(
        store,
        correlation_id,
        now=now,
        narrative=render_narrative(facts, correlation_id),
    )


def _why(facts: LifecycleFacts) -> str:
    if facts.applicability_verdict != "affected":
        return (
            f"Device {facts.device_id} was not updated because applicability was "
            f"{facts.applicability_verdict}."
        )
    if facts.original_policy_result in {"HOLD", "BLOCK"}:
        return (
            f"Device {facts.device_id} was not deployed because deterministic policy was "
            f"{facts.original_policy_result}."
        )
    if facts.deployment_status == "succeeded":
        return (
            f"Device {facts.device_id} was updated: affected, policy {facts.policy_result}, "
            f"validated {facts.validation_overall}, approved by {facts.approver}, "
            f"package {facts.package_id}."
        )
    return (
        f"Device {facts.device_id} was applicable but not left in a succeeded deployment "
        f"(status {facts.deployment_status}, ops {facts.ops_event or 'none'})."
    )
