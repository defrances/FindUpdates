"""Post-validate provider JSON. Model output cannot become a safety decision."""

from __future__ import annotations

import re
from datetime import datetime

from findupdates.agents.context import AgentInput, snapshot_to_dict
from findupdates.agents.models import (
    PROMPT_VERSION,
    SCHEMA_VERSION,
    TEMPLATE_VERSION,
    AgentAnalysis,
    AgentRole,
    AgentSection,
    AnalysisConfidence,
    Claim,
    ClaimKind,
    ModelIdentity,
)
from findupdates.agents.provider import OfflineProvider
from findupdates.ids import stable_id

_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_FORBIDDEN_KEYS = {"tools", "function_call", "tool_call", "actions", "deploy", "approve"}
_FORBIDDEN_ACTION_NAMES = {
    "deploy",
    "approve_production",
    "set_policy",
    "change_score",
    "change_applicability",
    "pause_safety",
}


def bind_analysis(
    raw: dict[str, object],
    agent_input: AgentInput,
    *,
    model: ModelIdentity,
    used_fallback: bool,
    provider_available: bool,
    fingerprint: str,
    generated_at: datetime,
) -> AgentAnalysis:
    """Copy authoritative facts from input and keep only evidence-backed claims."""
    errors: list[str] = []
    rejected = _forbidden_actions(raw)
    if rejected:
        errors.extend(f"rejected action {item}" for item in rejected)
    if _authoritative_tamper(raw, agent_input):
        errors.append("provider attempted to change authoritative fields")
        rejected = tuple(dict.fromkeys((*rejected, "authoritative_override")))

    allowed_evidence = {item.evidence_id for item in agent_input.evidence}
    claims, claim_errors = _claims(raw.get("claims"), allowed_evidence, agent_input)
    errors.extend(claim_errors)
    if agent_input.redacted:
        errors.append("source text required redaction")
    if agent_input.missing_fields:
        errors.append("incomplete advisory fields: " + ",".join(agent_input.missing_fields))

    if not claims:
        fallback = OfflineProvider().complete(agent_input.provider_payload())
        claims, extra = _claims(fallback.get("claims"), allowed_evidence, agent_input)
        errors.extend(extra)
        errors.append("provider claims were empty or invalid; used template claims")
        raw = fallback
        used_fallback = True

    claim_ids = {item.claim_id for item in claims}
    sections = _sections(raw.get("sections"), claim_ids, errors)
    confidence = _confidence(raw.get("confidence"), errors)
    needs_review = True
    if (
        not errors
        and agent_input.authoritative.policy_result == "ALLOW_ANALYSIS"
        and agent_input.authoritative.applicability_verdict == "not_affected"
    ):
        needs_review = bool(raw.get("needs_human_review", False))
    elif raw.get("needs_human_review") is False and errors:
        errors.append("needs_human_review cannot be false when validation failed")

    return AgentAnalysis(
        analysis_id=stable_id("analysis", fingerprint),
        advisory_id=agent_input.authoritative.advisory_id,
        device_id=agent_input.authoritative.device_id,
        model=model,
        prompt_version=PROMPT_VERSION,
        template_version=TEMPLATE_VERSION,
        used_fallback=used_fallback,
        provider_available=provider_available,
        needs_human_review=needs_review or bool(errors) or bool(rejected),
        confidence=confidence,
        validation_errors=tuple(dict.fromkeys(errors)),
        authoritative=agent_input.authoritative,
        claims=claims,
        sections=sections,
        rejected_actions=rejected,
        input_fingerprint=fingerprint,
        generated_at=generated_at,
        schema_version=SCHEMA_VERSION,
    )


def _claims(
    value: object,
    allowed_evidence: set[str],
    agent_input: AgentInput,
) -> tuple[tuple[Claim, ...], list[str]]:
    errors: list[str] = []
    if not isinstance(value, list):
        return (), ["claims must be an array"]
    items: list[Claim] = []
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            errors.append(f"claim {index} is not an object")
            continue
        try:
            kind = ClaimKind(str(raw.get("kind", "")))
            evidence_ids = tuple(
                str(item) for item in raw.get("evidence_ids", []) if str(item).strip()
            )
            claim = Claim(
                claim_id=str(raw.get("claim_id", "")).strip(),
                kind=kind,
                text=str(raw.get("text", "")).strip(),
                evidence_ids=evidence_ids,
            )
        except (TypeError, ValueError) as exc:
            errors.append(f"claim {index} rejected: {exc}")
            continue
        if any(item not in allowed_evidence for item in claim.evidence_ids):
            errors.append(f"claim {claim.claim_id} cites unknown evidence")
            continue
        invented = [
            cve
            for cve in _CVE.findall(claim.text)
            if cve.upper() not in {item.upper() for item in agent_input.allowed_cve_ids}
        ]
        if invented:
            errors.append(f"claim {claim.claim_id} invents identifiers {','.join(invented)}")
            continue
        items.append(claim)
    return tuple(items), errors


def _sections(value: object, claim_ids: set[str], errors: list[str]) -> tuple[AgentSection, ...]:
    by_role: dict[AgentRole, AgentSection] = {}
    if isinstance(value, list):
        for raw in value:
            if not isinstance(raw, dict):
                continue
            try:
                role = AgentRole(str(raw.get("role", "")))
                summary = str(raw.get("summary", "")).strip()
                ids = tuple(
                    item for item in _as_str_list(raw.get("claim_ids")) if item in claim_ids
                )
                by_role[role] = AgentSection(
                    role=role,
                    summary=summary or "Section required human review.",
                    claim_ids=ids,
                    needs_human_review=bool(raw.get("needs_human_review", True)),
                )
            except ValueError:
                errors.append("provider returned an unknown agent role")
    fallback_summary = {
        AgentRole.UPDATE_INTELLIGENCE: "Vendor fields were copied from structured evidence.",
        AgentRole.APPLICABILITY_REVIEW: "Applicability remains the deterministic matcher result.",
        AgentRole.RISK_EXPLANATION: "Risk score and policy remain the deterministic engine result.",
        AgentRole.CHANGE_PLANNING: "No deployment is authorized by this analysis.",
    }
    sections = []
    for role in AgentRole:
        section = by_role.get(role)
        if section is None:
            errors.append(f"missing section {role.value}")
            section = AgentSection(role, fallback_summary[role], (), True)
        sections.append(section)
    return tuple(sections)


def _confidence(value: object, errors: list[str]) -> AnalysisConfidence:
    if errors:
        return AnalysisConfidence.LOW
    try:
        return AnalysisConfidence(str(value))
    except ValueError:
        return AnalysisConfidence.UNKNOWN


def _forbidden_actions(raw: dict[str, object]) -> tuple[str, ...]:
    found: list[str] = []
    for key in raw:
        lowered = str(key).lower()
        if lowered in _FORBIDDEN_KEYS:
            found.append(lowered)
    for field in ("tools", "actions", "function_call", "tool_call"):
        value = raw.get(field)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    name = str(item.get("name") or item.get("action") or "").lower()
                    if name in _FORBIDDEN_ACTION_NAMES:
                        found.append(name)
                elif str(item).lower() in _FORBIDDEN_ACTION_NAMES:
                    found.append(str(item).lower())
        elif isinstance(value, dict):
            name = str(value.get("name") or "").lower()
            if name in _FORBIDDEN_ACTION_NAMES:
                found.append(name)
    return tuple(dict.fromkeys(found))


def _authoritative_tamper(raw: dict[str, object], agent_input: AgentInput) -> bool:
    provided = raw.get("authoritative")
    if provided is None:
        return False
    if not isinstance(provided, dict):
        return True
    expected = snapshot_to_dict(agent_input.authoritative)
    return provided != expected


def _as_str_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]
