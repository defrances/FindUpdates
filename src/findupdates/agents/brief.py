"""Run-level Agentic AI briefing assembled from bound analyses."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from findupdates.agents.models import AgentAnalysis, AgentRole
from findupdates.ids import stable_id

_ROLE_HEADINGS = {
    AgentRole.UPDATE_INTELLIGENCE: "Update intelligence",
    AgentRole.APPLICABILITY_REVIEW: "Applicability review",
    AgentRole.RISK_EXPLANATION: "Risk explanation",
    AgentRole.CHANGE_PLANNING: "Change planning",
}


@dataclass(frozen=True, slots=True)
class BriefSource:
    """One bound analysis plus the advisory/group labels used in the briefing."""

    title: str
    deployment_group: str
    analysis: AgentAnalysis


@dataclass(frozen=True, slots=True)
class UpdateBriefing:
    """Reviewer-facing analysis of all updates from one pipeline run."""

    briefing_id: str
    correlation_id: str
    generated_at: datetime
    used_fallback: bool
    items: tuple[BriefSource, ...]
    markdown: str


def brief_updates(
    sources: tuple[BriefSource, ...],
    *,
    correlation_id: str,
    now: datetime,
) -> UpdateBriefing:
    """Compose a run-level briefing. Deterministic policy is only echoed."""
    if not sources:
        raise ValueError("update briefing requires at least one bound analysis")
    briefing_id = stable_id("update-briefing", correlation_id, now.isoformat())
    used_fallback = any(item.analysis.used_fallback for item in sources)
    markdown = render_update_briefing(
        sources,
        correlation_id=correlation_id,
        generated_at=now,
        used_fallback=used_fallback,
    )
    return UpdateBriefing(
        briefing_id=briefing_id,
        correlation_id=correlation_id,
        generated_at=now,
        used_fallback=used_fallback,
        items=sources,
        markdown=markdown,
    )


def render_update_briefing(
    sources: tuple[BriefSource, ...],
    *,
    correlation_id: str,
    generated_at: datetime,
    used_fallback: bool,
) -> str:
    """Markdown briefing for operators and the GitHub Job Summary."""
    stamp = generated_at.isoformat().replace("+00:00", "Z")
    lines = [
        "# Agentic AI analysis of updates",
        "",
        "This briefing is reviewer-facing. It is not an authorization to deploy,",
        "approve, or change `policy_result`.",
        "",
        f"- correlation=`{correlation_id}`",
        f"- generated=`{stamp}`",
        f"- updates_analyzed=`{len(sources)}`",
        f"- fallback=`{str(used_fallback).lower()}`",
        "",
        "## Policy snapshot",
        "",
        "Deterministic pipeline results echoed by the agents:",
        "",
    ]
    for item in sources:
        analysis = item.analysis
        auth = analysis.authoritative
        title = item.title.strip() or analysis.advisory_id
        lines.append(
            f"- `{analysis.advisory_id}` `{title}` group=`{item.deployment_group}` "
            f"device=`{analysis.device_id}` verdict=`{auth.applicability_verdict}` "
            f"policy=`{auth.policy_result}` score={auth.risk_score}"
        )
    lines.append("")
    for item in sources:
        analysis = item.analysis
        auth = analysis.authoritative
        title = item.title.strip() or analysis.advisory_id
        lines.extend(
            [
                f"## {analysis.advisory_id} — {title}",
                "",
                f"Device `{analysis.device_id}` in `{item.deployment_group}`. "
                f"Analysis `{analysis.analysis_id}` "
                f"fallback=`{str(analysis.used_fallback).lower()}` "
                f"confidence=`{analysis.confidence.value}`.",
                "",
            ]
        )
        for section in analysis.sections:
            heading = _ROLE_HEADINGS.get(section.role, section.role.value)
            lines.append(f"### {heading}")
            lines.append("")
            lines.append(section.summary)
            lines.append("")
        if not analysis.sections:
            lines.append("No agent sections were bound for this update.")
            lines.append("")
    return "\n".join(lines)


def briefing_to_dict(briefing: UpdateBriefing) -> dict[str, object]:
    """JSON mapping for `analysis/run.json`. Token fields are not included."""
    return {
        "briefing_id": briefing.briefing_id,
        "correlation_id": briefing.correlation_id,
        "generated_at": briefing.generated_at.isoformat().replace("+00:00", "Z"),
        "used_fallback": briefing.used_fallback,
        "item_count": len(briefing.items),
        "items": [
            {
                "advisory_id": item.analysis.advisory_id,
                "title": item.title,
                "device_id": item.analysis.device_id,
                "deployment_group": item.deployment_group,
                "policy_result": item.analysis.authoritative.policy_result,
                "risk_score": item.analysis.authoritative.risk_score,
                "verdict": item.analysis.authoritative.applicability_verdict,
                "analysis_id": item.analysis.analysis_id,
                "used_fallback": item.analysis.used_fallback,
                "sections": [
                    {"role": section.role.value, "summary": section.summary}
                    for section in item.analysis.sections
                ],
            }
            for item in briefing.items
        ],
    }
