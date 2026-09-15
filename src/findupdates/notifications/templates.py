"""Render reviewer-facing notification text. No PHI, no secrets."""

from __future__ import annotations

from findupdates.notifications.models import NotificationEvent, NotificationKind

_TITLES = {
    NotificationKind.ADVISORY: "FindUpdates advisory",
    NotificationKind.OPERATIONAL_FAILURE: "FindUpdates operational failure",
    NotificationKind.ESCALATION: "FindUpdates unacknowledged escalation",
    NotificationKind.DIGEST: "FindUpdates low-priority digest",
}


def render_markdown(event: NotificationEvent) -> str:
    """HIGH/CRITICAL/EMERGENCY and failure templates share a structured body."""
    heading = _TITLES[event.kind]
    previous = ""
    if event.previous_state is not None:
        previous = (
            "\nPrevious state: "
            f"{event.previous_state.severity}/{event.previous_state.policy_result} "
            f"devices={event.previous_state.affected_device_count} "
            f"kev={event.previous_state.kev} "
            f"workflow={event.previous_state.workflow_state}\n"
        )
    ack = "required" if event.acknowledgement_required else "not required"
    return (
        f"## {heading} `{event.severity}`\n\n"
        f"- Advisories: {', '.join(event.advisory_ids) or 'none'}\n"
        f"- CVE: {', '.join(event.cve_ids) or 'none'}\n"
        f"- Packages: {', '.join(event.package_ids) or 'none'}\n"
        f"- Vendor: `{event.vendor}`\n"
        f"- Risk: `{event.risk_score}` `{event.severity}` policy `{event.policy_result}`\n"
        f"- Devices: {event.affected_device_count} "
        f"groups={', '.join(event.deployment_groups)} "
        f"models={', '.join(event.device_models) or 'unspecified'}\n"
        f"- Reasons: {', '.join(event.reason_codes) or 'none'}\n"
        f"- Applicability confidence: `{event.applicability_confidence}` "
        f"unknowns={', '.join(event.applicability_unknowns) or 'none'}\n"
        f"- Workflow: `{event.workflow_state}`\n"
        f"- Change record: {event.change_record_url}\n"
        f"- Acknowledgement: {ack}\n"
        f"{previous}\n"
        f"**Next action:** {event.recommended_next_action}\n"
    )
