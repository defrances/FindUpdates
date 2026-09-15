"""JSON serialization for notification events."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from findupdates.notifications.models import SCHEMA_VERSION, AssessmentState, NotificationEvent


def event_to_dict(event: NotificationEvent) -> dict[str, Any]:
    """Convert an event to a schema-compatible mapping."""
    return {
        "schema_version": SCHEMA_VERSION,
        "event_id": event.event_id,
        "kind": event.kind.value,
        "fingerprint": event.fingerprint,
        "severity": event.severity,
        "advisory_ids": list(event.advisory_ids),
        "cve_ids": list(event.cve_ids),
        "package_ids": list(event.package_ids),
        "vendor": event.vendor,
        "risk_score": event.risk_score,
        "policy_result": event.policy_result,
        "reason_codes": list(event.reason_codes),
        "affected_device_count": event.affected_device_count,
        "deployment_groups": list(event.deployment_groups),
        "device_models": list(event.device_models),
        "applicability_confidence": event.applicability_confidence,
        "applicability_unknowns": list(event.applicability_unknowns),
        "recommended_next_action": event.recommended_next_action,
        "workflow_state": event.workflow_state,
        "change_record_url": event.change_record_url,
        "change_idempotency_key": event.change_idempotency_key,
        "acknowledgement_required": event.acknowledgement_required,
        "acknowledged": event.acknowledged,
        "previous_state": None if event.previous_state is None else _state(event.previous_state),
        "created_at": _datetime(event.created_at),
    }


def canonical_event_json(event: NotificationEvent) -> str:
    """Stable JSON for tests and audit hashing."""
    return json.dumps(
        event_to_dict(event),
        ensure_ascii=True,
        indent=None,
        separators=(",", ":"),
        sort_keys=True,
    )


def _state(item: AssessmentState) -> dict[str, object]:
    return {
        "severity": item.severity,
        "policy_result": item.policy_result,
        "affected_device_count": item.affected_device_count,
        "kev": item.kev,
        "workflow_state": item.workflow_state,
    }


def _datetime(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
