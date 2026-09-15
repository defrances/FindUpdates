"""JSON and GitHub Issue body encoding for change records."""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

from findupdates.changerecords.models import (
    SCHEMA_VERSION,
    ChangeRecord,
    LifecycleState,
    OverrideEvent,
)

BEGIN = "<!-- findupdates-change-record:v1 -->"
END = "<!-- /findupdates-change-record -->"
_BLOCK = re.compile(
    re.escape(BEGIN) + r"\s*(.*?)\s*" + re.escape(END),
    re.DOTALL,
)


def record_to_dict(record: ChangeRecord) -> dict[str, Any]:
    """Convert a change record to a schema-compatible mapping."""
    return {
        "schema_version": SCHEMA_VERSION,
        "change_id": record.change_id,
        "idempotency_key": record.idempotency_key,
        "lifecycle": record.lifecycle.value,
        "advisory_ids": list(record.advisory_ids),
        "device_ids": list(record.device_ids),
        "deployment_group": record.deployment_group,
        "risk_score": record.risk_score,
        "severity": record.severity,
        "policy_result": record.policy_result,
        "vendor": record.vendor,
        "evidence_links": list(record.evidence_links),
        "validation_plan": record.validation_plan,
        "rollout_plan": record.rollout_plan,
        "overrides": [_override(item) for item in record.overrides],
        "github_issue_number": record.github_issue_number,
        "updated_at": _datetime(record.updated_at),
    }


def canonical_record_json(record: ChangeRecord) -> str:
    """Stable JSON used inside the GitHub Issue body."""
    return json.dumps(
        record_to_dict(record),
        ensure_ascii=True,
        indent=2,
        sort_keys=True,
    )


def issue_body(record: ChangeRecord) -> str:
    """Human-readable issue plus a machine-readable JSON fence."""
    devices = ", ".join(record.device_ids)
    advisories = ", ".join(record.advisory_ids)
    return (
        f"## Change record `{record.idempotency_key}`\n\n"
        f"- Lifecycle: `{record.lifecycle.value}`\n"
        f"- Policy: `{record.policy_result}` (authoritative; workflow inputs cannot override)\n"
        f"- Severity: `{record.severity}` score `{record.risk_score}`\n"
        f"- Vendor: `{record.vendor}`\n"
        f"- Advisories: {advisories}\n"
        f"- Devices: {devices}\n"
        f"- Deployment group: `{record.deployment_group}`\n\n"
        f"### Validation plan\n\n{record.validation_plan}\n\n"
        f"### Rollout plan\n\n{record.rollout_plan}\n\n"
        f"{BEGIN}\n{canonical_record_json(record)}\n{END}\n"
    )


def parse_issue_body(body: str) -> ChangeRecord:
    """Load the machine record from an issue body. Missing JSON fails closed."""
    match = _BLOCK.search(body)
    if match is None:
        raise ValueError("issue body does not contain a change-record payload")
    payload = json.loads(match.group(1))
    if not isinstance(payload, dict):
        raise ValueError("change-record payload must be an object")
    return dict_to_record(payload)


def dict_to_record(payload: dict[str, Any]) -> ChangeRecord:
    """Parse a schema-shaped mapping into a ChangeRecord."""
    overrides = tuple(_parse_override(item) for item in payload.get("overrides", []))
    return ChangeRecord(
        change_id=str(payload["change_id"]),
        idempotency_key=str(payload["idempotency_key"]),
        lifecycle=LifecycleState(str(payload["lifecycle"])),
        advisory_ids=tuple(str(item) for item in payload["advisory_ids"]),
        device_ids=tuple(str(item) for item in payload["device_ids"]),
        deployment_group=str(payload["deployment_group"]),
        risk_score=int(payload["risk_score"]),
        severity=str(payload["severity"]),
        policy_result=str(payload["policy_result"]),
        vendor=str(payload["vendor"]),
        evidence_links=tuple(str(item) for item in payload.get("evidence_links", [])),
        validation_plan=str(payload["validation_plan"]),
        rollout_plan=str(payload["rollout_plan"]),
        overrides=overrides,
        github_issue_number=_issue_number(payload.get("github_issue_number")),
        updated_at=_parse_datetime(str(payload["updated_at"])),
    )


def _override(item: OverrideEvent) -> dict[str, str]:
    return {
        "actor": item.actor,
        "timestamp": _datetime(item.timestamp),
        "reason": item.reason,
        "from_lifecycle": item.from_lifecycle.value,
        "to_lifecycle": item.to_lifecycle.value,
    }


def _parse_override(item: object) -> OverrideEvent:
    if not isinstance(item, dict):
        raise ValueError("override must be an object")
    return OverrideEvent(
        actor=str(item["actor"]),
        timestamp=_parse_datetime(str(item["timestamp"])),
        reason=str(item["reason"]),
        from_lifecycle=LifecycleState(str(item["from_lifecycle"])),
        to_lifecycle=LifecycleState(str(item["to_lifecycle"])),
    )


def _issue_number(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("github_issue_number must be an integer")
    if value < 1:
        raise ValueError("github_issue_number must be positive")
    return value


def _datetime(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _parse_datetime(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return parsed
