"""JSON serialization for risk assessments."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from findupdates.risk.models import SCHEMA_VERSION, RiskAssessment, ScoreContribution


def assessment_to_dict(assessment: RiskAssessment) -> dict[str, Any]:
    """Convert a risk assessment to a schema-compatible mapping."""
    return {
        "schema_version": SCHEMA_VERSION,
        "assessment_id": assessment.assessment_id,
        "advisory_id": assessment.advisory_id,
        "device_id": assessment.device_id,
        "policy_version": assessment.policy_version,
        "score": assessment.score,
        "severity": assessment.severity.value,
        "policy_result": assessment.policy_result.value,
        "reason_codes": list(assessment.reason_codes),
        "contributions": [_contribution(item) for item in assessment.contributions],
        "hard_gates_applied": list(assessment.hard_gates_applied),
        "input_fingerprint": assessment.input_fingerprint,
        "assessed_at": _datetime(assessment.assessed_at),
        "needs_reassessment": assessment.needs_reassessment,
    }


def canonical_assessment_json(assessment: RiskAssessment) -> str:
    """Return a stable JSON document for hashing and idempotency checks."""
    return json.dumps(
        assessment_to_dict(assessment),
        ensure_ascii=True,
        indent=None,
        separators=(",", ":"),
        sort_keys=True,
    )


def _contribution(item: ScoreContribution) -> dict[str, object]:
    return {"code": item.code, "points": item.points, "detail": item.detail}


def _datetime(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
