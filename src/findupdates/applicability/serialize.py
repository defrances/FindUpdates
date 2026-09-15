"""JSON serialization for applicability results."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from findupdates.applicability.models import (
    SCHEMA_VERSION,
    ApplicabilityEvidence,
    ApplicabilityResult,
)


def result_to_dict(result: ApplicabilityResult) -> dict[str, Any]:
    """Convert an applicability result to a schema-compatible mapping."""
    return {
        "schema_version": SCHEMA_VERSION,
        "result_id": result.result_id,
        "advisory_id": result.advisory_id,
        "device_id": result.device_id,
        "verdict": result.verdict.value,
        "confidence": result.confidence.value,
        "blocks_automatic_deployment": result.blocks_automatic_deployment,
        "evidence": [_evidence(item) for item in result.evidence],
        "source_fields": list(result.source_fields),
        "inventory_fields": list(result.inventory_fields),
        "missing_data": list(result.missing_data),
        "input_fingerprint": result.input_fingerprint,
        "evaluated_at": _datetime(result.evaluated_at),
        "needs_reassessment": result.needs_reassessment,
        "previous_fingerprint": result.previous_fingerprint,
    }


def canonical_result_json(result: ApplicabilityResult) -> str:
    """Return a stable JSON document for hashing and idempotency checks."""
    return json.dumps(
        result_to_dict(result),
        ensure_ascii=True,
        indent=None,
        separators=(",", ":"),
        sort_keys=True,
    )


def _evidence(item: ApplicabilityEvidence) -> dict[str, object]:
    return {
        "reason_code": item.reason_code.value,
        "detail": item.detail,
        "source_fields": list(item.source_fields),
        "inventory_fields": list(item.inventory_fields),
    }


def _datetime(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
