"""JSON serialization for agent analysis records."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from findupdates.agents.context import snapshot_to_dict
from findupdates.agents.models import SCHEMA_VERSION, AgentAnalysis, AgentSection, Claim


def analysis_to_dict(analysis: AgentAnalysis) -> dict[str, Any]:
    """Convert an analysis record to a schema-compatible mapping."""
    return {
        "schema_version": SCHEMA_VERSION,
        "analysis_id": analysis.analysis_id,
        "advisory_id": analysis.advisory_id,
        "device_id": analysis.device_id,
        "model": {
            "provider": analysis.model.provider,
            "name": analysis.model.name,
            "version": analysis.model.version,
        },
        "prompt_version": analysis.prompt_version,
        "template_version": analysis.template_version,
        "used_fallback": analysis.used_fallback,
        "provider_available": analysis.provider_available,
        "needs_human_review": analysis.needs_human_review,
        "confidence": analysis.confidence.value,
        "validation_errors": list(analysis.validation_errors),
        "authoritative": snapshot_to_dict(analysis.authoritative),
        "claims": [_claim(item) for item in analysis.claims],
        "sections": [_section(item) for item in analysis.sections],
        "rejected_actions": list(analysis.rejected_actions),
        "input_fingerprint": analysis.input_fingerprint,
        "generated_at": _datetime(analysis.generated_at),
    }


def canonical_analysis_json(analysis: AgentAnalysis) -> str:
    """Return stable JSON for audit hashing."""
    return json.dumps(
        analysis_to_dict(analysis),
        ensure_ascii=True,
        indent=None,
        separators=(",", ":"),
        sort_keys=True,
    )


def _claim(item: Claim) -> dict[str, object]:
    return {
        "claim_id": item.claim_id,
        "kind": item.kind.value,
        "text": item.text,
        "evidence_ids": list(item.evidence_ids),
    }


def _section(item: AgentSection) -> dict[str, object]:
    return {
        "role": item.role.value,
        "summary": item.summary,
        "claim_ids": list(item.claim_ids),
        "needs_human_review": item.needs_human_review,
    }


def _datetime(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
