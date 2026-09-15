"""JSON serialization for evidence records and bundles."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from findupdates.audit.models import (
    SCHEMA_VERSION,
    EvidenceBundle,
    EvidenceRecord,
    EvidenceStage,
    Provenance,
    ToolVersions,
)


def record_to_dict(record: EvidenceRecord) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "record_id": record.record_id,
        "correlation_id": record.correlation_id,
        "sequence": record.sequence,
        "stage": record.stage.value,
        "provenance": record.provenance.value,
        "payload_id": record.payload_id,
        "content_sha256": record.content_sha256,
        "prev_integrity_hash": record.prev_integrity_hash,
        "integrity_hash": record.integrity_hash,
        "actor": record.actor,
        "reason": record.reason,
        "workflow_run_id": record.workflow_run_id,
        "recorded_at": _datetime(record.recorded_at),
        "redacted": record.redacted,
        "supersedes": record.supersedes,
        "authoritative": record.authoritative,
        "versions": {
            "schema": record.versions.schema,
            "parser": record.versions.parser,
            "policy": record.versions.policy,
            "prompt": record.versions.prompt,
            "template": record.versions.template,
        },
    }


def bundle_to_dict(bundle: EvidenceBundle) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "bundle_id": bundle.bundle_id,
        "correlation_id": bundle.correlation_id,
        "created_at": _datetime(bundle.created_at),
        "retention_days": bundle.retention_days,
        "chain_tip": bundle.chain_tip,
        "manifest_sha256": bundle.manifest_sha256,
        "records": [record_to_dict(item) for item in bundle.records],
        "attachments": [
            {"name": item.name, "sha256": item.sha256, "media_type": item.media_type}
            for item in bundle.attachments
        ],
    }


def dict_to_record(payload: dict[str, Any]) -> EvidenceRecord:
    versions = payload["versions"]
    return EvidenceRecord(
        record_id=str(payload["record_id"]),
        correlation_id=str(payload["correlation_id"]),
        sequence=int(payload["sequence"]),
        stage=EvidenceStage(str(payload["stage"])),
        provenance=Provenance(str(payload["provenance"])),
        payload_id=str(payload["payload_id"]),
        content_sha256=str(payload["content_sha256"]),
        prev_integrity_hash=str(payload["prev_integrity_hash"]),
        integrity_hash=str(payload["integrity_hash"]),
        actor=str(payload["actor"]),
        reason=str(payload["reason"]),
        recorded_at=_parse_datetime(str(payload["recorded_at"])),
        redacted=bool(payload["redacted"]),
        supersedes=None if payload.get("supersedes") is None else str(payload["supersedes"]),
        versions=ToolVersions(
            schema=str(versions["schema"]),
            parser=str(versions["parser"]),
            policy=str(versions["policy"]),
            prompt=None if versions.get("prompt") is None else str(versions["prompt"]),
            template=None if versions.get("template") is None else str(versions["template"]),
        ),
        authoritative=bool(
            payload.get("authoritative", payload["provenance"] != "ai_interpretation")
        ),
        workflow_run_id=(
            None if payload.get("workflow_run_id") is None else str(payload["workflow_run_id"])
        ),
        schema_version=str(payload.get("schema_version", SCHEMA_VERSION)),
    )


def _datetime(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return parsed
