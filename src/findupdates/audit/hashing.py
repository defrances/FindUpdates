"""Canonical hashing for append-only evidence."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from findupdates.audit.models import EvidenceAttachment, EvidenceRecord


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_dumps(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, indent=None, separators=(",", ":"), sort_keys=True)


def content_hash(payload: dict[str, Any]) -> str:
    return sha256_text(canonical_dumps(payload))


def integrity_hash(*, prev: str, body: dict[str, Any]) -> str:
    """Bind this record to the previous chain tip."""
    return sha256_text(prev + canonical_dumps(body))


def record_body(record: EvidenceRecord) -> dict[str, Any]:
    """Fields that participate in the chain, excluding integrity_hash itself."""
    return {
        "actor": record.actor,
        "authoritative": record.authoritative,
        "content_sha256": record.content_sha256,
        "correlation_id": record.correlation_id,
        "payload_id": record.payload_id,
        "prev_integrity_hash": record.prev_integrity_hash,
        "provenance": record.provenance.value,
        "reason": record.reason,
        "record_id": record.record_id,
        "recorded_at": record.recorded_at.isoformat().replace("+00:00", "Z"),
        "redacted": record.redacted,
        "schema_version": record.schema_version,
        "sequence": record.sequence,
        "stage": record.stage.value,
        "supersedes": record.supersedes,
        "versions": {
            "parser": record.versions.parser,
            "policy": record.versions.policy,
            "prompt": record.versions.prompt,
            "schema": record.versions.schema,
            "template": record.versions.template,
        },
        "workflow_run_id": record.workflow_run_id,
    }


def manifest_digest(
    *,
    bundle_id: str,
    chain_tip: str,
    records: tuple[EvidenceRecord, ...],
    attachments: tuple[EvidenceAttachment, ...],
    narrative: str,
) -> str:
    """Digest the export manifest, including the human narrative."""
    payload = {
        "attachment_sha256": [item.sha256 for item in attachments],
        "bundle_id": bundle_id,
        "chain_tip": chain_tip,
        "narrative_sha256": sha256_text(narrative),
        "record_ids": [item.record_id for item in records],
    }
    return sha256_text(canonical_dumps(payload))
