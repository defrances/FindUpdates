"""Append-only evidence storage. Existing records are never overwritten."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from findupdates.audit.errors import ImmutableViolation
from findupdates.audit.hashing import content_hash, integrity_hash, record_body, sha256_text
from findupdates.audit.models import (
    GENESIS_HASH,
    EvidenceAttachment,
    EvidenceRecord,
    EvidenceStage,
    Provenance,
    ToolVersions,
)
from findupdates.audit.redact import redact_payload
from findupdates.audit.serialize import record_to_dict
from findupdates.ids import stable_id


class EvidenceStore(Protocol):
    def append(
        self,
        *,
        correlation_id: str,
        stage: EvidenceStage,
        provenance: Provenance,
        payload: dict[str, Any],
        actor: str,
        reason: str,
        now: datetime,
        versions: ToolVersions,
        authoritative: bool,
        workflow_run_id: str | None = None,
        supersedes: str | None = None,
    ) -> EvidenceRecord: ...

    def records(self, correlation_id: str) -> tuple[EvidenceRecord, ...]: ...

    def attachments(self, correlation_id: str) -> tuple[EvidenceAttachment, ...]: ...


class MemoryEvidenceStore:
    """In-memory append-only log used by tests and local reconstruction."""

    def __init__(self) -> None:
        self._records: dict[str, list[EvidenceRecord]] = {}
        self._attachments: dict[str, list[EvidenceAttachment]] = {}
        self._ids: set[str] = set()

    def append(
        self,
        *,
        correlation_id: str,
        stage: EvidenceStage,
        provenance: Provenance,
        payload: dict[str, Any],
        actor: str,
        reason: str,
        now: datetime,
        versions: ToolVersions,
        authoritative: bool,
        workflow_run_id: str | None = None,
        supersedes: str | None = None,
    ) -> EvidenceRecord:
        if provenance is Provenance.AI_INTERPRETATION:
            authoritative = False
        redacted, changed = redact_payload(payload)
        if not isinstance(redacted, dict):
            raise ValueError("evidence payload must be an object")
        digest = content_hash(redacted)
        previous = self._records.get(correlation_id, [])
        prev_hash = previous[-1].integrity_hash if previous else GENESIS_HASH
        sequence = len(previous) + 1
        payload_id = stable_id("ev-payload", correlation_id, stage.value, str(sequence))
        record_id = stable_id("ev-rec", correlation_id, str(sequence), stage.value)
        if record_id in self._ids:
            raise ImmutableViolation(f"evidence record {record_id} already exists")
        draft = EvidenceRecord(
            record_id=record_id,
            correlation_id=correlation_id,
            sequence=sequence,
            stage=stage,
            provenance=provenance,
            payload_id=payload_id,
            content_sha256=digest,
            prev_integrity_hash=prev_hash,
            integrity_hash=GENESIS_HASH,
            actor=actor,
            reason=reason,
            recorded_at=now,
            redacted=changed,
            supersedes=supersedes,
            versions=versions,
            authoritative=authoritative,
            workflow_run_id=workflow_run_id,
        )
        chained = replace(
            draft,
            integrity_hash=integrity_hash(prev=prev_hash, body=record_body(draft)),
        )
        self._ids.add(record_id)
        self._records.setdefault(correlation_id, []).append(chained)
        body = json.dumps(redacted, ensure_ascii=True, indent=2, sort_keys=True)
        attachment = EvidenceAttachment(
            name=f"{sequence:02d}-{stage.value}.json",
            sha256=sha256_text(body),
            media_type="application/json",
            body=body,
        )
        self._attachments.setdefault(correlation_id, []).append(attachment)
        return chained

    def records(self, correlation_id: str) -> tuple[EvidenceRecord, ...]:
        return tuple(self._records.get(correlation_id, ()))

    def attachments(self, correlation_id: str) -> tuple[EvidenceAttachment, ...]:
        return tuple(self._attachments.get(correlation_id, ()))


class FilesystemEvidenceStore(MemoryEvidenceStore):
    """Writes each record once. A second write to the same path is rejected."""

    def __init__(self, root: Path) -> None:
        super().__init__()
        self._root = root
        self._root.mkdir(parents=True, exist_ok=True)

    def append(
        self,
        *,
        correlation_id: str,
        stage: EvidenceStage,
        provenance: Provenance,
        payload: dict[str, Any],
        actor: str,
        reason: str,
        now: datetime,
        versions: ToolVersions,
        authoritative: bool,
        workflow_run_id: str | None = None,
        supersedes: str | None = None,
    ) -> EvidenceRecord:
        record = super().append(
            correlation_id=correlation_id,
            stage=stage,
            provenance=provenance,
            payload=payload,
            actor=actor,
            reason=reason,
            now=now,
            versions=versions,
            authoritative=authoritative,
            workflow_run_id=workflow_run_id,
            supersedes=supersedes,
        )
        folder = self._root / correlation_id
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{record.sequence:04d}-{record.record_id}.json"
        if path.exists():
            raise ImmutableViolation(f"refusing to overwrite {path}")
        path.write_text(
            json.dumps(record_to_dict(record), ensure_ascii=True, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        payload_path = folder / f"{record.sequence:04d}-{record.stage.value}.payload.json"
        if payload_path.exists():
            raise ImmutableViolation(f"refusing to overwrite {payload_path}")
        payload_path.write_text(self._attachments[correlation_id][-1].body, encoding="utf-8")
        return record
