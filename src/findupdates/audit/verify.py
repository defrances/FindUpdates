"""Verify hash chains and attachment digests. Tampering is detectable."""

from __future__ import annotations

import json

from findupdates.audit.errors import IntegrityFailure
from findupdates.audit.hashing import (
    content_hash,
    integrity_hash,
    manifest_digest,
    record_body,
    sha256_text,
)
from findupdates.audit.models import GENESIS_HASH, EvidenceBundle, EvidenceRecord


def verify_chain(records: tuple[EvidenceRecord, ...]) -> str:
    """Walk the append-only chain. Returns the tip hash when intact."""
    if not records:
        raise IntegrityFailure("evidence chain is empty")
    prev = GENESIS_HASH
    expected_sequence = 1
    for item in records:
        if item.sequence != expected_sequence:
            raise IntegrityFailure(f"sequence gap at {item.record_id}")
        if item.prev_integrity_hash != prev:
            raise IntegrityFailure(f"broken prev link at {item.record_id}")
        computed = integrity_hash(prev=prev, body=record_body(item))
        if computed != item.integrity_hash:
            raise IntegrityFailure(f"integrity hash mismatch at {item.record_id}")
        prev = item.integrity_hash
        expected_sequence += 1
    return prev


def verify_bundle(bundle: EvidenceBundle) -> None:
    """Fail if records, attachments, narrative or the manifest digest were altered."""
    tip = verify_chain(bundle.records)
    if tip != bundle.chain_tip:
        raise IntegrityFailure("bundle chain_tip does not match the record chain")
    if len(bundle.records) != len(bundle.attachments):
        raise IntegrityFailure("attachment count does not match the record chain")
    for record, attachment in zip(bundle.records, bundle.attachments, strict=True):
        expected_name = f"{record.sequence:02d}-{record.stage.value}.json"
        if attachment.name != expected_name:
            raise IntegrityFailure(
                f"attachment {attachment.name} does not match {record.record_id}"
            )
        if sha256_text(attachment.body) != attachment.sha256:
            raise IntegrityFailure(f"attachment {attachment.name} digest mismatch")
        parsed = json.loads(attachment.body)
        if not isinstance(parsed, dict):
            raise IntegrityFailure(f"attachment {attachment.name} is not an object")
        if content_hash(parsed) != record.content_sha256:
            raise IntegrityFailure(f"attachment {attachment.name} does not match content_sha256")
    expected_manifest = manifest_digest(
        bundle_id=bundle.bundle_id,
        chain_tip=bundle.chain_tip,
        records=bundle.records,
        attachments=bundle.attachments,
        narrative=bundle.narrative,
    )
    if expected_manifest != bundle.manifest_sha256:
        raise IntegrityFailure("bundle manifest digest mismatch")
