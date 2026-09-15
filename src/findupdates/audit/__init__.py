"""Append-only audit trail and tamper-evident evidence export."""

from findupdates.audit.errors import AuditError, ImmutableViolation, IntegrityFailure
from findupdates.audit.export import (
    export_bundle,
    load_audit_config,
    load_package,
    load_retention_days,
    payloads_by_stage,
    write_package,
)
from findupdates.audit.lifecycle import LifecycleFacts, bundle_lifecycle, record_lifecycle
from findupdates.audit.models import (
    SCHEMA_VERSION,
    EvidenceAttachment,
    EvidenceBundle,
    EvidenceRecord,
    EvidenceStage,
    Provenance,
    ToolVersions,
)
from findupdates.audit.serialize import bundle_to_dict, dict_to_record, record_to_dict
from findupdates.audit.store import FilesystemEvidenceStore, MemoryEvidenceStore
from findupdates.audit.verify import verify_bundle, verify_chain

__all__ = [
    "SCHEMA_VERSION",
    "AuditError",
    "EvidenceAttachment",
    "EvidenceBundle",
    "EvidenceRecord",
    "EvidenceStage",
    "FilesystemEvidenceStore",
    "ImmutableViolation",
    "IntegrityFailure",
    "LifecycleFacts",
    "MemoryEvidenceStore",
    "Provenance",
    "ToolVersions",
    "bundle_lifecycle",
    "bundle_to_dict",
    "dict_to_record",
    "export_bundle",
    "load_audit_config",
    "load_package",
    "load_retention_days",
    "payloads_by_stage",
    "record_lifecycle",
    "record_to_dict",
    "verify_bundle",
    "verify_chain",
    "write_package",
]
