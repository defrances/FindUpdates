"""Backup and restore evidence packages. Restore verifies the hash chain."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from findupdates.audit.export import export_bundle, load_package, write_package
from findupdates.audit.models import EvidenceBundle
from findupdates.audit.store import EvidenceStore
from findupdates.audit.verify import verify_bundle


def backup_evidence(
    store: EvidenceStore,
    correlation_id: str,
    destination: Path,
    *,
    now: datetime,
    narrative: str,
) -> EvidenceBundle:
    """Snapshot the append-only log to a directory. The log is not rewritten."""
    bundle = export_bundle(store, correlation_id, now=now, narrative=narrative)
    write_package(bundle, destination)
    return bundle


def restore_evidence(destination: Path) -> EvidenceBundle:
    """Load a backup and fail closed if the package was altered."""
    bundle = load_package(destination)
    verify_bundle(bundle)
    return bundle
