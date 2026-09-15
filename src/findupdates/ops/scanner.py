"""Merge/deployment blocking from configured scanner severity."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from findupdates.ops.config import scanner_block_severities
from findupdates.ops.models import Alert, AlertCode, ScannerFinding


def merge_allowed(findings: tuple[ScannerFinding, ...], config: dict[str, Any]) -> bool:
    """High/critical findings block merge and production deployment."""
    blocking = scanner_block_severities(config)
    return not any(item.severity.lower() in blocking for item in findings)


def scanner_alert(
    findings: tuple[ScannerFinding, ...],
    config: dict[str, Any],
    *,
    correlation_id: str,
    now: datetime,
) -> Alert | None:
    if merge_allowed(findings, config):
        return None
    return Alert(
        code=AlertCode.SCANNER_BLOCK,
        correlation_id=correlation_id,
        summary="configured scanner severity blocks merge/deployment",
        source="sca",
        advisory_id=None,
        recorded_at=now,
    )
