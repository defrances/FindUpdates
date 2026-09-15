"""Audit metadata for deployment operations. Secrets and PHI are stripped."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from findupdates.agents.redaction import redact_text
from findupdates.deployment.models import DeploymentAudit, DeploymentRequest

_SECRET_KEYS = frozenset(
    {
        "token",
        "access_token",
        "refresh_token",
        "authorization",
        "password",
        "secret",
        "api_key",
        "apikey",
    }
)


def build_audit(request: DeploymentRequest, *, operation: str) -> DeploymentAudit:
    """Record who authorized the change and which evidence was bound to it."""
    evidence = request.evidence
    return DeploymentAudit(
        approver=evidence.approver,
        risk_assessment_id=evidence.risk_assessment_id,
        validation_result_id=evidence.validation_result_id,
        change_idempotency_key=evidence.change_idempotency_key,
        backend_operation=operation,
        credential_kind="oidc",
    )


def redact_backend_payload(value: object) -> object:
    """Drop credential material from backend request/response snapshots."""
    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if lowered in _SECRET_KEYS or "token" in lowered:
                redacted[str(key)] = "[REDACTED]"
            else:
                redacted[str(key)] = redact_backend_payload(item)
        return redacted
    if isinstance(value, list):
        return [redact_backend_payload(item) for item in value]
    if isinstance(value, str):
        text, _changed = redact_text(value)
        return text
    return value
