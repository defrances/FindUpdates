"""JSON serialization for deployment requests and results."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from findupdates.deployment.models import (
    SCHEMA_VERSION,
    AuthorizationEvidence,
    DeploymentAudit,
    DeploymentRequest,
    DeploymentResult,
    DeploymentStatus,
    DeploymentTarget,
    ErrorCode,
    PackageIdentity,
    RolloutPolicy,
    UpdateKind,
)


def request_to_dict(request: DeploymentRequest) -> dict[str, Any]:
    """Schema-compatible request mapping. Credentials are never included."""
    return {
        "schema_version": SCHEMA_VERSION,
        "request_id": request.request_id,
        "idempotency_key": request.idempotency_key,
        "dry_run": request.dry_run,
        "update": {
            "kind": request.update.kind.value,
            "package_id": request.update.package_id,
            "version": request.update.version,
            "sha256": request.update.sha256,
        },
        "targets": [
            {"device_id": item.device_id, "backend": item.backend} for item in request.targets
        ],
        "approved_target_set_hash": request.approved_target_set_hash,
        "rollout": {
            "environment": request.rollout.environment,
            "ring": request.rollout.ring,
        },
        "evidence": {
            "advisory_ids": list(request.evidence.advisory_ids),
            "risk_assessment_id": request.evidence.risk_assessment_id,
            "policy_result": request.evidence.policy_result,
            "change_idempotency_key": request.evidence.change_idempotency_key,
            "validation_result_id": request.evidence.validation_result_id,
            "approver": request.evidence.approver,
            "approved_at": _datetime(request.evidence.approved_at),
        },
        "oem_qualified": request.oem_qualified,
    }


def result_to_dict(result: DeploymentResult) -> dict[str, Any]:
    """Schema-compatible result mapping."""
    return {
        "schema_version": SCHEMA_VERSION,
        "deployment_id": result.deployment_id,
        "idempotency_key": result.idempotency_key,
        "status": result.status.value,
        "dry_run": result.dry_run,
        "backend": result.backend,
        "target_device_ids": list(result.target_device_ids),
        "package_id": result.package_id,
        "package_sha256": result.package_sha256,
        "duplicate": result.duplicate,
        "error_code": None if result.error_code is None else result.error_code.value,
        "audit": {
            "approver": result.audit.approver,
            "risk_assessment_id": result.audit.risk_assessment_id,
            "validation_result_id": result.audit.validation_result_id,
            "change_idempotency_key": result.audit.change_idempotency_key,
            "backend_operation": result.audit.backend_operation,
            "credential_kind": result.audit.credential_kind,
        },
        "updated_at": _datetime(result.updated_at),
    }


def dict_to_request(payload: dict[str, Any]) -> DeploymentRequest:
    """Parse a stored request. Missing authorization fields fail closed."""
    update = payload["update"]
    evidence = payload["evidence"]
    targets = tuple(
        DeploymentTarget(str(item["device_id"]), str(item["backend"]))
        for item in payload["targets"]
    )
    request = DeploymentRequest(
        request_id=str(payload["request_id"]),
        idempotency_key=str(payload["idempotency_key"]),
        dry_run=bool(payload["dry_run"]),
        update=PackageIdentity(
            kind=UpdateKind(str(update["kind"])),
            package_id=str(update["package_id"]),
            version=str(update["version"]),
            sha256=str(update["sha256"]),
        ),
        targets=targets,
        approved_target_set_hash=str(payload["approved_target_set_hash"]),
        rollout=RolloutPolicy(
            environment=str(payload["rollout"]["environment"]),
            ring=str(payload["rollout"]["ring"]),
        ),
        evidence=AuthorizationEvidence(
            advisory_ids=tuple(str(item) for item in evidence["advisory_ids"]),
            risk_assessment_id=str(evidence["risk_assessment_id"]),
            policy_result=str(evidence["policy_result"]),
            change_idempotency_key=str(evidence["change_idempotency_key"]),
            validation_result_id=str(evidence["validation_result_id"]),
            approver=str(evidence["approver"]),
            approved_at=_parse_datetime(str(evidence["approved_at"])),
        ),
        oem_qualified=bool(payload["oem_qualified"]),
        schema_version=str(payload.get("schema_version", SCHEMA_VERSION)),
    )
    return request


def dict_to_result(payload: dict[str, Any]) -> DeploymentResult:
    """Parse a stored deployment result."""
    error = payload.get("error_code")
    audit = payload["audit"]
    return DeploymentResult(
        deployment_id=str(payload["deployment_id"]),
        idempotency_key=str(payload["idempotency_key"]),
        status=DeploymentStatus(str(payload["status"])),
        dry_run=bool(payload["dry_run"]),
        backend=str(payload["backend"]),
        target_device_ids=tuple(str(item) for item in payload["target_device_ids"]),
        package_id=str(payload["package_id"]),
        package_sha256=str(payload["package_sha256"]),
        duplicate=bool(payload["duplicate"]),
        error_code=None if error is None else ErrorCode(str(error)),
        audit=DeploymentAudit(
            approver=str(audit["approver"]),
            risk_assessment_id=str(audit["risk_assessment_id"]),
            validation_result_id=str(audit["validation_result_id"]),
            change_idempotency_key=str(audit["change_idempotency_key"]),
            backend_operation=str(audit["backend_operation"]),
            credential_kind=str(audit["credential_kind"]),
        ),
        updated_at=_parse_datetime(str(payload["updated_at"])),
        schema_version=str(payload.get("schema_version", SCHEMA_VERSION)),
    )


def _datetime(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return parsed
