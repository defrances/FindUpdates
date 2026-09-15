"""Fail-closed checks for already-authorized deployment requests."""

from __future__ import annotations

from datetime import datetime

from findupdates.deployment.errors import (
    AuthError,
    AuthorizationMissing,
    FirmwareNotOemQualified,
    PackageMismatch,
    TargetMismatch,
    UnsupportedUpdateKind,
)
from findupdates.deployment.hashing import hash_targets
from findupdates.deployment.models import (
    AdapterCapabilities,
    DeploymentRequest,
    OidcCredential,
    PackageIdentity,
)

_DEPLOYABLE_POLICY = frozenset({"REQUIRE_VALIDATION", "REQUIRE_APPROVAL"})


def validate_request(
    request: DeploymentRequest,
    capabilities: AdapterCapabilities,
    *,
    expected_package: PackageIdentity | None = None,
) -> None:
    """Reject requests that would invent scope, skip gates or use the wrong backend."""
    _assert_authorization(request)
    if request.update.kind not in capabilities.update_kinds:
        raise UnsupportedUpdateKind(
            f"{capabilities.backend} cannot deploy {request.update.kind.value} packages"
        )
    _assert_targets(request, capabilities)
    if expected_package is not None and request.update != expected_package:
        raise PackageMismatch("package identity does not match the approved artifact")
    if request.update.is_firmware and not request.oem_qualified:
        raise FirmwareNotOemQualified(
            "Intel/OEM firmware cannot be deployed without OEM qualification"
        )


def assert_credential(credential: OidcCredential | None, *, now: datetime) -> OidcCredential:
    """Require a short-lived OIDC token. The token is never stored on the request."""
    if credential is None:
        raise AuthorizationMissing("OIDC credential is required for deployment operations")
    if not credential.token.strip() or not credential.audience.strip():
        raise AuthError("OIDC credential is incomplete")
    if credential.expires_at <= now:
        raise AuthError("OIDC credential has expired")
    return credential


def _assert_authorization(request: DeploymentRequest) -> None:
    evidence = request.evidence
    if evidence.policy_result not in _DEPLOYABLE_POLICY:
        raise AuthorizationMissing(f"policy {evidence.policy_result} does not authorize deployment")
    if not evidence.approver.strip() or not evidence.validation_result_id.strip():
        raise AuthorizationMissing("approval and validation evidence are required")
    if not evidence.risk_assessment_id.strip() or not evidence.change_idempotency_key.strip():
        raise AuthorizationMissing("risk assessment and change-record linkage are required")
    if not evidence.advisory_ids:
        raise AuthorizationMissing("advisory linkage is required")


def _assert_targets(request: DeploymentRequest, capabilities: AdapterCapabilities) -> None:
    try:
        computed = hash_targets(request.targets)
    except ValueError as exc:
        raise TargetMismatch(str(exc)) from exc
    if computed != request.approved_target_set_hash:
        raise TargetMismatch("target set does not match the approved target set hash")
    unexpected = {item.backend for item in request.targets if item.backend != capabilities.backend}
    if unexpected:
        raise TargetMismatch(
            f"targets request backends {sorted(unexpected)}; adapter is {capabilities.backend}"
        )
