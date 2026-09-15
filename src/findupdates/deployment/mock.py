"""In-memory adapters used by tests. They do not talk to Intune or OEM agents."""

from __future__ import annotations

import logging
from datetime import datetime

from findupdates.deployment.audit import build_audit, redact_backend_payload
from findupdates.deployment.authorize import assert_credential, validate_request
from findupdates.deployment.errors import (
    BackendRejected,
    DeploymentTimeout,
    PackageMismatch,
    PartialFailure,
    RollbackUnsupported,
    TargetMismatch,
)
from findupdates.deployment.models import (
    WINDOWS_CAPABILITIES,
    AdapterCapabilities,
    DeploymentRequest,
    DeploymentResult,
    DeploymentStatus,
    ErrorCode,
    OidcCredential,
    PackageIdentity,
)
from findupdates.ids import stable_id

LOGGER = logging.getLogger("findupdates.deployment")

_ACTIVE = frozenset({DeploymentStatus.IN_PROGRESS, DeploymentStatus.PAUSED})
_INSTALLED = frozenset(
    {
        DeploymentStatus.IN_PROGRESS,
        DeploymentStatus.PAUSED,
        DeploymentStatus.SUCCEEDED,
        DeploymentStatus.FAILED,
        DeploymentStatus.ROLLED_BACK,
        DeploymentStatus.CANCELLED,
    }
)


class MockDeploymentAdapter:
    """Backend-neutral mock. Windows OS/driver vs OEM firmware via capabilities."""

    def __init__(
        self,
        capabilities: AdapterCapabilities | None = None,
        *,
        expected_package: PackageIdentity | None = None,
        inject_error: ErrorCode | None = None,
        inject_rollback_error: ErrorCode | None = None,
    ) -> None:
        self._capabilities = capabilities or WINDOWS_CAPABILITIES
        self._expected_package = expected_package
        self._inject_error = inject_error
        self._inject_rollback_error = inject_rollback_error
        self._by_id: dict[str, DeploymentResult] = {}
        self._by_key: dict[str, str] = {}
        self._install_index: dict[tuple[str, tuple[str, ...]], str] = {}
        self._requests: dict[str, DeploymentRequest] = {}
        self.backend_audit: list[object] = []

    def capabilities(self) -> AdapterCapabilities:
        return self._capabilities

    def validate_request(self, request: DeploymentRequest) -> None:
        validate_request(
            request,
            self._capabilities,
            expected_package=self._expected_package,
        )

    def deploy(
        self,
        request: DeploymentRequest,
        *,
        credential: OidcCredential | None,
        now: datetime,
    ) -> DeploymentResult:
        assert_credential(credential, now=now)
        self.validate_request(request)
        existing = self._existing(request)
        if existing is not None:
            return self._duplicate(existing, now=now, operation="deploy")
        self._maybe_inject("deploy")
        status = DeploymentStatus.SUCCEEDED if request.dry_run else DeploymentStatus.IN_PROGRESS
        result = self._record(request, status=status, operation="deploy", now=now, duplicate=False)
        LOGGER.info(
            "deployment submitted id=%s dry_run=%s backend=%s",
            result.deployment_id,
            result.dry_run,
            result.backend,
        )
        return result

    def status(self, deployment_id: str) -> DeploymentResult:
        return self._require(deployment_id)

    def pause(
        self,
        deployment_id: str,
        *,
        credential: OidcCredential | None,
        now: datetime,
    ) -> DeploymentResult:
        assert_credential(credential, now=now)
        current = self._require(deployment_id)
        if not self._capabilities.supports_pause:
            raise BackendRejected(f"{self._capabilities.backend} does not support pause")
        if current.status is not DeploymentStatus.IN_PROGRESS:
            raise BackendRejected("only in-progress deployments can be paused")
        return self._transition(current, DeploymentStatus.PAUSED, "pause", now)

    def resume(
        self,
        deployment_id: str,
        *,
        credential: OidcCredential | None,
        now: datetime,
    ) -> DeploymentResult:
        assert_credential(credential, now=now)
        current = self._require(deployment_id)
        if not self._capabilities.supports_resume:
            raise BackendRejected(f"{self._capabilities.backend} does not support resume")
        if current.status is not DeploymentStatus.PAUSED:
            raise BackendRejected("only paused deployments can be resumed")
        return self._transition(current, DeploymentStatus.IN_PROGRESS, "resume", now)

    def rollback_or_uninstall(
        self,
        deployment_id: str,
        *,
        credential: OidcCredential | None,
        now: datetime,
    ) -> DeploymentResult:
        assert_credential(credential, now=now)
        current = self._require(deployment_id)
        if not self._capabilities.supports_rollback:
            raise RollbackUnsupported(
                f"{self._capabilities.backend} does not support rollback or uninstall"
            )
        if current.status not in {DeploymentStatus.SUCCEEDED, DeploymentStatus.IN_PROGRESS}:
            raise BackendRejected("rollback is only available for in-progress or succeeded jobs")
        if self._inject_rollback_error is ErrorCode.PARTIAL_FAILURE:
            raise PartialFailure("backend rolled back a subset of approved targets")
        if self._inject_rollback_error is ErrorCode.TIMEOUT:
            raise DeploymentTimeout("backend timed out during rollback")
        return self._transition(current, DeploymentStatus.ROLLED_BACK, "rollback", now)

    def cancel(
        self,
        deployment_id: str,
        *,
        credential: OidcCredential | None,
        now: datetime,
    ) -> DeploymentResult:
        assert_credential(credential, now=now)
        current = self._require(deployment_id)
        if current.status not in _ACTIVE:
            raise BackendRejected("only in-progress or paused deployments can be cancelled")
        return self._transition(current, DeploymentStatus.CANCELLED, "cancel", now)

    def complete(self, deployment_id: str, *, now: datetime) -> DeploymentResult:
        """Test helper: simulate the backend finishing an in-progress job."""
        current = self._require(deployment_id)
        if current.status is not DeploymentStatus.IN_PROGRESS:
            raise BackendRejected("only in-progress deployments can complete")
        return self._transition(current, DeploymentStatus.SUCCEEDED, "complete", now)

    def _existing(self, request: DeploymentRequest) -> DeploymentResult | None:
        found_id = self._by_key.get(request.idempotency_key)
        if found_id is not None:
            stored = self._requests[found_id]
            if stored.update != request.update:
                raise PackageMismatch("idempotency key is bound to a different package")
            if stored.device_ids != request.device_ids:
                raise TargetMismatch("idempotency key is bound to a different target set")
            return self._by_id[found_id]
        install_key = (request.update.sha256, tuple(sorted(request.device_ids)))
        found_install = self._install_index.get(install_key)
        if found_install is not None:
            return self._by_id[found_install]
        return None

    def _maybe_inject(self, operation: str) -> None:
        del operation
        if self._inject_error is ErrorCode.TIMEOUT:
            raise DeploymentTimeout("backend timed out before acknowledging the job")
        if self._inject_error is ErrorCode.PARTIAL_FAILURE:
            raise PartialFailure("backend installed on a subset of approved targets")
        if self._inject_error is ErrorCode.BACKEND_REJECTED:
            raise BackendRejected("backend rejected the approved request")

    def _record(
        self,
        request: DeploymentRequest,
        *,
        status: DeploymentStatus,
        operation: str,
        now: datetime,
        duplicate: bool,
        error_code: ErrorCode | None = None,
    ) -> DeploymentResult:
        deployment_id = stable_id("deployment", request.idempotency_key)
        result = DeploymentResult(
            deployment_id=deployment_id,
            idempotency_key=request.idempotency_key,
            status=status,
            dry_run=request.dry_run,
            backend=self._capabilities.backend,
            target_device_ids=tuple(sorted(request.device_ids)),
            package_id=request.update.package_id,
            package_sha256=request.update.sha256,
            duplicate=duplicate,
            error_code=error_code,
            audit=build_audit(request, operation=operation),
            updated_at=now,
        )
        self._by_id[deployment_id] = result
        self._by_key[request.idempotency_key] = deployment_id
        self._requests[deployment_id] = request
        if status in _INSTALLED and not request.dry_run:
            self._install_index[(request.update.sha256, tuple(sorted(request.device_ids)))] = (
                deployment_id
            )
        self._snapshot(operation, request, result, credential_present=True)
        return result

    def _transition(
        self,
        current: DeploymentResult,
        status: DeploymentStatus,
        operation: str,
        now: datetime,
    ) -> DeploymentResult:
        request = self._requests[current.deployment_id]
        return self._record(
            request,
            status=status,
            operation=operation,
            now=now,
            duplicate=False,
        )

    def _duplicate(
        self, current: DeploymentResult, *, now: datetime, operation: str
    ) -> DeploymentResult:
        request = self._requests[current.deployment_id]
        LOGGER.info(
            "deployment replayed id=%s idempotency_key=%s",
            current.deployment_id,
            current.idempotency_key,
        )
        return self._record(
            request,
            status=current.status,
            operation=operation,
            now=now,
            duplicate=True,
            error_code=current.error_code,
        )

    def _require(self, deployment_id: str) -> DeploymentResult:
        try:
            return self._by_id[deployment_id]
        except KeyError as exc:
            raise BackendRejected(f"unknown deployment_id {deployment_id}") from exc

    def _snapshot(
        self,
        operation: str,
        request: DeploymentRequest,
        result: DeploymentResult,
        *,
        credential_present: bool,
    ) -> None:
        payload = {
            "operation": operation,
            "backend": self._capabilities.backend,
            "request": {
                "deployment_id": result.deployment_id,
                "package_id": request.update.package_id,
                "package_sha256": request.update.sha256,
                "targets": list(request.device_ids),
                "authorization": "Bearer super-secret-token",
            },
            "response": {
                "status": result.status.value,
                "duplicate": result.duplicate,
            },
            "credential_present": credential_present,
        }
        self.backend_audit.append(redact_backend_payload(payload))
