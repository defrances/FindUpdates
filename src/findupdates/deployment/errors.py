"""Structured deployment failures. Callers must not treat these as success."""

from __future__ import annotations

from findupdates.deployment.models import ErrorCode


class DeploymentError(Exception):
    """Base class for adapter rejections and backend failures."""

    code: ErrorCode = ErrorCode.BACKEND_REJECTED

    def __init__(self, message: str, *, code: ErrorCode | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code


class AuthError(DeploymentError):
    code = ErrorCode.AUTH


class TargetMismatch(DeploymentError):
    code = ErrorCode.TARGET_MISMATCH


class PackageMismatch(DeploymentError):
    code = ErrorCode.PACKAGE_MISMATCH


class BackendRejected(DeploymentError):
    code = ErrorCode.BACKEND_REJECTED


class DeploymentTimeout(DeploymentError):
    code = ErrorCode.TIMEOUT


class PartialFailure(DeploymentError):
    code = ErrorCode.PARTIAL_FAILURE


class AuthorizationMissing(DeploymentError):
    code = ErrorCode.AUTHORIZATION_MISSING


class FirmwareNotOemQualified(DeploymentError):
    code = ErrorCode.FIRMWARE_NOT_OEM_QUALIFIED


class RollbackUnsupported(DeploymentError):
    code = ErrorCode.ROLLBACK_UNSUPPORTED


class UnsupportedUpdateKind(DeploymentError):
    code = ErrorCode.UNSUPPORTED_UPDATE_KIND
