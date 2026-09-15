"""Backend-neutral deployment request, status and capability contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

SCHEMA_VERSION = "1.0"

_FIRMWARE_KINDS = frozenset({"firmware", "bios", "microcode"})
_BLOCKING_POLICY = frozenset({"HOLD", "BLOCK"})


class UpdateKind(StrEnum):
    OS = "os"
    DRIVER = "driver"
    FIRMWARE = "firmware"
    BIOS = "bios"
    MICROCODE = "microcode"
    APPLICATION = "application"


class DeploymentStatus(StrEnum):
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    PAUSED = "paused"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    ROLLED_BACK = "rolled_back"
    REJECTED = "rejected"


class ErrorCode(StrEnum):
    AUTH = "auth"
    TARGET_MISMATCH = "target_mismatch"
    PACKAGE_MISMATCH = "package_mismatch"
    BACKEND_REJECTED = "backend_rejected"
    TIMEOUT = "timeout"
    PARTIAL_FAILURE = "partial_failure"
    AUTHORIZATION_MISSING = "authorization_missing"
    FIRMWARE_NOT_OEM_QUALIFIED = "firmware_not_oem_qualified"
    ROLLBACK_UNSUPPORTED = "rollback_unsupported"
    UNSUPPORTED_UPDATE_KIND = "unsupported_update_kind"


@dataclass(frozen=True, slots=True)
class AdapterCapabilities:
    backend: str
    update_kinds: frozenset[UpdateKind]
    supports_pause: bool
    supports_resume: bool
    supports_rollback: bool
    supports_scheduling: bool
    supports_reboot_control: bool
    auth: str

    def __post_init__(self) -> None:
        if not self.backend.strip() or not self.update_kinds:
            raise ValueError("adapter capabilities require a backend and update kinds")
        if self.auth != "oidc":
            raise ValueError("deployment adapters must authenticate with OIDC")


@dataclass(frozen=True, slots=True)
class PackageIdentity:
    kind: UpdateKind
    package_id: str
    version: str
    sha256: str

    def __post_init__(self) -> None:
        if not self.package_id.strip() or not self.version.strip():
            raise ValueError("package identity fields must not be empty")
        if len(self.sha256) != 64 or any(ch not in "0123456789abcdef" for ch in self.sha256):
            raise ValueError("package sha256 must be a lowercase hex digest")

    @property
    def is_firmware(self) -> bool:
        return self.kind.value in _FIRMWARE_KINDS


@dataclass(frozen=True, slots=True)
class DeploymentTarget:
    device_id: str
    backend: str

    def __post_init__(self) -> None:
        if not self.device_id.strip() or not self.backend.strip():
            raise ValueError("deployment target fields must not be empty")


@dataclass(frozen=True, slots=True)
class RolloutPolicy:
    environment: str
    ring: str

    def __post_init__(self) -> None:
        if self.environment not in {"lab", "canary", "production"}:
            raise ValueError(f"unknown rollout environment {self.environment}")
        if not self.ring.strip():
            raise ValueError("rollout ring must not be empty")


@dataclass(frozen=True, slots=True)
class AuthorizationEvidence:
    """Immutable linkage to advisory, risk, change record and lab validation."""

    advisory_ids: tuple[str, ...]
    risk_assessment_id: str
    policy_result: str
    change_idempotency_key: str
    validation_result_id: str
    approver: str
    approved_at: datetime

    def __post_init__(self) -> None:
        if not self.advisory_ids or any(not item.strip() for item in self.advisory_ids):
            raise ValueError("authorization requires advisory ids")
        for value in (
            self.risk_assessment_id,
            self.policy_result,
            self.change_idempotency_key,
            self.validation_result_id,
            self.approver,
        ):
            if not value.strip():
                raise ValueError("authorization evidence fields must not be empty")
        if self.approved_at.tzinfo is None:
            raise ValueError("approved_at must be timezone-aware")
        if self.policy_result in _BLOCKING_POLICY:
            raise ValueError("HOLD/BLOCK cannot authorize a deployment request")


@dataclass(frozen=True, slots=True)
class OidcCredential:
    """Short-lived identity. The raw token is never persisted on the request."""

    audience: str
    expires_at: datetime
    token: str

    def __post_init__(self) -> None:
        if not self.audience.strip() or not self.token.strip():
            raise ValueError("OIDC credential fields must not be empty")
        if self.expires_at.tzinfo is None:
            raise ValueError("credential expiry must be timezone-aware")


@dataclass(frozen=True, slots=True)
class DeploymentRequest:
    request_id: str
    idempotency_key: str
    dry_run: bool
    update: PackageIdentity
    targets: tuple[DeploymentTarget, ...]
    approved_target_set_hash: str
    rollout: RolloutPolicy
    evidence: AuthorizationEvidence
    oem_qualified: bool
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version}")
        if not self.targets:
            raise ValueError("deployment request requires at least one target")
        if len(self.approved_target_set_hash) != 64:
            raise ValueError("approved_target_set_hash must be a SHA-256 digest")

    @property
    def device_ids(self) -> tuple[str, ...]:
        return tuple(item.device_id for item in self.targets)


@dataclass(frozen=True, slots=True)
class DeploymentAudit:
    approver: str
    risk_assessment_id: str
    validation_result_id: str
    change_idempotency_key: str
    backend_operation: str
    credential_kind: str


@dataclass(frozen=True, slots=True)
class DeploymentResult:
    deployment_id: str
    idempotency_key: str
    status: DeploymentStatus
    dry_run: bool
    backend: str
    target_device_ids: tuple[str, ...]
    package_id: str
    package_sha256: str
    duplicate: bool
    error_code: ErrorCode | None
    audit: DeploymentAudit
    updated_at: datetime
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version}")
        if self.updated_at.tzinfo is None:
            raise ValueError("updated_at must be timezone-aware")


WINDOWS_CAPABILITIES = AdapterCapabilities(
    backend="mock-intune",
    update_kinds=frozenset({UpdateKind.OS, UpdateKind.DRIVER}),
    supports_pause=True,
    supports_resume=True,
    supports_rollback=True,
    supports_scheduling=True,
    supports_reboot_control=True,
    auth="oidc",
)

OEM_CAPABILITIES = AdapterCapabilities(
    backend="mock-oem-agent",
    update_kinds=frozenset({UpdateKind.FIRMWARE, UpdateKind.BIOS, UpdateKind.MICROCODE}),
    supports_pause=False,
    supports_resume=False,
    supports_rollback=False,
    supports_scheduling=True,
    supports_reboot_control=True,
    auth="oidc",
)
