"""Build an immutable deployment request from approved inputs."""

from __future__ import annotations

from collections.abc import Sequence

from findupdates.deployment.hashing import hash_targets
from findupdates.deployment.models import (
    AuthorizationEvidence,
    DeploymentRequest,
    DeploymentTarget,
    PackageIdentity,
    RolloutPolicy,
)
from findupdates.ids import stable_id


def make_idempotency_key(
    update: PackageIdentity,
    targets: Sequence[DeploymentTarget],
    evidence: AuthorizationEvidence,
    *,
    dry_run: bool,
) -> str:
    """Stable key for one authorized package, target set and change record."""
    devices = ",".join(sorted(item.device_id for item in targets))
    return stable_id(
        "deploy",
        update.package_id,
        update.version,
        update.sha256,
        devices,
        evidence.change_idempotency_key,
        "dry" if dry_run else "live",
    )


def prepare(
    update: PackageIdentity,
    targets: Sequence[DeploymentTarget],
    rollout: RolloutPolicy,
    evidence: AuthorizationEvidence,
    *,
    dry_run: bool = False,
    oem_qualified: bool = False,
    request_id: str | None = None,
    idempotency_key: str | None = None,
) -> DeploymentRequest:
    """Create a request. The adapter still has to validate and execute it."""
    frozen_targets = tuple(targets)
    key = idempotency_key or make_idempotency_key(update, frozen_targets, evidence, dry_run=dry_run)
    return DeploymentRequest(
        request_id=request_id or stable_id("dreq", key),
        idempotency_key=key,
        dry_run=dry_run,
        update=update,
        targets=frozen_targets,
        approved_target_set_hash=hash_targets(frozen_targets),
        rollout=rollout,
        evidence=evidence,
        oem_qualified=oem_qualified,
    )
