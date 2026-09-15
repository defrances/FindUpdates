"""Backend-neutral adapter contract. Implementations must not invent scope."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from findupdates.deployment.models import (
    AdapterCapabilities,
    DeploymentRequest,
    DeploymentResult,
    OidcCredential,
)


class DeploymentAdapter(Protocol):
    """Execute only already-authorized requests through an approved channel."""

    def capabilities(self) -> AdapterCapabilities:
        """Describe pause, rollback and update-kind support."""
        ...

    def validate_request(self, request: DeploymentRequest) -> None:
        """Fail closed before any backend side effect."""
        ...

    def deploy(
        self,
        request: DeploymentRequest,
        *,
        credential: OidcCredential,
        now: datetime,
    ) -> DeploymentResult:
        """Submit the approved request. Same idempotency key must not reinstall."""
        ...

    def status(self, deployment_id: str) -> DeploymentResult:
        """Return the last known backend state."""
        ...

    def pause(
        self,
        deployment_id: str,
        *,
        credential: OidcCredential,
        now: datetime,
    ) -> DeploymentResult:
        """Pause an in-progress job when the backend supports it."""
        ...

    def resume(
        self,
        deployment_id: str,
        *,
        credential: OidcCredential,
        now: datetime,
    ) -> DeploymentResult:
        """Resume a paused job when the backend supports it."""
        ...

    def rollback_or_uninstall(
        self,
        deployment_id: str,
        *,
        credential: OidcCredential,
        now: datetime,
    ) -> DeploymentResult:
        """Roll back only when the backend capability is explicitly true."""
        ...

    def cancel(
        self,
        deployment_id: str,
        *,
        credential: OidcCredential,
        now: datetime,
    ) -> DeploymentResult:
        """Cancel a job that has not finished installing."""
        ...
