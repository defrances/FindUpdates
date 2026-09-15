"""Adapter wrapper that honors the deployment kill switch."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from findupdates.deployment.adapter import DeploymentAdapter
from findupdates.deployment.models import (
    AdapterCapabilities,
    DeploymentRequest,
    DeploymentResult,
    OidcCredential,
)
from findupdates.ops.killswitch import assert_deployments_enabled


class GuardedDeploymentAdapter:
    """Refuse new deploy/resume/rollback when deployments are independently disabled."""

    def __init__(
        self,
        inner: DeploymentAdapter,
        config: dict[str, Any],
        *,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self._inner = inner
        self._config = config
        self._environ = environ

    def capabilities(self) -> AdapterCapabilities:
        return self._inner.capabilities()

    def validate_request(self, request: DeploymentRequest) -> None:
        self._inner.validate_request(request)

    def deploy(
        self,
        request: DeploymentRequest,
        *,
        credential: OidcCredential,
        now: datetime,
    ) -> DeploymentResult:
        assert_deployments_enabled(self._config, environ=self._environ)
        return self._inner.deploy(request, credential=credential, now=now)

    def status(self, deployment_id: str) -> DeploymentResult:
        return self._inner.status(deployment_id)

    def pause(
        self,
        deployment_id: str,
        *,
        credential: OidcCredential,
        now: datetime,
    ) -> DeploymentResult:
        return self._inner.pause(deployment_id, credential=credential, now=now)

    def resume(
        self,
        deployment_id: str,
        *,
        credential: OidcCredential,
        now: datetime,
    ) -> DeploymentResult:
        assert_deployments_enabled(self._config, environ=self._environ)
        return self._inner.resume(deployment_id, credential=credential, now=now)

    def rollback_or_uninstall(
        self,
        deployment_id: str,
        *,
        credential: OidcCredential,
        now: datetime,
    ) -> DeploymentResult:
        assert_deployments_enabled(self._config, environ=self._environ)
        return self._inner.rollback_or_uninstall(deployment_id, credential=credential, now=now)

    def cancel(
        self,
        deployment_id: str,
        *,
        credential: OidcCredential,
        now: datetime,
    ) -> DeploymentResult:
        return self._inner.cancel(deployment_id, credential=credential, now=now)
