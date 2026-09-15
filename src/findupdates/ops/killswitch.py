"""Emergency deployment kill switch. Collection and assessment stay available."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from findupdates.ops.config import deployments_enabled, load_operations_config
from findupdates.ops.errors import DeploymentDisabled


def assert_deployments_enabled(
    config: dict[str, Any] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> None:
    """Fail closed before any backend side effect when the kill switch is on."""
    policy = config if config is not None else load_operations_config()
    enabled, reason = deployments_enabled(policy, environ=environ)
    if not enabled:
        raise DeploymentDisabled(
            "new deployments are disabled "
            f"({reason}); collection and risk analysis remain operational"
        )
