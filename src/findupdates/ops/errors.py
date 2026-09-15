"""Fail-closed operational errors. Missing telemetry is never treated as healthy."""

from findupdates.ops.models import Alert


class OpsError(Exception):
    """Base class for security/observability control failures."""


class DeploymentDisabled(OpsError):
    """Kill switch is engaged. Collection and assessment may continue."""


class IntegrityMismatch(OpsError):
    """Artifact bytes do not match the expected SHA-256 digest."""


class FreshnessFailure(OpsError):
    """A vendor source or inventory snapshot is stale or unobserved."""


class DeadLetterExhausted(OpsError):
    """A pipeline event exceeded retry policy and was quarantined."""

    def __init__(self, message: str, *, alert: Alert) -> None:
        super().__init__(message)
        self.alert = alert
