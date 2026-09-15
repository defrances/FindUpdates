"""In-memory pipeline metrics. Absence of samples is not a healthy signal."""

from __future__ import annotations

from findupdates.ops.errors import OpsError
from findupdates.ops.models import MetricSample, PipelineStage


class PipelineMetrics:
    """Append-only samples keyed by correlation ID for one advisory lifecycle."""

    def __init__(self) -> None:
        self._samples: list[MetricSample] = []

    def record(self, sample: MetricSample) -> None:
        self._samples.append(sample)

    def samples(self, correlation_id: str | None = None) -> tuple[MetricSample, ...]:
        if correlation_id is None:
            return tuple(self._samples)
        return tuple(item for item in self._samples if item.correlation_id == correlation_id)

    def total(self, name: str, *, correlation_id: str | None = None) -> int:
        return sum(item.value for item in self.samples(correlation_id) if item.name == name)

    def stages(self, correlation_id: str) -> frozenset[PipelineStage]:
        return frozenset(item.stage for item in self.samples(correlation_id))

    def observability_healthy(
        self,
        correlation_id: str,
        required: tuple[PipelineStage, ...],
        *,
        missing_is_healthy: bool,
    ) -> bool:
        """Missing required stage metrics are unhealthy unless policy says otherwise."""
        if missing_is_healthy:
            raise OpsError("missing observability must not be configured as healthy")
        seen = self.stages(correlation_id)
        return all(stage in seen for stage in required)
