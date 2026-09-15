"""Poll vendor collectors with durable checkpoints and freshness alerts."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from findupdates.collectors.checkpoint import CollectionCheckpoint
from findupdates.collectors.errors import ParseError, SourceUnavailableError
from findupdates.collectors.http import ByteTransport, HttpClient
from findupdates.collectors.intel import IntelCollector
from findupdates.collectors.metrics import CollectionMetrics
from findupdates.collectors.microsoft import MicrosoftCollector
from findupdates.collectors.persist import load_checkpoint, save_checkpoint
from findupdates.collectors.result import CollectionResult
from findupdates.config import Settings
from findupdates.ids import stable_id
from findupdates.logging import set_correlation_id, set_log_context
from findupdates.normalization.serialize import advisory_to_dict
from findupdates.ops.alerts import AlertBus, alert_for_freshness
from findupdates.ops.config import load_operations_config
from findupdates.ops.freshness import evaluate_freshness
from findupdates.ops.metrics import PipelineMetrics
from findupdates.ops.models import (
    Alert,
    MetricSample,
    PipelineStage,
    SourceObservation,
)

ALLOWED_SOURCES = ("msrc", "intel")
_CHECKPOINT_SOURCE = {"msrc": "msrc", "intel": "intel-csaf"}
_OBSERVATION_SOURCE = {"msrc": "msrc", "intel": "intel"}


@dataclass(frozen=True, slots=True)
class PollOptions:
    sources: tuple[str, ...] = ("msrc", "intel")
    checkpoint_dir: Path = Path(".findupdates/checkpoints")
    output_dir: Path | None = None
    dry_run: bool = False
    settings: Settings | None = None
    transport: ByteTransport | None = None
    operations_config: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class SourcePoll:
    source: str
    status: str
    observation: SourceObservation
    metrics: CollectionMetrics | None
    result: CollectionResult | None
    alerts: tuple[Alert, ...]
    notes: tuple[str, ...]


@dataclass
class PollRun:
    correlation_id: str
    sources: tuple[SourcePoll, ...]
    alerts: tuple[Alert, ...]
    exit_code: int
    notes: list[str] = field(default_factory=list)


def resolve_sources(requested: tuple[str, ...]) -> tuple[str, ...]:
    """Normalize CLI source names. ``all`` expands to MSRC then Intel."""
    if not requested or "all" in requested:
        return ALLOWED_SOURCES
    seen: list[str] = []
    for item in requested:
        name = item.strip().lower()
        if name not in ALLOWED_SOURCES:
            raise ValueError(f"unknown collector source {item}")
        if name not in seen:
            seen.append(name)
    return tuple(seen)


def poll(options: PollOptions, *, now: datetime) -> PollRun:
    """Run selected collectors. Deployment kill switch is not consulted."""
    settings = options.settings or Settings.from_env()
    ops = options.operations_config or load_operations_config()
    correlation_id = stable_id("collect-run", now.isoformat())
    set_correlation_id(correlation_id)
    set_log_context(stage="collect")
    bus = AlertBus()
    metrics_bus = PipelineMetrics()
    rows: list[SourcePoll] = []
    notes: list[str] = []
    failed = False
    for source in resolve_sources(options.sources):
        row = _poll_source(
            source,
            options=options,
            settings=settings,
            ops=ops,
            correlation_id=correlation_id,
            bus=bus,
            metrics_bus=metrics_bus,
            now=now,
        )
        rows.append(row)
        notes.extend(row.notes)
        if row.status == "failed":
            failed = True
    set_log_context(stage="none")
    return PollRun(
        correlation_id=correlation_id,
        sources=tuple(rows),
        alerts=bus.alerts(),
        exit_code=1 if failed else 0,
        notes=notes,
    )


def write_summary(run: PollRun, output_dir: Path) -> Path:
    """Write a non-secret run summary next to advisory artifacts."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "summary.json"
    payload = {
        "correlation_id": run.correlation_id,
        "exit_code": run.exit_code,
        "sources": [
            {
                "source": item.source,
                "status": item.status,
                "observation": {
                    "source": item.observation.source,
                    "last_success_at": _iso(item.observation.last_success_at),
                    "last_error": item.observation.last_error,
                    "observed_at": _iso(item.observation.observed_at),
                },
                "metrics": None
                if item.metrics is None
                else {
                    "collected": item.metrics.collected,
                    "changed": item.metrics.changed,
                    "unchanged": item.metrics.unchanged,
                    "failed": item.metrics.failed,
                    "parse_error": item.metrics.parse_error,
                    "skipped": item.metrics.skipped,
                },
                "alerts": [alert.code.value for alert in item.alerts],
                "notes": list(item.notes),
            }
            for item in run.sources
        ],
        "alerts": [
            {"code": item.code.value, "source": item.source, "summary": item.summary}
            for item in run.alerts
        ],
        "notes": list(run.notes),
    }
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n")
    return path


def _poll_source(
    source: str,
    *,
    options: PollOptions,
    settings: Settings,
    ops: dict[str, Any],
    correlation_id: str,
    bus: AlertBus,
    metrics_bus: PipelineMetrics,
    now: datetime,
) -> SourcePoll:
    observation_name = _OBSERVATION_SOURCE[source]
    checkpoint_name = _CHECKPOINT_SOURCE[source]
    if options.dry_run:
        skip_reason = _skip_reason(source, settings)
        note = (
            f"dry-run {source} skip={skip_reason}"
            if skip_reason
            else f"dry-run {source} would poll"
        )
        observation = SourceObservation(observation_name, None, None, now)
        alerts = _freshness_alerts(observation, ops, correlation_id, now, bus)
        return SourcePoll(
            source=source,
            status="skipped" if skip_reason else "dry-run",
            observation=observation,
            metrics=None,
            result=None,
            alerts=alerts,
            notes=(note,),
        )
    skip_reason = _skip_reason(source, settings)
    if skip_reason:
        observation = SourceObservation(observation_name, None, None, now)
        alerts = _freshness_alerts(observation, ops, correlation_id, now, bus)
        return SourcePoll(
            source=source,
            status="skipped",
            observation=observation,
            metrics=None,
            result=None,
            alerts=alerts,
            notes=(f"{source} skipped: {skip_reason}",),
        )
    try:
        prior = load_checkpoint(options.checkpoint_dir, checkpoint_name)
    except ParseError as exc:
        observation = SourceObservation(observation_name, None, str(exc), now)
        alerts = _freshness_alerts(observation, ops, correlation_id, now, bus)
        return SourcePoll(
            source=source,
            status="failed",
            observation=observation,
            metrics=None,
            result=None,
            alerts=alerts,
            notes=(f"{source} checkpoint unreadable: {exc}",),
        )
    client = HttpClient(
        timeout_seconds=settings.http_timeout_seconds,
        max_retries=settings.http_max_retries,
        min_interval_seconds=settings.http_min_interval_seconds,
        transport=options.transport,
    )
    try:
        result = _collect(source, client=client, settings=settings, prior=prior, now=now)
    except SourceUnavailableError as exc:
        last_ok = prior.captured_at if prior is not None else None
        observation = SourceObservation(observation_name, last_ok, str(exc), now)
        alerts = _freshness_alerts(observation, ops, correlation_id, now, bus)
        return SourcePoll(
            source=source,
            status="failed",
            observation=observation,
            metrics=None,
            result=None,
            alerts=alerts,
            notes=(f"{source} failed: {exc}",),
        )
    save_checkpoint(options.checkpoint_dir, result.checkpoint)
    _write_artifacts(options.output_dir, source, result)
    observation = SourceObservation(observation_name, now, None, now)
    _record_metrics(metrics_bus, correlation_id, source, result.metrics, now)
    alerts = _freshness_alerts(observation, ops, correlation_id, now, bus)
    return SourcePoll(
        source=source,
        status="ok",
        observation=observation,
        metrics=result.metrics,
        result=result,
        alerts=alerts,
        notes=(
            (
                f"{source} collected={result.metrics.collected} "
                f"changed={result.metrics.changed} unchanged={result.metrics.unchanged} "
                f"skipped={result.metrics.skipped} failed={result.metrics.failed} "
                f"lookback_days={_lookback_days(source, settings)}"
            ),
        ),
    )


def _collect(
    source: str,
    *,
    client: HttpClient,
    settings: Settings,
    prior: CollectionCheckpoint | None,
    now: datetime,
) -> CollectionResult:
    if source == "msrc":
        collector = MicrosoftCollector(
            client=client,
            base_url=settings.msrc_base_url,
            lookback=timedelta(days=settings.msrc_lookback_days),
            now=now,
        )
        return collector.collect(prior)
    intel = IntelCollector(
        client=client,
        index_url=settings.intel_csaf_index_url,
        lookback=timedelta(days=settings.intel_lookback_days),
        now=now,
    )
    return intel.collect(prior)


def _lookback_days(source: str, settings: Settings) -> int:
    if source == "msrc":
        return settings.msrc_lookback_days
    return settings.intel_lookback_days


def _skip_reason(source: str, settings: Settings) -> str | None:
    if source == "intel" and not settings.intel_csaf_index_url:
        return "FINDUPDATES_INTEL_CSAF_INDEX_URL is not configured"
    return None


def _freshness_alerts(
    observation: SourceObservation,
    ops: dict[str, Any],
    correlation_id: str,
    now: datetime,
    bus: AlertBus,
) -> tuple[Alert, ...]:
    verdict = evaluate_freshness(observation, ops, now=now)
    alert = alert_for_freshness(verdict, observation, correlation_id=correlation_id, now=now)
    if alert is None:
        return ()
    bus.emit(alert)
    return (alert,)


def _record_metrics(
    metrics_bus: PipelineMetrics,
    correlation_id: str,
    source: str,
    metrics: CollectionMetrics,
    now: datetime,
) -> None:
    for name, value in (
        ("collected", metrics.collected),
        ("changed", metrics.changed),
        ("unchanged", metrics.unchanged),
        ("failed", metrics.failed),
        ("parse_error", metrics.parse_error),
        ("skipped", metrics.skipped),
    ):
        metrics_bus.record(
            MetricSample(
                correlation_id=correlation_id,
                advisory_id=source,
                stage=PipelineStage.COLLECT,
                name=name,
                value=value,
                recorded_at=now,
            )
        )


def _write_artifacts(output_dir: Path | None, source: str, result: CollectionResult) -> None:
    if output_dir is None:
        return
    folder = output_dir / source
    folder.mkdir(parents=True, exist_ok=True)
    for advisory in result.advisories:
        path = folder / f"{advisory.advisory_id}.json"
        path.write_text(
            json.dumps(advisory_to_dict(advisory), ensure_ascii=True, indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat().replace("+00:00", "Z")
