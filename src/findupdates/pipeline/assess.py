"""Assess collector output against inventory and upsert change records.

This module does not deploy updates and does not call Intune or OEM backends.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from findupdates.agents import analysis_to_dict, analyze
from findupdates.agents.models import AgentAnalysis
from findupdates.agents.provider import AgentProvider
from findupdates.applicability import evaluate
from findupdates.applicability.models import ApplicabilityResult
from findupdates.changerecords import (
    ChangeStoreError,
    MemoryChangeStore,
    build_change_record,
    record_to_dict,
    store_from_env,
)
from findupdates.changerecords.github import IssuesTransport
from findupdates.changerecords.models import ChangeRecord
from findupdates.changerecords.store import ChangeRecordStore, UpsertResult
from findupdates.collectors.http import ByteTransport
from findupdates.config import Settings
from findupdates.enrichment import (
    EnrichmentService,
    enrichment_service_from_settings,
    enrichment_to_dict,
)
from findupdates.enrichment.models import CveEnrichment
from findupdates.ids import stable_id
from findupdates.inventory import DeviceInventory, load_inventory, refresh_for_assessment
from findupdates.logging import set_correlation_id, set_log_context
from findupdates.normalization.models import UpdateAdvisory
from findupdates.normalization.serialize import dict_to_advisory
from findupdates.notifications.channels import (
    ChannelAdapter,
    GitHubCommentChannel,
    WebhookChannel,
    WebhookTransport,
)
from findupdates.notifications.models import DeliveryStatus, NotifyResult
from findupdates.notifications.serialize import event_to_dict
from findupdates.notifications.service import NotificationService
from findupdates.pipeline.errors import AssessError
from findupdates.risk import assess as assess_risk
from findupdates.risk.models import RiskAssessment


@dataclass(frozen=True, slots=True)
class AssessOptions:
    advisories: Path
    inventory: Path
    output_dir: Path | None = None
    dry_run: bool = False
    store_name: str = "memory"
    store: ChangeRecordStore | None = None
    environ: Mapping[str, str] | None = None
    transport: IssuesTransport | None = None
    repository: str | None = None
    skip_enrichment: bool = False
    enrichment: EnrichmentService | None = None
    nvd_transport: ByteTransport | None = None
    kev_transport: ByteTransport | None = None
    settings: Settings | None = None
    skip_notify: bool = False
    notifications: NotificationService | None = None
    webhook_transport: WebhookTransport | None = None
    skip_ai: bool = False
    analysis_provider: AgentProvider | None = None


@dataclass(frozen=True, slots=True)
class AssessedChange:
    advisory_id: str
    deployment_group: str
    verdicts: tuple[str, ...]
    policy_result: str
    risk_score: int
    known_exploited: str
    record_id: str
    idempotency_key: str
    created: bool | None
    issue_number: int | None
    notified: bool | None
    notification_suppressed: bool | None
    analyzed: bool | None
    analysis_fallback: bool | None


@dataclass
class AssessRun:
    correlation_id: str
    changes: tuple[AssessedChange, ...]
    exit_code: int
    notes: list[str] = field(default_factory=list)


def assess_collected(options: AssessOptions, *, now: datetime) -> AssessRun:
    """Evaluate advisories, score risk, and upsert one record per advisory/group."""
    correlation_id = stable_id("assess-run", now.isoformat())
    set_correlation_id(correlation_id)
    set_log_context(stage="assess")
    try:
        advisories = load_advisories(options.advisories)
        devices = tuple(
            refresh_for_assessment(item, now) for item in load_inventory(options.inventory)
        )
        store = options.store if options.dry_run else _resolve_store(options)
        enrichment = _enrichment_service(options, now)
        notifications = _notification_service(options)
        changes, notes = _assess_all(
            advisories,
            devices,
            store,
            options,
            now,
            enrichment=enrichment,
            notifications=notifications,
        )
    except (AssessError, ChangeStoreError, OSError, ValueError, KeyError, TypeError) as exc:
        set_log_context(stage="none")
        return AssessRun(correlation_id, (), 1, [str(exc)])
    if options.output_dir is not None:
        write_summary(AssessRun(correlation_id, changes, 0, notes), options.output_dir)
    set_log_context(stage="none")
    return AssessRun(correlation_id, changes, 0, notes)


def load_advisories(path: Path) -> tuple[UpdateAdvisory, ...]:
    """Load schema-shaped advisory JSON from a file or collector output directory."""
    files = _advisory_files(path)
    loaded: list[UpdateAdvisory] = []
    for file in files:
        try:
            payload = json.loads(file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise AssessError(f"advisory file is unreadable: {file}") from exc
        if not isinstance(payload, dict):
            raise AssessError(f"advisory JSON must be an object: {file}")
        try:
            loaded.append(dict_to_advisory(payload))
        except (KeyError, TypeError, ValueError) as exc:
            raise AssessError(f"advisory JSON is invalid: {file}") from exc
    if not loaded:
        raise AssessError("no advisory JSON found")
    return tuple(loaded)


def write_summary(run: AssessRun, output_dir: Path) -> Path:
    """Write a non-secret assess summary next to change-record JSON."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "summary.json"
    payload = {
        "correlation_id": run.correlation_id,
        "exit_code": run.exit_code,
        "changes": [
            {
                "advisory_id": item.advisory_id,
                "deployment_group": item.deployment_group,
                "verdicts": list(item.verdicts),
                "policy_result": item.policy_result,
                "risk_score": item.risk_score,
                "known_exploited": item.known_exploited,
                "idempotency_key": item.idempotency_key,
                "created": item.created,
                "issue_number": item.issue_number,
                "notified": item.notified,
                "notification_suppressed": item.notification_suppressed,
                "analyzed": item.analyzed,
                "analysis_fallback": item.analysis_fallback,
            }
            for item in run.changes
        ],
        "notes": list(run.notes),
    }
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n")
    return path


def write_record(output_dir: Path, record: ChangeRecord) -> Path:
    """Write one change-record JSON file. Token fields are refused."""
    payload = record_to_dict(record)
    if "token" in payload:
        raise AssessError("refusing to write a change record that contains a token field")
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{record.idempotency_key}.json"
    path.write_text(
        json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def write_enrichment(output_dir: Path, records: tuple[CveEnrichment, ...]) -> None:
    """Write enrichment artifacts. Token fields are refused."""
    if not records:
        return
    folder = output_dir / "enrichment"
    folder.mkdir(parents=True, exist_ok=True)
    for record in records:
        payload = enrichment_to_dict(record)
        if "token" in payload:
            raise AssessError("refusing to write enrichment JSON that contains a token field")
        path = folder / f"{record.cve_id}.json"
        path.write_text(
            json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def write_analysis(output_dir: Path, analyses: tuple[AgentAnalysis, ...]) -> None:
    """Write bounded AI analysis artifacts. Token fields are refused."""
    if not analyses:
        return
    folder = output_dir / "analysis"
    folder.mkdir(parents=True, exist_ok=True)
    for analysis in analyses:
        payload = analysis_to_dict(analysis)
        if "token" in payload:
            raise AssessError("refusing to write analysis JSON that contains a token field")
        path = folder / f"{analysis.analysis_id}.json"
        path.write_text(
            json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def write_notification(output_dir: Path, result: NotifyResult) -> None:
    """Write notification artifacts. Token fields are refused."""
    if result.event is None:
        return
    payload = event_to_dict(result.event)
    if "token" in payload:
        raise AssessError("refusing to write notification JSON that contains a token field")
    folder = output_dir / "notifications"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{result.event.event_id}.json"
    path.write_text(
        json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _assess_all(
    advisories: tuple[UpdateAdvisory, ...],
    devices: tuple[DeviceInventory, ...],
    store: ChangeRecordStore | None,
    options: AssessOptions,
    now: datetime,
    *,
    enrichment: EnrichmentService | None,
    notifications: NotificationService | None,
) -> tuple[tuple[AssessedChange, ...], list[str]]:
    grouped: dict[str, list[DeviceInventory]] = defaultdict(list)
    for device in devices:
        grouped[device.deployment_group].append(device)
    rows: list[AssessedChange] = []
    notes: list[str] = []
    for advisory in advisories:
        set_log_context(advisory_id=advisory.advisory_id, stage="assess")
        products_before = advisory.affected_products
        if enrichment is not None:
            outcome = enrichment.enrich(advisory)
            advisory = outcome.advisory
            if advisory.affected_products != products_before:
                raise AssessError("enrichment overwrote vendor affected_products")
            if options.output_dir is not None:
                write_enrichment(options.output_dir, outcome.records)
        for group, members in grouped.items():
            apps = tuple(evaluate(advisory, device, now=now) for device in members)
            risks = tuple(
                assess_risk(advisory, device, app, now=now)
                for device, app in zip(members, apps, strict=True)
            )
            analyses = _analyze_group(
                advisory,
                tuple(members),
                apps,
                risks,
                options,
                now,
            )
            policy_before = tuple(item.policy_result.value for item in risks)
            record = build_change_record(
                advisory,
                tuple(members),
                apps,
                risks,
                now=now,
            )
            if tuple(item.policy_result.value for item in risks) != policy_before:
                raise AssessError("analysis rewrote policy_result")
            if analyses and any(
                item.authoritative.policy_result != record.policy_result for item in analyses
            ):
                raise AssessError("analysis authoritative snapshot diverged from policy_result")
            upsert: UpsertResult | None = None
            if store is not None:
                upsert = store.upsert(record)
                record = upsert.record
            if options.output_dir is not None:
                write_record(options.output_dir, record)
                write_analysis(options.output_dir, analyses)
            notice = _notify(
                notifications,
                advisory,
                tuple(members),
                apps,
                risks,
                record,
                options,
                now,
            )
            if options.output_dir is not None and notice is not None and not notice.suppressed:
                write_notification(options.output_dir, notice)
            notes.append(
                f"{advisory.advisory_id} group={group} "
                f"policy={record.policy_result} key={record.idempotency_key} "
                f"known_exploited={advisory.known_exploited.value}"
                f"{_notify_note(notice)}"
                f"{_ai_note(analyses)}"
            )
            rows.append(
                AssessedChange(
                    advisory_id=advisory.advisory_id,
                    deployment_group=group,
                    verdicts=tuple(item.verdict.value for item in apps),
                    policy_result=record.policy_result,
                    risk_score=record.risk_score,
                    known_exploited=advisory.known_exploited.value,
                    record_id=record.change_id,
                    idempotency_key=record.idempotency_key,
                    created=None if upsert is None else upsert.created,
                    issue_number=None if upsert is None else upsert.issue_number,
                    notified=None if notice is None else not notice.suppressed,
                    notification_suppressed=None if notice is None else notice.suppressed,
                    analyzed=None if not analyses else True,
                    analysis_fallback=None
                    if not analyses
                    else any(item.used_fallback for item in analyses),
                )
            )
    return tuple(rows), notes


def _enrichment_service(options: AssessOptions, now: datetime) -> EnrichmentService | None:
    if options.skip_enrichment:
        return None
    if options.enrichment is not None:
        return options.enrichment
    settings = options.settings or Settings.from_env()
    return enrichment_service_from_settings(
        settings,
        nvd_transport=options.nvd_transport,
        kev_transport=options.kev_transport,
        now=now,
    )


def _notification_service(options: AssessOptions) -> NotificationService | None:
    if options.skip_notify:
        return None
    if options.notifications is not None:
        return options.notifications
    github = GitHubCommentChannel()
    channels: dict[str, ChannelAdapter] = {"github": github}
    if options.dry_run:
        channels["webhook"] = github
    else:
        url = _webhook_url(options.environ)
        if url is not None:
            settings = options.settings or Settings.from_env()
            channels["webhook"] = WebhookChannel(
                url,
                timeout_seconds=settings.http_timeout_seconds,
                transport=options.webhook_transport,
            )
    return NotificationService(channels)


def _analyze_group(
    advisory: UpdateAdvisory,
    devices: tuple[DeviceInventory, ...],
    apps: tuple[ApplicabilityResult, ...],
    risks: tuple[RiskAssessment, ...],
    options: AssessOptions,
    now: datetime,
) -> tuple[AgentAnalysis, ...]:
    if options.skip_ai:
        return ()
    settings = options.settings or Settings.from_env()
    rows: list[AgentAnalysis] = []
    for device, app, risk in zip(devices, apps, risks, strict=True):
        rows.append(
            analyze(
                advisory,
                device,
                app,
                risk,
                now=now,
                provider=options.analysis_provider,
                settings=settings,
            )
        )
    return tuple(rows)


def _ai_note(analyses: tuple[AgentAnalysis, ...]) -> str:
    if not analyses:
        return ""
    if any(item.used_fallback for item in analyses):
        return " ai=fallback"
    return " ai=emitted"


def _notify(
    notifications: NotificationService | None,
    advisory: UpdateAdvisory,
    devices: tuple[DeviceInventory, ...],
    apps: tuple[ApplicabilityResult, ...],
    risks: tuple[RiskAssessment, ...],
    record: ChangeRecord,
    options: AssessOptions,
    now: datetime,
) -> NotifyResult | None:
    if notifications is None:
        return None
    return notifications.notify_advisory(
        advisory,
        devices,
        apps,
        risks,
        record,
        now=now,
        change_record_url=_change_record_url(options, record),
    )


def _change_record_url(options: AssessOptions, record: ChangeRecord) -> str:
    repo = (options.repository or "").strip()
    number = record.github_issue_number
    if repo and number:
        return f"https://github.com/{repo}/issues/{number}"
    return f"https://example.invalid/findupdates/changes/{record.idempotency_key}"


def _webhook_url(environ: Mapping[str, str] | None) -> str | None:
    env = os.environ if environ is None else environ
    raw = env.get("FINDUPDATES_NOTIFICATION_WEBHOOK_URL")
    if raw is None or not raw.strip():
        return None
    return raw.strip()


def _notify_note(result: NotifyResult | None) -> str:
    if result is None:
        return ""
    if result.suppressed:
        return " notify=suppressed"
    failed = [item.channel for item in result.deliveries if item.status is DeliveryStatus.FAILED]
    if failed:
        return f" notify=failed:{','.join(failed)}"
    return " notify=emitted"


def _resolve_store(options: AssessOptions) -> ChangeRecordStore:
    if options.store is not None:
        return options.store
    name = options.store_name.strip().lower()
    if name == "memory":
        return MemoryChangeStore()
    if name != "github":
        raise AssessError(f"unknown change-record store {options.store_name}")
    return store_from_env(
        repository=options.repository,
        environ=options.environ,
        transport=options.transport,
    )


def _advisory_files(path: Path) -> list[Path]:
    if not path.exists():
        raise AssessError(f"advisory path does not exist: {path}")
    if path.is_file():
        if path.name == "summary.json":
            raise AssessError("summary.json is not an advisory")
        return [path]
    files = [
        item
        for item in sorted(path.rglob("*.json"))
        if item.is_file() and item.name != "summary.json"
    ]
    if not files:
        raise AssessError("no advisory JSON found")
    return files
