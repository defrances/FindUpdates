"""Assess collector output against inventory and upsert change records.

This module does not deploy updates and does not call Intune or OEM backends.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from findupdates.applicability import evaluate
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
from findupdates.ids import stable_id
from findupdates.inventory import DeviceInventory, load_inventory, refresh_for_assessment
from findupdates.logging import set_correlation_id, set_log_context
from findupdates.normalization.models import UpdateAdvisory
from findupdates.normalization.serialize import dict_to_advisory
from findupdates.pipeline.errors import AssessError
from findupdates.risk import assess as assess_risk


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


@dataclass(frozen=True, slots=True)
class AssessedChange:
    advisory_id: str
    deployment_group: str
    verdicts: tuple[str, ...]
    policy_result: str
    record_id: str
    idempotency_key: str
    created: bool | None
    issue_number: int | None


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
        changes, notes = _assess_all(advisories, devices, store, options, now)
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
                "idempotency_key": item.idempotency_key,
                "created": item.created,
                "issue_number": item.issue_number,
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


def _assess_all(
    advisories: tuple[UpdateAdvisory, ...],
    devices: tuple[DeviceInventory, ...],
    store: ChangeRecordStore | None,
    options: AssessOptions,
    now: datetime,
) -> tuple[tuple[AssessedChange, ...], list[str]]:
    grouped: dict[str, list[DeviceInventory]] = defaultdict(list)
    for device in devices:
        grouped[device.deployment_group].append(device)
    rows: list[AssessedChange] = []
    notes: list[str] = []
    for advisory in advisories:
        set_log_context(advisory_id=advisory.advisory_id, stage="assess")
        for group, members in grouped.items():
            apps = tuple(evaluate(advisory, device, now=now) for device in members)
            risks = tuple(
                assess_risk(advisory, device, app, now=now)
                for device, app in zip(members, apps, strict=True)
            )
            record = build_change_record(
                advisory,
                tuple(members),
                apps,
                risks,
                now=now,
            )
            upsert: UpsertResult | None = None
            if store is not None:
                upsert = store.upsert(record)
                record = upsert.record
            if options.output_dir is not None:
                write_record(options.output_dir, record)
            notes.append(
                f"{advisory.advisory_id} group={group} "
                f"policy={record.policy_result} key={record.idempotency_key}"
            )
            rows.append(
                AssessedChange(
                    advisory_id=advisory.advisory_id,
                    deployment_group=group,
                    verdicts=tuple(item.verdict.value for item in apps),
                    policy_result=record.policy_result,
                    record_id=record.change_id,
                    idempotency_key=record.idempotency_key,
                    created=None if upsert is None else upsert.created,
                    issue_number=None if upsert is None else upsert.issue_number,
                )
            )
    return tuple(rows), notes


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
