"""Idempotent GitHub Issue store for change records."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from findupdates.changerecords.build import labels_for
from findupdates.changerecords.models import ChangeRecord
from findupdates.changerecords.serialize import issue_body, parse_issue_body, record_to_dict


@dataclass(frozen=True, slots=True)
class UpsertResult:
    record: ChangeRecord
    created: bool
    issue_number: int


class ChangeRecordStore(Protocol):
    """Persistence for one logical change issue per idempotency key."""

    def upsert(self, record: ChangeRecord) -> UpsertResult: ...

    def get(self, idempotency_key: str) -> ChangeRecord | None: ...


class MemoryChangeStore:
    """In-memory store used by unit tests and local dry-runs."""

    def __init__(self) -> None:
        self._by_key: dict[str, ChangeRecord] = {}
        self._next_issue = 1

    def upsert(self, record: ChangeRecord) -> UpsertResult:
        existing = self._by_key.get(record.idempotency_key)
        if existing is None:
            issue = self._next_issue
            self._next_issue += 1
            stored = _with_issue(record, issue)
            self._by_key[record.idempotency_key] = stored
            return UpsertResult(stored, True, issue)
        stored = _with_issue(
            record,
            existing.github_issue_number or self._next_issue,
        )
        self._by_key[record.idempotency_key] = stored
        return UpsertResult(stored, False, stored.github_issue_number or 0)

    def get(self, idempotency_key: str) -> ChangeRecord | None:
        return self._by_key.get(idempotency_key)


def render_github_issue(record: ChangeRecord) -> dict[str, object]:
    """Payload a GitHub Issues adapter would POST/PATCH. Token is not included."""
    return {
        "title": (
            f"[{record.severity}/{record.policy_result}] "
            f"{record.advisory_ids[0]} @ {record.deployment_group}"
        ),
        "body": issue_body(record),
        "labels": list(labels_for(record)),
        "idempotency_key": record.idempotency_key,
        "record": record_to_dict(record),
    }


def load_from_issue_body(body: str) -> ChangeRecord:
    """Parse a GitHub Issue body back into a change record."""
    return parse_issue_body(body)


def _with_issue(record: ChangeRecord, issue_number: int) -> ChangeRecord:
    return ChangeRecord(
        change_id=record.change_id,
        idempotency_key=record.idempotency_key,
        lifecycle=record.lifecycle,
        advisory_ids=record.advisory_ids,
        device_ids=record.device_ids,
        deployment_group=record.deployment_group,
        risk_score=record.risk_score,
        severity=record.severity,
        policy_result=record.policy_result,
        vendor=record.vendor,
        evidence_links=record.evidence_links,
        validation_plan=record.validation_plan,
        rollout_plan=record.rollout_plan,
        overrides=record.overrides,
        github_issue_number=issue_number,
        updated_at=record.updated_at,
    )
