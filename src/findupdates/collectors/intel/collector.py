"""Intel CSAF collector with incremental checkpoints."""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from findupdates.collectors.checkpoint import CollectionCheckpoint
from findupdates.collectors.errors import SourceUnavailableError
from findupdates.collectors.http import HttpClient
from findupdates.collectors.intel.csaf import parse_csaf_document
from findupdates.collectors.jsonutil import (
    list_of,
    mapping,
    parse_datetime,
    pick,
    sha256_bytes,
    text_of,
)
from findupdates.collectors.metrics import CollectionMetrics
from findupdates.collectors.result import CollectionResult
from findupdates.normalization.models import normalize_source_record

LOGGER = logging.getLogger("findupdates.collectors.intel")
DEFAULT_LOOKBACK = timedelta(days=120)


@dataclass(frozen=True, slots=True)
class _IndexEntry:
    document_id: str
    updated_at: datetime
    url: str


class IntelCollector:
    """Collect Intel CSAF documents from a machine-readable index."""

    def __init__(
        self,
        *,
        client: HttpClient,
        index_url: str | None,
        lookback: timedelta = DEFAULT_LOOKBACK,
        now: datetime | None = None,
    ) -> None:
        self._client = client
        self._index_url = index_url
        self._lookback = lookback
        self._now = now

    def collect(self, checkpoint: CollectionCheckpoint | None = None) -> CollectionResult:
        """Fetch the configured CSAF index, then selected advisory documents."""
        if not self._index_url:
            raise SourceUnavailableError("Intel CSAF index URL is not configured")
        retrieved_at = self._now or datetime.now(UTC)
        payload = self._client.get_json(self._index_url)
        entries = _index_entries(payload)
        selected = _select_entries(
            entries,
            checkpoint=checkpoint,
            retrieved_at=retrieved_at,
            lookback=self._lookback,
        )
        documents: list[tuple[str, bytes]] = []
        failed = 0
        errors: list[str] = []
        for entry in selected:
            try:
                fetched = self._client.get_bytes(entry.url)
            except SourceUnavailableError as exc:
                failed += 1
                errors.append(f"{entry.document_id}: {exc}")
                LOGGER.warning("intel CSAF fetch failed document_id=%s", entry.document_id)
                continue
            documents.append((entry.url, fetched.body))
        if not documents and failed:
            raise SourceUnavailableError(
                "all selected Intel CSAF documents failed; last checkpoint preserved"
            )
        result = self.collect_documents(documents, checkpoint=checkpoint, retrieved_at=retrieved_at)
        return CollectionResult(
            advisories=result.advisories,
            metrics=result.metrics.add(failed=failed),
            checkpoint=result.checkpoint,
            errors=result.errors + tuple(errors),
        )

    def collect_documents(
        self,
        documents: list[tuple[str, bytes]],
        *,
        checkpoint: CollectionCheckpoint | None = None,
        retrieved_at: datetime | None = None,
    ) -> CollectionResult:
        """Normalize already-fetched CSAF documents."""
        collected_at = retrieved_at or self._now or datetime.now(UTC)
        previous_hashes = checkpoint.hashes_as_dict() if checkpoint else {}
        advisories = []
        errors: list[str] = []
        metrics = CollectionMetrics()
        next_hashes = dict(previous_hashes)
        for source_url, body in documents:
            digest = sha256_bytes(body)
            try:
                parsed = _load_json_object(body)
                record = parse_csaf_document(
                    parsed, source_url=source_url, retrieved_at=collected_at
                )
            except (SourceUnavailableError, ValueError, TypeError, KeyError) as exc:
                errors.append(f"{source_url}: {exc}")
                metrics = metrics.add(parse_error=1)
                continue
            advisory = normalize_source_record(record)
            advisories.append(advisory)
            key = f"adv:{advisory.vendor_advisory_id or advisory.advisory_id}"
            previous = previous_hashes.get(key)
            metrics = metrics.add(collected=1)
            if previous == digest or previous == record.provenance.raw_sha256:
                metrics = metrics.add(unchanged=1)
            else:
                metrics = metrics.add(changed=1)
            next_hashes[key] = record.provenance.raw_sha256
            next_hashes[f"doc:{advisory.vendor_advisory_id or digest}"] = digest
        new_checkpoint = CollectionCheckpoint(
            source="intel-csaf",
            cursor=collected_at.isoformat().replace("+00:00", "Z"),
            document_hashes=tuple(sorted(next_hashes.items())),
            captured_at=collected_at,
        )
        return CollectionResult(
            advisories=tuple(advisories),
            metrics=metrics,
            checkpoint=new_checkpoint,
            errors=tuple(errors),
        )


def _load_json_object(body: bytes) -> Mapping[str, Any]:
    try:
        parsed_obj = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceUnavailableError("Intel CSAF document is not valid JSON") from exc
    parsed = mapping(parsed_obj)
    if parsed is None:
        raise SourceUnavailableError("Intel CSAF document JSON must be an object")
    return parsed


def _index_entries(payload: object) -> list[_IndexEntry]:
    root = mapping(payload)
    items = list_of(pick(root, "advisories") if root is not None else payload)
    entries: list[_IndexEntry] = []
    for item in items:
        node = mapping(item)
        if node is None:
            continue
        document_id = text_of(pick(node, "id")) or ""
        updated = parse_datetime(pick(node, "updated", "current_release_date"))
        url = text_of(pick(node, "url"))
        if not document_id or updated is None or url is None:
            continue
        entries.append(_IndexEntry(document_id=document_id, updated_at=updated, url=url))
    return entries


def _select_entries(
    entries: list[_IndexEntry],
    *,
    checkpoint: CollectionCheckpoint | None,
    retrieved_at: datetime,
    lookback: timedelta,
) -> list[_IndexEntry]:
    if checkpoint is None:
        start = retrieved_at - lookback
        return [entry for entry in entries if entry.updated_at >= start]
    cursor = parse_datetime(checkpoint.cursor)
    if cursor is None:
        return entries
    return [entry for entry in entries if entry.updated_at >= cursor]
