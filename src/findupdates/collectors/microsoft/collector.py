"""Microsoft MSRC CVRF collector with incremental checkpoints."""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote, urlencode

from findupdates.collectors.checkpoint import CollectionCheckpoint
from findupdates.collectors.errors import ParseError, SourceUnavailableError
from findupdates.collectors.http import HttpClient
from findupdates.collectors.jsonutil import (
    list_of,
    mapping,
    parse_datetime,
    pick,
    sha256_bytes,
    text_of,
)
from findupdates.collectors.lookback import advisory_in_lookback, window_start
from findupdates.collectors.metrics import CollectionMetrics
from findupdates.collectors.microsoft.cvrf import parse_cvrf_document
from findupdates.collectors.microsoft.xmlcvrf import parse_cvrf_xml
from findupdates.collectors.result import CollectionResult
from findupdates.normalization.models import UpdateAdvisory, normalize_source_record

LOGGER = logging.getLogger("findupdates.collectors.microsoft")
DEFAULT_BASE_URL = "https://api.msrc.microsoft.com/cvrf/v3.0"
DEFAULT_LOOKBACK = timedelta(days=7)
DOCUMENT_LOOKBACK_FLOOR = timedelta(days=45)
MSRC_API_VERSION = "2023-11-01"


@dataclass(frozen=True, slots=True)
class _IndexEntry:
    document_id: str
    current_release_date: datetime
    url: str


class MicrosoftCollector:
    """Collect MSRC CVRF documents and emit canonical UpdateAdvisory records."""

    def __init__(
        self,
        *,
        client: HttpClient,
        base_url: str = DEFAULT_BASE_URL,
        lookback: timedelta = DEFAULT_LOOKBACK,
        now: datetime | None = None,
    ) -> None:
        self._client = client
        self._base_url = base_url.rstrip("/")
        self._lookback = lookback
        self._now = now

    def collect(self, checkpoint: CollectionCheckpoint | None = None) -> CollectionResult:
        """Fetch the MSRC index, then documents in the lookback/revision window."""
        retrieved_at = self._now or datetime.now(UTC)
        document_lookback = _document_lookback(self._lookback)
        after = _incremental_after(
            checkpoint, retrieved_at=retrieved_at, lookback=document_lookback
        )
        index_url = updates_url(self._base_url, after=after)
        payload = self._client.get_json(index_url)
        entries = _index_entries(payload, base_url=self._base_url)
        selected = _select_entries(
            entries,
            checkpoint=checkpoint,
            retrieved_at=retrieved_at,
            lookback=document_lookback,
        )
        documents: list[tuple[str, bytes, str]] = []
        failed = 0
        errors: list[str] = []
        for entry in selected:
            try:
                fetched = self._client.get_bytes(entry.url)
            except SourceUnavailableError as exc:
                failed += 1
                errors.append(f"{entry.document_id}: {exc}")
                LOGGER.warning("msrc document fetch failed document_id=%s", entry.document_id)
                continue
            documents.append((entry.url, fetched.body, fetched.sha256))
        if not documents and failed:
            raise SourceUnavailableError(
                "all selected MSRC documents failed; last checkpoint preserved"
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
        documents: list[tuple[str, bytes]] | list[tuple[str, bytes, str]],
        *,
        checkpoint: CollectionCheckpoint | None = None,
        retrieved_at: datetime | None = None,
    ) -> CollectionResult:
        """Normalize already-fetched CVRF documents. Used by tests and collect()."""
        collected_at = retrieved_at or self._now or datetime.now(UTC)
        previous_hashes = checkpoint.hashes_as_dict() if checkpoint else {}
        advisories: list[UpdateAdvisory] = []
        errors: list[str] = []
        metrics = CollectionMetrics()
        next_hashes = dict(previous_hashes)
        for item in documents:
            source_url, body, *rest = item
            digest = rest[0] if rest else sha256_bytes(body)
            try:
                document_id, parsed, content_type = _load_document(body)
            except (SourceUnavailableError, ParseError) as exc:
                errors.append(str(exc))
                metrics = metrics.add(failed=1, parse_error=1)
                continue
            previous = previous_hashes.get(f"doc:{document_id}")
            document_unchanged = previous == digest
            records, record_errors = parse_cvrf_document(
                parsed,
                source_url=source_url,
                retrieved_at=collected_at,
                document_sha256=digest,
                content_type=content_type,
            )
            errors.extend(record_errors)
            metrics = metrics.add(parse_error=len(record_errors))
            next_hashes[f"doc:{document_id}"] = digest
            for record in records:
                advisory = normalize_source_record(record)
                advisory_key = f"adv:{advisory.vendor_advisory_id or advisory.advisory_id}"
                next_hashes[advisory_key] = record.provenance.raw_sha256
                if not advisory_in_lookback(
                    advisory, retrieved_at=collected_at, lookback=self._lookback
                ):
                    metrics = metrics.add(skipped=1)
                    continue
                advisories.append(advisory)
                metrics = metrics.add(collected=1)
                previous_advisory = previous_hashes.get(advisory_key)
                if document_unchanged or previous_advisory == record.provenance.raw_sha256:
                    metrics = metrics.add(unchanged=1)
                else:
                    metrics = metrics.add(changed=1)
        new_checkpoint = CollectionCheckpoint(
            source="msrc",
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


def updates_url(base_url: str, *, after: datetime | None = None) -> str:
    """Build the MSRC /Updates URL on the fixed API host."""
    query: dict[str, str] = {"api-version": MSRC_API_VERSION}
    if after is not None:
        if after.tzinfo is None:
            raise ValueError("after must be timezone-aware")
        query["$filter"] = f"CurrentReleaseDate gt {after.astimezone(UTC).date().isoformat()}"
    return f"{base_url.rstrip('/')}/Updates?{urlencode(query)}"


def cvrf_url(base_url: str, document_id: str) -> str:
    """Build a detail URL on the fixed MSRC host. Source CvrfUrl values are never used."""
    if not document_id.strip():
        raise ValueError("document_id must not be empty")
    query = urlencode({"api-version": MSRC_API_VERSION})
    return f"{base_url.rstrip('/')}/cvrf/{quote(document_id, safe='')}?{query}"


def _load_document(body: bytes) -> tuple[str, Mapping[str, Any], str]:
    stripped = body.lstrip()
    if stripped.startswith(b"<"):
        document_id, parsed = parse_cvrf_xml(body)
        return document_id, parsed, "application/xml"
    try:
        parsed_obj = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ParseError("MSRC document is not valid JSON") from exc
    parsed_json = mapping(parsed_obj)
    if parsed_json is None:
        raise ParseError("MSRC document JSON must be an object")
    tracking = mapping(pick(parsed_json, "DocumentTracking")) or {}
    identification = mapping(pick(tracking, "Identification")) or {}
    document_id = text_of(pick(identification, "ID")) or "unknown-document"
    return document_id, parsed_json, "application/json"


def _index_entries(payload: object, *, base_url: str) -> list[_IndexEntry]:
    root = mapping(payload)
    if root is None:
        if isinstance(payload, list):
            items = payload
        else:
            raise SourceUnavailableError("MSRC Updates index must be a JSON object")
    else:
        items = list_of(pick(root, "value"))
    entries: list[_IndexEntry] = []
    for item in items:
        node = mapping(item)
        if node is None:
            continue
        document_id = text_of(pick(node, "ID", "Alias")) or ""
        release = parse_datetime(pick(node, "CurrentReleaseDate"))
        if not document_id or release is None:
            continue
        entries.append(
            _IndexEntry(
                document_id=document_id,
                current_release_date=release,
                url=cvrf_url(base_url, document_id),
            )
        )
    return entries


def _select_entries(
    entries: list[_IndexEntry],
    *,
    checkpoint: CollectionCheckpoint | None,
    retrieved_at: datetime,
    lookback: timedelta,
) -> list[_IndexEntry]:
    if checkpoint is None:
        start = window_start(retrieved_at, lookback)
        return [entry for entry in entries if entry.current_release_date >= start]
    cursor = parse_datetime(checkpoint.cursor)
    if cursor is None:
        return entries
    return [entry for entry in entries if entry.current_release_date >= cursor]


def _document_lookback(lookback: timedelta) -> timedelta:
    return lookback if lookback >= DOCUMENT_LOOKBACK_FLOOR else DOCUMENT_LOOKBACK_FLOOR


def _incremental_after(
    checkpoint: CollectionCheckpoint | None,
    *,
    retrieved_at: datetime,
    lookback: timedelta,
) -> datetime:
    if checkpoint is None:
        return window_start(retrieved_at, lookback)
    cursor = parse_datetime(checkpoint.cursor)
    return cursor if cursor is not None else window_start(retrieved_at, lookback)
