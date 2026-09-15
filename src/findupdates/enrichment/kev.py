"""CISA Known Exploited Vulnerabilities catalog ingestion."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from findupdates.collectors.errors import SourceUnavailableError
from findupdates.collectors.http import HttpClient
from findupdates.collectors.jsonutil import list_of, mapping, pick, text_of
from findupdates.normalization.models import TriState

DEFAULT_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


@dataclass(frozen=True, slots=True)
class KevEntry:
    """One KEV row. Absence from the catalog is not proof of no exploitation."""

    cve_id: str
    date_added: str | None
    due_date: str | None
    required_action: str | None
    ransomware_use: TriState


@dataclass(frozen=True, slots=True)
class KevCatalog:
    """Loaded KEV catalog. Lookups against a missing catalog must stay unknown."""

    version: str | None
    date_released: str | None
    retrieved_at: datetime
    raw_sha256: str
    entries: dict[str, KevEntry]
    stale: bool = False

    def listing(self, cve_id: str) -> TriState:
        """Return whether the CVE is in this successfully loaded catalog."""
        return TriState.TRUE if cve_id in self.entries else TriState.FALSE


class KevClient:
    """Fetch the CISA KEV JSON feed once per refresh window."""

    def __init__(self, *, client: HttpClient, url: str = DEFAULT_KEV_URL) -> None:
        self._client = client
        self._url = url

    def load(self, *, retrieved_at: datetime) -> KevCatalog:
        """Download and index the catalog. Failure must not be an empty catalog."""
        payload = self._client.get_bytes(self._url)
        parsed = _parse_json_object(payload.body, self._url)
        return parse_kev_payload(parsed, retrieved_at=retrieved_at, raw_sha256=payload.sha256)


def parse_kev_payload(
    payload: Mapping[str, Any],
    *,
    retrieved_at: datetime,
    raw_sha256: str,
) -> KevCatalog:
    """Parse the CISA KEV JSON document."""
    entries: dict[str, KevEntry] = {}
    for item in list_of(pick(payload, "vulnerabilities")):
        node = mapping(item)
        if node is None:
            continue
        cve_id = text_of(pick(node, "cveID", "cveId", "cve_id"))
        if not cve_id or not cve_id.startswith("CVE-"):
            continue
        entries[cve_id] = KevEntry(
            cve_id=cve_id,
            date_added=text_of(pick(node, "dateAdded", "date_added")),
            due_date=text_of(pick(node, "dueDate", "due_date")),
            required_action=text_of(pick(node, "requiredAction", "required_action")),
            ransomware_use=_ransomware(text_of(pick(node, "knownRansomwareCampaignUse"))),
        )
    return KevCatalog(
        version=text_of(pick(payload, "catalogVersion", "catalog_version")),
        date_released=text_of(pick(payload, "dateReleased", "date_released")),
        retrieved_at=retrieved_at,
        raw_sha256=raw_sha256,
        entries=entries,
    )


def _ransomware(value: str | None) -> TriState:
    if value is None:
        return TriState.UNKNOWN
    normalized = value.strip().lower()
    if normalized == "known":
        return TriState.TRUE
    if normalized in {"unknown", ""}:
        return TriState.UNKNOWN
    if normalized in {"not known", "no"}:
        return TriState.FALSE
    return TriState.UNKNOWN


def _parse_json_object(body: bytes, url: str) -> Mapping[str, Any]:
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceUnavailableError(f"KEV returned invalid JSON for {url}") from exc
    obj = mapping(parsed)
    if obj is None:
        raise SourceUnavailableError(f"KEV JSON must be an object for {url}")
    return obj
