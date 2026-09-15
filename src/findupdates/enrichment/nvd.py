"""NVD CVE 2.0 lookup. CVSS versions are retained separately."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlencode

from findupdates.collectors.errors import NotFoundError, SourceUnavailableError
from findupdates.collectors.http import HttpClient
from findupdates.collectors.jsonutil import list_of, mapping, parse_datetime, pick, text_of
from findupdates.normalization.models import CvssRecord, CvssVersion, TriState

DEFAULT_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_SOURCE = "nvd"


@dataclass(frozen=True, slots=True)
class NvdFact:
    """Parsed NVD record for one CVE. Missing NVD data is not an outage."""

    cve_id: str
    found: TriState
    cvss: tuple[CvssRecord, ...]
    cwes: tuple[str, ...]
    cpes: tuple[str, ...]
    last_modified: datetime | None
    retrieved_at: datetime
    raw_sha256: str
    stale: bool = False


class NvdClient:
    """Lookup a CVE by id using the public NVD 2.0 API."""

    def __init__(self, *, client: HttpClient, base_url: str = DEFAULT_BASE_URL) -> None:
        self._client = client
        self._base_url = base_url.rstrip("/")

    def lookup(self, cve_id: str, *, retrieved_at: datetime) -> NvdFact:
        """Fetch one CVE. 404/empty results mean not found, not unknown-safe."""
        url = f"{self._base_url}?{urlencode({'cveId': cve_id})}"
        try:
            payload = self._client.get_bytes(url)
        except NotFoundError:
            return _not_found(cve_id, retrieved_at, "e" * 64)
        parsed = _parse_json_object(payload.body, url)
        return parse_nvd_payload(
            parsed, cve_id=cve_id, retrieved_at=retrieved_at, raw_sha256=payload.sha256
        )


def parse_nvd_payload(
    payload: Mapping[str, Any],
    *,
    cve_id: str,
    retrieved_at: datetime,
    raw_sha256: str,
) -> NvdFact:
    """Parse an NVD 2.0 JSON document for a single CVE request."""
    vulns = list_of(pick(payload, "vulnerabilities"))
    if not vulns:
        return _not_found(cve_id, retrieved_at, raw_sha256)
    cve = mapping(pick(mapping(vulns[0]), "cve"))
    if cve is None:
        return _not_found(cve_id, retrieved_at, raw_sha256)
    return NvdFact(
        cve_id=cve_id,
        found=TriState.TRUE,
        cvss=_cvss(cve),
        cwes=_cwes(cve),
        cpes=_cpes(cve),
        last_modified=parse_datetime(pick(cve, "lastModified", "last_modified")),
        retrieved_at=retrieved_at,
        raw_sha256=raw_sha256,
    )


def _not_found(cve_id: str, retrieved_at: datetime, raw_sha256: str) -> NvdFact:
    return NvdFact(
        cve_id=cve_id,
        found=TriState.FALSE,
        cvss=(),
        cwes=(),
        cpes=(),
        last_modified=None,
        retrieved_at=retrieved_at,
        raw_sha256=raw_sha256,
    )


def _cvss(cve: Mapping[str, Any]) -> tuple[CvssRecord, ...]:
    metrics = mapping(pick(cve, "metrics")) or {}
    records: list[CvssRecord] = []
    seen: set[tuple[str, str | None, str]] = set()
    groups: tuple[tuple[str, CvssVersion], ...] = (
        ("cvssMetricV40", CvssVersion.V4_0),
        ("cvssMetricV31", CvssVersion.V3_1),
        ("cvssMetricV30", CvssVersion.V3_0),
        ("cvssMetricV2", CvssVersion.V2_0),
    )
    for key, fallback in groups:
        for item in list_of(pick(metrics, key)):
            node = mapping(item)
            if node is None:
                continue
            data = mapping(pick(node, "cvssData")) or node
            vector = text_of(pick(data, "vectorString", "vector"))
            score = pick(data, "baseScore")
            base_score = float(score) if isinstance(score, int | float) else None
            version = _cvss_version(text_of(pick(data, "version")), fallback, vector)
            source = text_of(pick(node, "source")) or NVD_SOURCE
            record = CvssRecord(version, vector, base_score, f"{NVD_SOURCE}:{source}")
            identity = (record.version.value, record.vector, record.source)
            if identity in seen:
                continue
            seen.add(identity)
            records.append(record)
    return tuple(records)


def _cvss_version(raw: str | None, fallback: CvssVersion, vector: str | None) -> CvssVersion:
    if raw == "4.0" or (vector and vector.startswith("CVSS:4.0")):
        return CvssVersion.V4_0
    if raw == "3.1" or (vector and vector.startswith("CVSS:3.1")):
        return CvssVersion.V3_1
    if raw == "3.0" or (vector and vector.startswith("CVSS:3.0")):
        return CvssVersion.V3_0
    if raw in {"2.0", "2"} or (vector and vector.startswith("AV:")):
        return CvssVersion.V2_0 if raw in {"2.0", "2"} or fallback is CvssVersion.V2_0 else fallback
    return fallback


def _cwes(cve: Mapping[str, Any]) -> tuple[str, ...]:
    found: list[str] = []
    for item in list_of(pick(cve, "weaknesses")):
        node = mapping(item)
        if node is None:
            continue
        for description in list_of(pick(node, "description")):
            text = text_of(pick(mapping(description), "value"))
            if text:
                found.append(text)
    return tuple(dict.fromkeys(found))


def _cpes(cve: Mapping[str, Any]) -> tuple[str, ...]:
    found: list[str] = []
    for config in list_of(pick(cve, "configurations")):
        config_node = mapping(config)
        if config_node is None:
            continue
        for node in list_of(pick(config_node, "nodes")):
            branch = mapping(node)
            if branch is None:
                continue
            for match in list_of(pick(branch, "cpeMatch")):
                criteria = text_of(pick(mapping(match), "criteria", "cpe23Uri"))
                if criteria:
                    found.append(criteria)
    return tuple(dict.fromkeys(found))


def _parse_json_object(body: bytes, url: str) -> Mapping[str, Any]:
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceUnavailableError(f"NVD returned invalid JSON for {url}") from exc
    obj = mapping(parsed)
    if obj is None:
        raise SourceUnavailableError(f"NVD JSON must be an object for {url}")
    return obj
