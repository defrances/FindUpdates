"""Microsoft Security Response Center (MSRC) update collector."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from http.client import HTTPResponse
from typing import Any, Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ET

from findupdates.normalization import AffectedProduct, UpdateAdvisory

MSRC_BASE_URL = "https://api.msrc.microsoft.com/cvrf/v3.0"
MSRC_API_VERSION = "2023-11-01"
PARSER_VERSION = "msrc-v1"
MAX_RESPONSE_BYTES = 25 * 1024 * 1024
_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
_CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$", re.IGNORECASE)
_KB_RE = re.compile(r"\bKB\s*([0-9]{6,8})\b", re.IGNORECASE)


class MsrcError(RuntimeError):
    """Base class for MSRC collection failures."""


class MsrcTransportError(MsrcError):
    """Raised for transport-level failures."""


class MsrcHttpError(MsrcError):
    """Raised for a non-retryable or exhausted HTTP response."""


class MsrcParseError(MsrcError):
    """Raised when source data cannot be safely interpreted."""


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    content_type: str
    body: bytes
    headers: Mapping[str, str]


class HttpTransport(Protocol):
    """Minimal injectable transport for deterministic collector tests."""

    def get(
        self,
        url: str,
        *,
        timeout_seconds: float,
        headers: Mapping[str, str],
    ) -> HttpResponse: ...


class UrllibTransport:
    """Standard-library HTTPS transport with bounded response reads."""

    def get(
        self,
        url: str,
        *,
        timeout_seconds: float,
        headers: Mapping[str, str],
    ) -> HttpResponse:
        request = Request(url, headers=dict(headers), method="GET")
        try:
            with urlopen(request, timeout=timeout_seconds) as raw_response:
                response = cast(HTTPResponse, raw_response)
                body = _read_bounded(response)
                return HttpResponse(
                    status=response.status,
                    content_type=response.headers.get_content_type(),
                    body=body,
                    headers={key.lower(): value for key, value in response.headers.items()},
                )
        except HTTPError as exc:
            body = exc.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise MsrcTransportError("MSRC error response exceeded size limit") from exc
            response_headers = (
                {key.lower(): value for key, value in exc.headers.items()} if exc.headers else {}
            )
            content_type = exc.headers.get_content_type() if exc.headers else ""
            return HttpResponse(
                status=exc.code,
                content_type=content_type,
                body=body,
                headers=response_headers,
            )
        except URLError as exc:
            raise MsrcTransportError(f"MSRC transport failure: {exc.reason}") from exc


@dataclass(frozen=True, slots=True)
class UpdateSummary:
    update_id: str
    title: str
    severity: str | None
    initial_release_date: datetime
    current_release_date: datetime
    cvrf_url: str | None


@dataclass(frozen=True, slots=True)
class CollectionError:
    update_id: str
    error_type: str
    message: str


@dataclass(frozen=True, slots=True)
class CollectionMetrics:
    collected: int
    changed: int
    unchanged: int
    failed: int
    parse_errors: int


@dataclass(frozen=True, slots=True)
class CollectionResult:
    advisories: tuple[UpdateAdvisory, ...]
    errors: tuple[CollectionError, ...]
    metrics: CollectionMetrics


class MsrcClient:
    """Collect and normalize MSRC v3 update documents."""

    def __init__(
        self,
        *,
        transport: HttpTransport | None = None,
        timeout_seconds: float = 20.0,
        max_attempts: int = 3,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        self._transport = transport or UrllibTransport()
        self._timeout_seconds = timeout_seconds
        self._max_attempts = max_attempts
        self._sleeper = sleeper

    def list_update_summaries(self, *, after: datetime | None = None) -> tuple[UpdateSummary, ...]:
        """List update documents, optionally using an incremental release-date filter."""
        query: dict[str, str] = {"api-version": MSRC_API_VERSION}
        if after is not None:
            if after.tzinfo is None:
                raise ValueError("after must be timezone-aware")
            release_date = after.astimezone(UTC).date().isoformat()
            query["$filter"] = f"CurrentReleaseDate gt {release_date}"
        url = f"{MSRC_BASE_URL}/Updates?{urlencode(query)}"
        response = self._request(url, accept="application/json")
        payload = _load_json(response.body)
        if isinstance(payload, list):
            items = payload
        elif isinstance(payload, dict) and isinstance(payload.get("value"), list):
            items = cast(list[Any], payload["value"])
        else:
            raise MsrcParseError("MSRC Updates response must be an array or contain value[]")
        summaries = [_parse_update_summary(item) for item in items]
        return tuple(sorted(summaries, key=lambda item: item.update_id))

    def fetch_cvrf(self, update_id: str) -> HttpResponse:
        """Fetch a detailed CVRF document from the fixed MSRC host."""
        if not update_id.strip():
            raise ValueError("update_id must not be empty")
        encoded_id = quote(update_id, safe="")
        query = urlencode({"api-version": MSRC_API_VERSION})
        url = f"{MSRC_BASE_URL}/cvrf/{encoded_id}?{query}"
        accept = "application/json, application/xml;q=0.9, text/xml;q=0.8"
        return self._request(url, accept=accept)

    def collect(
        self,
        *,
        after: datetime | None = None,
        known_hashes: Mapping[str, str] | None = None,
        collected_at: datetime | None = None,
    ) -> CollectionResult:
        """Collect updates while isolating failures to individual CVRF documents."""
        effective_collected_at = collected_at or datetime.now(UTC)
        if effective_collected_at.tzinfo is None:
            raise ValueError("collected_at must be timezone-aware")
        previous_hashes = known_hashes or {}
        advisories_by_id: dict[str, UpdateAdvisory] = {}
        errors: list[CollectionError] = []
        failed = 0
        parse_errors = 0

        for summary in self.list_update_summaries(after=after):
            try:
                response = self.fetch_cvrf(summary.update_id)
                normalized = normalize_cvrf(
                    summary,
                    response,
                    collected_at=effective_collected_at,
                )
            except MsrcParseError as exc:
                failed += 1
                parse_errors += 1
                errors.append(CollectionError(summary.update_id, "parse", str(exc)))
                continue
            except MsrcError as exc:
                failed += 1
                errors.append(CollectionError(summary.update_id, "source", str(exc)))
                continue
            for advisory in normalized:
                advisories_by_id[advisory.advisory_id] = advisory

        advisories = tuple(advisories_by_id[key] for key in sorted(advisories_by_id))
        unchanged = sum(
            previous_hashes.get(advisory.advisory_id) == advisory.raw_sha256
            for advisory in advisories
        )
        changed = len(advisories) - unchanged
        metrics = CollectionMetrics(
            collected=len(advisories),
            changed=changed,
            unchanged=unchanged,
            failed=failed,
            parse_errors=parse_errors,
        )
        return CollectionResult(advisories=advisories, errors=tuple(errors), metrics=metrics)

    def _request(self, url: str, *, accept: str) -> HttpResponse:
        headers = {
            "Accept": accept,
            "User-Agent": "FindUpdates/0.1 MSRC collector",
        }
        for attempt in range(1, self._max_attempts + 1):
            try:
                response = self._transport.get(
                    url,
                    timeout_seconds=self._timeout_seconds,
                    headers=headers,
                )
            except MsrcTransportError:
                if attempt == self._max_attempts:
                    raise
                self._sleeper(float(2 ** (attempt - 1)))
                continue
            if 200 <= response.status < 300:
                return response
            if response.status in _RETRYABLE_STATUS and attempt < self._max_attempts:
                self._sleeper(_retry_delay(response, attempt))
                continue
            raise MsrcHttpError(f"MSRC returned HTTP {response.status} for {url}")
        raise MsrcTransportError("MSRC retry loop exited unexpectedly")


def normalize_cvrf(
    summary: UpdateSummary,
    response: HttpResponse,
    *,
    collected_at: datetime,
) -> tuple[UpdateAdvisory, ...]:
    """Normalize a CVRF JSON or XML document into per-vulnerability advisories."""
    if collected_at.tzinfo is None:
        raise ValueError("collected_at must be timezone-aware")
    content_type = response.content_type.lower()
    stripped = response.body.lstrip()
    raw_hash = sha256(response.body).hexdigest()
    source_url = _source_url(summary.update_id)

    if "json" in content_type or stripped.startswith((b"{", b"[")):
        payload = _load_json(response.body)
        advisories = _normalize_json(
            summary,
            payload,
            raw_hash=raw_hash,
            source_url=source_url,
            collected_at=collected_at,
        )
    elif "xml" in content_type or stripped.startswith(b"<"):
        advisories = _normalize_xml(
            summary,
            response.body,
            raw_hash=raw_hash,
            source_url=source_url,
            collected_at=collected_at,
        )
    else:
        raise MsrcParseError(f"unsupported MSRC content type: {response.content_type!r}")
    if not advisories:
        raise MsrcParseError(f"MSRC document {summary.update_id} contained no vulnerabilities")
    return advisories


def _normalize_json(
    summary: UpdateSummary,
    payload: Any,
    *,
    raw_hash: str,
    source_url: str,
    collected_at: datetime,
) -> tuple[UpdateAdvisory, ...]:
    if not isinstance(payload, dict):
        raise MsrcParseError("CVRF JSON root must be an object")
    document = cast(dict[str, Any], payload)
    products = _json_product_map(document.get("ProductTree"))
    raw_vulnerabilities = document.get("Vulnerability")
    if not isinstance(raw_vulnerabilities, list):
        raise MsrcParseError("CVRF JSON must contain Vulnerability[]")

    advisories: list[UpdateAdvisory] = []
    for index, raw_vulnerability in enumerate(raw_vulnerabilities, start=1):
        if not isinstance(raw_vulnerability, dict):
            raise MsrcParseError("CVRF Vulnerability entry must be an object")
        vulnerability = cast(dict[str, Any], raw_vulnerability)
        cve = _text_value(vulnerability.get("CVE"))
        source_identifier = cve or _text_value(vulnerability.get("ID")) or f"item-{index}"
        title = _text_value(vulnerability.get("Title")) or f"{summary.title}: {source_identifier}"
        notes = _json_notes(vulnerability.get("Notes"))
        product_ids = _json_affected_product_ids(vulnerability.get("ProductStatuses"))
        remediation = _json_remediation(vulnerability.get("Remediations"))
        cve_ids = (cve.upper(),) if cve and _CVE_RE.fullmatch(cve) else ()
        affected_products = tuple(
            AffectedProduct(product_id=product_id, name=products.get(product_id))
            for product_id in product_ids
        )
        references = _unique_sorted((source_url, *remediation.references))
        advisories.append(
            UpdateAdvisory(
                advisory_id=f"MSRC:{summary.update_id}:{source_identifier.upper()}",
                source_advisory_id=summary.update_id,
                vendor="microsoft",
                source="msrc-cvrf-v3",
                title=title,
                description=_note_category(notes, "description") or _first_note(notes),
                published_at=summary.initial_release_date,
                revised_at=summary.current_release_date,
                cve_ids=cve_ids,
                kb_ids=remediation.kb_ids,
                vendor_severity=summary.severity,
                affected_products=affected_products,
                fixed_versions=remediation.fixed_versions,
                reboot_required=remediation.reboot_required,
                known_issues=_note_categories(notes, ("known issue", "known issues")),
                prerequisites=_note_categories(notes, ("prerequisite", "prerequisites")),
                workarounds=_note_categories(notes, ("workaround", "workarounds")),
                references=references,
                raw_sha256=raw_hash,
                collected_at=collected_at,
                parser_version=PARSER_VERSION,
            )
        )
    return tuple(advisories)


def _normalize_xml(
    summary: UpdateSummary,
    body: bytes,
    *,
    raw_hash: str,
    source_url: str,
    collected_at: datetime,
) -> tuple[UpdateAdvisory, ...]:
    upper_prefix = body[:4096].upper()
    if b"<!DOCTYPE" in upper_prefix or b"<!ENTITY" in upper_prefix:
        raise MsrcParseError("CVRF XML with DTD/entity declarations is not accepted")
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        raise MsrcParseError(f"invalid CVRF XML: {exc}") from exc

    products = _xml_product_map(root)
    vulnerabilities = [element for element in root.iter() if _local_name(element.tag) == "Vulnerability"]
    advisories: list[UpdateAdvisory] = []
    for index, vulnerability in enumerate(vulnerabilities, start=1):
        cve = _xml_direct_text(vulnerability, "CVE")
        source_identifier = cve or vulnerability.attrib.get("Ordinal") or f"item-{index}"
        title = _xml_direct_text(vulnerability, "Title") or f"{summary.title}: {source_identifier}"
        notes = _xml_notes(vulnerability)
        product_ids = _xml_affected_product_ids(vulnerability)
        remediation = _xml_remediation(vulnerability)
        cve_ids = (cve.upper(),) if cve and _CVE_RE.fullmatch(cve) else ()
        affected_products = tuple(
            AffectedProduct(product_id=product_id, name=products.get(product_id))
            for product_id in product_ids
        )
        references = _unique_sorted((source_url, *remediation.references))
        advisories.append(
            UpdateAdvisory(
                advisory_id=f"MSRC:{summary.update_id}:{source_identifier.upper()}",
                source_advisory_id=summary.update_id,
                vendor="microsoft",
                source="msrc-cvrf-v3",
                title=title,
                description=_note_category(notes, "description") or _first_note(notes),
                published_at=summary.initial_release_date,
                revised_at=summary.current_release_date,
                cve_ids=cve_ids,
                kb_ids=remediation.kb_ids,
                vendor_severity=summary.severity,
                affected_products=affected_products,
                fixed_versions=remediation.fixed_versions,
                reboot_required=remediation.reboot_required,
                known_issues=_note_categories(notes, ("known issue", "known issues")),
                prerequisites=_note_categories(notes, ("prerequisite", "prerequisites")),
                workarounds=_note_categories(notes, ("workaround", "workarounds")),
                references=references,
                raw_sha256=raw_hash,
                collected_at=collected_at,
                parser_version=PARSER_VERSION,
            )
        )
    return tuple(advisories)


@dataclass(frozen=True, slots=True)
class _RemediationData:
    kb_ids: tuple[str, ...]
    fixed_versions: tuple[str, ...]
    reboot_required: bool | None
    references: tuple[str, ...]


def _parse_update_summary(value: Any) -> UpdateSummary:
    if not isinstance(value, dict):
        raise MsrcParseError("MSRC update summary must be an object")
    item = cast(dict[str, Any], value)
    return UpdateSummary(
        update_id=_required_text(item.get("ID"), "ID"),
        title=_required_text(item.get("DocumentTitle"), "DocumentTitle"),
        severity=_optional_text(item.get("Severity")),
        initial_release_date=_parse_datetime(
            _required_text(item.get("InitialReleaseDate"), "InitialReleaseDate")
        ),
        current_release_date=_parse_datetime(
            _required_text(item.get("CurrentReleaseDate"), "CurrentReleaseDate")
        ),
        cvrf_url=_optional_text(item.get("CvrfUrl")),
    )


def _json_product_map(value: Any) -> dict[str, str]:
    products: dict[str, str] = {}

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            mapping = cast(dict[str, Any], node)
            product_id = _optional_text(mapping.get("ProductID"))
            product_name = _text_value(mapping.get("Value"))
            if product_id and product_name:
                products[product_id] = product_name
            for child in mapping.values():
                visit(child)
        elif isinstance(node, list):
            for child in cast(list[Any], node):
                visit(child)

    visit(value)
    return products


def _json_affected_product_ids(value: Any) -> tuple[str, ...]:
    product_ids: set[str] = set()
    if not isinstance(value, list):
        return ()
    for raw_status in cast(list[Any], value):
        if not isinstance(raw_status, dict):
            continue
        status = cast(dict[str, Any], raw_status)
        status_type = _text_value(status.get("Type")) or ""
        if "not affected" in status_type.casefold():
            continue
        raw_ids = status.get("ProductID")
        if isinstance(raw_ids, list):
            for raw_id in cast(list[Any], raw_ids):
                product_id = _optional_text(raw_id)
                if product_id:
                    product_ids.add(product_id)
        else:
            product_id = _optional_text(raw_ids)
            if product_id:
                product_ids.add(product_id)
    return tuple(sorted(product_ids))


def _json_notes(value: Any) -> tuple[tuple[str, str], ...]:
    notes: list[tuple[str, str]] = []
    if not isinstance(value, list):
        return ()
    for raw_note in cast(list[Any], value):
        if not isinstance(raw_note, dict):
            continue
        note = cast(dict[str, Any], raw_note)
        text = _text_value(note.get("Value"))
        if not text:
            continue
        title = _text_value(note.get("Title")) or _text_value(note.get("Type")) or "note"
        notes.append((title, text))
    return tuple(notes)


def _json_remediation(value: Any) -> _RemediationData:
    kb_ids: set[str] = set()
    fixed_versions: set[str] = set()
    references: set[str] = set()
    restart_values: list[bool] = []
    if not isinstance(value, list):
        return _RemediationData((), (), None, ())
    for raw_item in cast(list[Any], value):
        if not isinstance(raw_item, dict):
            continue
        item = cast(dict[str, Any], raw_item)
        description = _text_value(item.get("Description")) or ""
        kb_ids.update(_extract_kb_ids(description))
        reference = _optional_text(item.get("URL"))
        if reference:
            references.add(reference)
            kb_ids.update(_extract_kb_ids(reference))
        for key in ("FixedBuild", "FixedVersion"):
            fixed_version = _text_value(item.get(key))
            if fixed_version:
                fixed_versions.add(fixed_version)
        restart = _parse_restart(_text_value(item.get("RestartRequired")))
        if restart is not None:
            restart_values.append(restart)
    reboot_required: bool | None
    if any(restart_values):
        reboot_required = True
    elif restart_values:
        reboot_required = False
    else:
        reboot_required = None
    return _RemediationData(
        kb_ids=tuple(sorted(kb_ids)),
        fixed_versions=tuple(sorted(fixed_versions)),
        reboot_required=reboot_required,
        references=tuple(sorted(references)),
    )


def _xml_product_map(root: ET.Element) -> dict[str, str]:
    products: dict[str, str] = {}
    for element in root.iter():
        if _local_name(element.tag) != "FullProductName":
            continue
        product_id = element.attrib.get("ProductID")
        product_name = _clean_text(element.text)
        if product_id and product_name:
            products[product_id] = product_name
    return products


def _xml_affected_product_ids(vulnerability: ET.Element) -> tuple[str, ...]:
    product_ids: set[str] = set()
    for element in vulnerability.iter():
        if _local_name(element.tag) != "Status":
            continue
        if "not affected" in element.attrib.get("Type", "").casefold():
            continue
        for child in element.iter():
            if _local_name(child.tag) == "ProductID":
                product_id = _clean_text(child.text)
                if product_id:
                    product_ids.add(product_id)
    return tuple(sorted(product_ids))


def _xml_notes(vulnerability: ET.Element) -> tuple[tuple[str, str], ...]:
    notes: list[tuple[str, str]] = []
    for element in vulnerability.iter():
        if _local_name(element.tag) != "Note":
            continue
        text = _clean_text("".join(element.itertext()))
        if not text:
            continue
        title = element.attrib.get("Title") or element.attrib.get("Type") or "note"
        notes.append((title, text))
    return tuple(notes)


def _xml_remediation(vulnerability: ET.Element) -> _RemediationData:
    kb_ids: set[str] = set()
    fixed_versions: set[str] = set()
    references: set[str] = set()
    restart_values: list[bool] = []
    for remediation in vulnerability.iter():
        if _local_name(remediation.tag) != "Remediation":
            continue
        description = _xml_direct_text(remediation, "Description") or ""
        kb_ids.update(_extract_kb_ids(description))
        reference = _xml_direct_text(remediation, "URL")
        if reference:
            references.add(reference)
            kb_ids.update(_extract_kb_ids(reference))
        for key in ("FixedBuild", "FixedVersion"):
            fixed_version = _xml_direct_text(remediation, key)
            if fixed_version:
                fixed_versions.add(fixed_version)
        restart = _parse_restart(_xml_direct_text(remediation, "RestartRequired"))
        if restart is not None:
            restart_values.append(restart)
    reboot_required: bool | None
    if any(restart_values):
        reboot_required = True
    elif restart_values:
        reboot_required = False
    else:
        reboot_required = None
    return _RemediationData(
        kb_ids=tuple(sorted(kb_ids)),
        fixed_versions=tuple(sorted(fixed_versions)),
        reboot_required=reboot_required,
        references=tuple(sorted(references)),
    )


def _xml_direct_text(parent: ET.Element, local_name: str) -> str | None:
    for child in parent:
        if _local_name(child.tag) == local_name:
            return _clean_text("".join(child.itertext()))
    return None


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _note_category(notes: tuple[tuple[str, str], ...], category: str) -> str | None:
    target = category.casefold()
    for title, text in notes:
        if target in title.casefold():
            return text
    return None


def _note_categories(
    notes: tuple[tuple[str, str], ...],
    categories: tuple[str, ...],
) -> tuple[str, ...]:
    targets = tuple(category.casefold() for category in categories)
    values = {
        text
        for title, text in notes
        if any(target in title.casefold() for target in targets)
    }
    return tuple(sorted(values))


def _first_note(notes: tuple[tuple[str, str], ...]) -> str | None:
    return notes[0][1] if notes else None


def _text_value(value: Any) -> str | None:
    if isinstance(value, str):
        return _clean_text(value)
    if isinstance(value, dict):
        mapping = cast(dict[str, Any], value)
        return _optional_text(mapping.get("Value"))
    return None


def _required_text(value: Any, field_name: str) -> str:
    text = _optional_text(value)
    if not text:
        raise MsrcParseError(f"MSRC field {field_name} is missing or empty")
    return text


def _optional_text(value: Any) -> str | None:
    return _clean_text(value) if isinstance(value, str) else None


def _clean_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = " ".join(value.split())
    return cleaned or None


def _parse_datetime(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise MsrcParseError(f"invalid MSRC datetime: {value}") from exc
    if parsed.tzinfo is None:
        raise MsrcParseError(f"MSRC datetime is missing timezone: {value}")
    return parsed


def _load_json(body: bytes) -> Any:
    try:
        return json.loads(body.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MsrcParseError(f"invalid MSRC JSON: {exc}") from exc


def _parse_restart(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = value.casefold()
    if normalized in {"yes", "true", "required"}:
        return True
    if normalized in {"no", "false", "not required"}:
        return False
    return None


def _extract_kb_ids(value: str) -> tuple[str, ...]:
    return tuple(sorted({f"KB{match}" for match in _KB_RE.findall(value)}))


def _source_url(update_id: str) -> str:
    encoded_id = quote(update_id, safe="")
    query = urlencode({"api-version": MSRC_API_VERSION})
    return f"{MSRC_BASE_URL}/cvrf/{encoded_id}?{query}"


def _unique_sorted(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted({value for value in values if value.strip()}))


def _retry_delay(response: HttpResponse, attempt: int) -> float:
    retry_after = response.headers.get("retry-after")
    if retry_after is not None:
        try:
            return min(max(float(retry_after), 0.0), 60.0)
        except ValueError:
            pass
    return float(min(2 ** (attempt - 1), 8))


def _read_bounded(response: HTTPResponse) -> bytes:
    body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise MsrcTransportError("MSRC response exceeded size limit")
    return body
