"""Retrying HTTP GET for vendor feeds. No long-lived credentials are sent."""

from __future__ import annotations

import hashlib
import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urljoin

from findupdates.collectors.errors import NotFoundError, SourceUnavailableError

LOGGER = logging.getLogger("findupdates.collectors.http")

RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
MAX_RESPONSE_BYTES = 25 * 1024 * 1024


class ByteTransport(Protocol):
    """Test seam for HTTP GET without opening real sockets."""

    def fetch(self, url: str, headers: dict[str, str], timeout: float) -> HttpTransportResult: ...


@dataclass(frozen=True, slots=True)
class HttpTransportResult:
    status: int
    body: bytes
    retry_after_seconds: float | None = None


@dataclass(frozen=True, slots=True)
class HttpGet:
    url: str
    body: bytes
    sha256: str


class UrllibTransport:
    """Default transport using the standard library."""

    def fetch(self, url: str, headers: dict[str, str], timeout: float) -> HttpTransportResult:
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                status = int(getattr(response, "status", 200))
                retry_after = _retry_after(dict(response.headers.items()))
                return HttpTransportResult(
                    status=status,
                    body=_read_bounded(response),
                    retry_after_seconds=retry_after,
                )
        except urllib.error.HTTPError as exc:
            retry_after = _retry_after(dict(exc.headers.items())) if exc.headers else None
            body = _read_bounded(exc) if exc.fp is not None else b""
            return HttpTransportResult(
                status=int(exc.code),
                body=body,
                retry_after_seconds=retry_after,
            )


class HttpClient:
    """GET JSON/bytes with timeout, Retry-After and bounded retries."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 30.0,
        max_retries: int = 3,
        min_interval_seconds: float = 0.0,
        transport: ByteTransport | None = None,
        extra_headers: dict[str, str] | None = None,
        accept: str = "application/json",
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_retries < 0:
            raise ValueError("max_retries must be >= 0")
        self._timeout = timeout_seconds
        self._max_retries = max_retries
        self._min_interval = min_interval_seconds
        self._transport = transport or UrllibTransport()
        headers = {"Accept": accept, "User-Agent": "FindUpdates/0.1"}
        if extra_headers:
            headers.update({key: value for key, value in extra_headers.items() if value})
        self._headers = headers
        self._last_request_at = 0.0

    def get_bytes(self, url: str) -> HttpGet:
        """Return response bytes or raise SourceUnavailableError after retries."""
        last_error = "unspecified HTTP failure"
        attempts = self._max_retries + 1
        for attempt in range(attempts):
            self._respect_min_interval()
            try:
                result = self._transport.fetch(url, self._headers, self._timeout)
            except (TimeoutError, urllib.error.URLError, OSError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                LOGGER.warning("vendor HTTP transport error url_host_only attempt=%s", attempt + 1)
                self._backoff(attempt, None)
                continue

            if result.status == 200:
                return HttpGet(url=url, body=result.body, sha256=_sha256(result.body))
            if result.status == 404:
                raise NotFoundError(url)
            last_error = f"HTTP {result.status}"
            if result.status in RETRYABLE_STATUS and attempt < attempts - 1:
                LOGGER.warning(
                    "retryable vendor HTTP status=%s attempt=%s", result.status, attempt + 1
                )
                self._backoff(attempt, result.retry_after_seconds)
                continue
            break
        raise SourceUnavailableError(f"source unavailable for {url}: {last_error}")

    def get_json(self, url: str) -> object:
        """GET and parse JSON. Invalid JSON is a source failure, not an empty catalog."""
        payload = self.get_bytes(url)
        try:
            return json.loads(payload.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SourceUnavailableError(f"source returned invalid JSON for {url}") from exc

    def _respect_min_interval(self) -> None:
        if self._min_interval <= 0:
            self._last_request_at = time.monotonic()
            return
        elapsed = time.monotonic() - self._last_request_at
        remaining = self._min_interval - elapsed
        if remaining > 0 and self._last_request_at > 0:
            time.sleep(remaining)
        self._last_request_at = time.monotonic()

    def _backoff(self, attempt: int, retry_after: float | None) -> None:
        delay = _backoff_seconds(attempt, retry_after)
        if delay > 0:
            time.sleep(delay)


class MappingTransport:
    """In-memory transport for tests and captured fixtures."""

    def __init__(self, responses: dict[str, HttpTransportResult | bytes]) -> None:
        self._responses = responses

    def fetch(self, url: str, headers: dict[str, str], timeout: float) -> HttpTransportResult:
        del headers, timeout
        payload = self._responses.get(url)
        if payload is None:
            for key, value in self._responses.items():
                if key and (key in url or url.startswith(key)):
                    payload = value
                    break
        if payload is None:
            return HttpTransportResult(status=404, body=b"")
        if isinstance(payload, HttpTransportResult):
            return payload
        return HttpTransportResult(status=200, body=payload)


def join_url(base: str, path: str) -> str:
    """Join a base API URL with a relative path."""
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return urljoin(base if base.endswith("/") else base + "/", path.lstrip("/"))


def _sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _read_bounded(stream: object) -> bytes:
    reader = getattr(stream, "read", None)
    if reader is None:
        return b""
    raw = reader(MAX_RESPONSE_BYTES + 1)
    if not isinstance(raw, bytes):
        raise SourceUnavailableError("HTTP response body was not bytes")
    if len(raw) > MAX_RESPONSE_BYTES:
        raise SourceUnavailableError("HTTP response exceeded 25 MiB limit")
    return raw


def _retry_after(headers: dict[str, str]) -> float | None:
    raw = headers.get("Retry-After") or headers.get("retry-after")
    if raw is None:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        return None


def _backoff_seconds(attempt: int, retry_after: float | None) -> float:
    if retry_after is not None:
        return retry_after
    return float(min(8.0, 0.2 * (2**attempt)))
