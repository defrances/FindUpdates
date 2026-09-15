"""GitHub Issues adapter. Tokens are request credentials, never record fields."""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol

from findupdates.changerecords.errors import ChangeStoreError
from findupdates.changerecords.models import ChangeRecord
from findupdates.changerecords.serialize import parse_issue_body
from findupdates.changerecords.store import (
    UpsertResult,
    render_github_issue,
    with_github_issue,
)

LOGGER = logging.getLogger("findupdates.changerecords")
API_HOST = "https://api.github.com"
_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
MAX_RESPONSE_BYTES = 1 * 1024 * 1024


class IssuesTransport(Protocol):
    """Test seam for GitHub Issues HTTP without opening real sockets."""

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout: float,
    ) -> IssuesHttpResult: ...


@dataclass(frozen=True, slots=True)
class IssuesHttpResult:
    status: int
    body: bytes


@dataclass
class MappingIssuesTransport:
    """Scripted GitHub Issues responses for tests."""

    scripts: dict[str, list[tuple[int, bytes]]] = field(default_factory=dict)
    calls: list[tuple[str, str, bytes | None]] = field(default_factory=list)
    authorized: list[bool] = field(default_factory=list)

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout: float,
    ) -> IssuesHttpResult:
        del timeout
        self.calls.append((method, url, body))
        self.authorized.append(bool(headers.get("Authorization")))
        if body and b"Bearer " in body:
            raise ChangeStoreError("GitHub token leaked into the Issues JSON body")
        key = _call_key(method, url)
        queue = self.scripts.get(key)
        if not queue:
            return IssuesHttpResult(404, b'{"message":"Not Found"}')
        status, payload = queue.pop(0)
        return IssuesHttpResult(status, payload)


class UrllibIssuesTransport:
    """Standard-library GitHub Issues transport."""

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout: float,
    ) -> IssuesHttpResult:
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                status = int(getattr(response, "status", 200))
                return IssuesHttpResult(status, _read_bounded(response))
        except urllib.error.HTTPError as exc:
            raw = _read_bounded(exc) if exc.fp is not None else b""
            return IssuesHttpResult(int(exc.code), raw)


class GitHubChangeStore:
    """Create or update one GitHub Issue per change-record idempotency key."""

    def __init__(
        self,
        *,
        repository: str,
        token: str,
        transport: IssuesTransport | None = None,
        timeout_seconds: float = 30.0,
        max_retries: int = 3,
    ) -> None:
        if not _REPO.match(repository.strip()):
            raise ChangeStoreError("FINDUPDATES_GITHUB_REPOSITORY must be owner/repo")
        if not token.strip():
            raise ChangeStoreError("GitHub token is required for a live change-record upsert")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._repository = repository.strip()
        self._token = token.strip()
        self._transport = transport or UrllibIssuesTransport()
        self._timeout = timeout_seconds
        self._max_retries = max_retries

    def upsert(self, record: ChangeRecord) -> UpsertResult:
        """Create the Issue on first scan; PATCH the same Issue on later scans."""
        matches = self._search(record.idempotency_key)
        if len(matches) > 1:
            numbers = ", ".join(str(item[0]) for item in matches)
            raise ChangeStoreError(
                f"multiple GitHub Issues share idempotency key {record.idempotency_key}: {numbers}"
            )
        payload = _issue_payload(record)
        if not matches:
            created = self._request("POST", self._collection_url(), payload)
            number = _issue_number(created)
            stamped = with_github_issue(record, number)
            self._request("PATCH", self._item_url(number), _issue_payload(stamped))
            LOGGER.info("change record issue created number=%s", number)
            return UpsertResult(stamped, True, number)
        number = matches[0][0]
        stamped = with_github_issue(record, number)
        self._request("PATCH", self._item_url(number), _issue_payload(stamped))
        LOGGER.info("change record issue updated number=%s", number)
        return UpsertResult(stamped, False, number)

    def get(self, idempotency_key: str) -> ChangeRecord | None:
        matches = self._search(idempotency_key)
        if len(matches) > 1:
            raise ChangeStoreError(
                f"multiple GitHub Issues share idempotency key {idempotency_key}"
            )
        if not matches:
            return None
        number, body = matches[0]
        try:
            parsed = parse_issue_body(body)
        except (ValueError, json.JSONDecodeError) as exc:
            raise ChangeStoreError(f"GitHub Issue #{number} body is not a change record") from exc
        return with_github_issue(parsed, number)

    def _search(self, idempotency_key: str) -> list[tuple[int, str]]:
        query = urllib.parse.urlencode(
            {"labels": idempotency_key, "state": "all", "per_page": "10"}
        )
        payload = self._request("GET", f"{self._collection_url()}?{query}", None)
        if not isinstance(payload, list):
            raise ChangeStoreError("GitHub Issues search must return an array")
        found: list[tuple[int, str]] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            number = item.get("number")
            body = item.get("body")
            if not isinstance(number, int) or isinstance(number, bool) or number < 1:
                raise ChangeStoreError("GitHub Issue is missing a valid number")
            if not isinstance(body, str):
                raise ChangeStoreError(f"GitHub Issue #{number} is missing a body")
            found.append((number, body))
        return found

    def _request(self, method: str, url: str, payload: dict[str, object] | None) -> object:
        if not url.startswith(API_HOST + "/"):
            raise ChangeStoreError("refusing GitHub request that leaves api.github.com")
        body = None if payload is None else json.dumps(payload, ensure_ascii=True).encode("utf-8")
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "User-Agent": "FindUpdates/0.1",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        last_error = "unspecified GitHub failure"
        attempts = self._max_retries + 1
        for attempt in range(attempts):
            result = self._transport.request(method, url, headers, body, self._timeout)
            if result.status in {200, 201}:
                return _parse_json(result.body)
            last_error = f"HTTP {result.status}"
            if result.status in {401, 403}:
                raise ChangeStoreError("GitHub authentication failed")
            if result.status in RETRYABLE_STATUS and attempt < attempts - 1:
                LOGGER.warning(
                    "retryable GitHub Issues status=%s attempt=%s", result.status, attempt + 1
                )
                continue
            break
        raise ChangeStoreError(f"GitHub Issues {method} failed: {last_error}")

    def _collection_url(self) -> str:
        owner, name = self._repository.split("/", 1)
        return f"{API_HOST}/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(name)}/issues"

    def _item_url(self, number: int) -> str:
        return f"{self._collection_url()}/{number}"


def github_token(environ: Mapping[str, str] | None = None) -> str | None:
    """Read a GitHub token from the environment. Never log the return value."""
    env = os.environ if environ is None else environ
    for key in ("FINDUPDATES_GITHUB_TOKEN", "GH_TOKEN"):
        raw = env.get(key)
        if raw is not None and raw.strip():
            return raw.strip()
    return None


def store_from_env(
    *,
    repository: str | None,
    environ: Mapping[str, str] | None = None,
    transport: IssuesTransport | None = None,
    timeout_seconds: float = 30.0,
    max_retries: int = 3,
) -> GitHubChangeStore:
    """Build a live store. Missing repository or token fails closed."""
    token = github_token(environ)
    if repository is None or not repository.strip():
        raise ChangeStoreError("FINDUPDATES_GITHUB_REPOSITORY is not configured")
    if token is None:
        raise ChangeStoreError("FINDUPDATES_GITHUB_TOKEN or GH_TOKEN is required")
    return GitHubChangeStore(
        repository=repository,
        token=token,
        transport=transport,
        timeout_seconds=timeout_seconds,
        max_retries=max_retries,
    )


def _issue_payload(record: ChangeRecord) -> dict[str, object]:
    rendered = render_github_issue(record)
    return {
        "title": rendered["title"],
        "body": rendered["body"],
        "labels": rendered["labels"],
    }


def _issue_number(payload: object) -> int:
    if not isinstance(payload, dict):
        raise ChangeStoreError("GitHub Issue response must be an object")
    number = payload.get("number")
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise ChangeStoreError("GitHub Issue response is missing a valid number")
    return number


def _parse_json(body: bytes) -> object:
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ChangeStoreError("GitHub Issues returned invalid JSON") from exc


def _call_key(method: str, url: str) -> str:
    return f"{method} {url.split('?', 1)[0]}"


def _read_bounded(stream: object) -> bytes:
    reader = getattr(stream, "read", None)
    if reader is None:
        return b""
    raw = reader(MAX_RESPONSE_BYTES + 1)
    if not isinstance(raw, bytes):
        raise ChangeStoreError("GitHub response body was not bytes")
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ChangeStoreError("GitHub response exceeded 1 MiB limit")
    return raw
