"""Channel adapters. Core routing does not import Teams/Slack/SIEM SDKs."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Protocol

from findupdates.notifications.models import DeliveryAttempt, DeliveryStatus, NotificationEvent
from findupdates.notifications.serialize import event_to_dict
from findupdates.notifications.templates import render_markdown

LOGGER = logging.getLogger("findupdates.notifications")


class ChannelAdapter(Protocol):
    """Deliver one event. Adapters must not log PHI or secrets."""

    name: str

    def send(self, event: NotificationEvent, *, attempts: int) -> DeliveryAttempt: ...


class WebhookTransport(Protocol):
    def post(self, url: str, body: bytes, headers: dict[str, str], timeout: float) -> int: ...


class MemoryChannel:
    """In-memory adapter used by tests and local dry-runs."""

    name = "memory"

    def __init__(self) -> None:
        self.sent: list[NotificationEvent] = []
        self.markdown: list[str] = []

    def send(self, event: NotificationEvent, *, attempts: int) -> DeliveryAttempt:
        del attempts
        self.sent.append(event)
        self.markdown.append(render_markdown(event))
        LOGGER.info("notification delivered channel=memory event_id=%s", event.event_id)
        return DeliveryAttempt("memory", DeliveryStatus.DELIVERED, 1)


class GitHubCommentChannel:
    """Formats a GitHub Issue comment. Transport is injected; no SDK coupling."""

    name = "github"

    def __init__(self, sink: list[str] | None = None) -> None:
        self.sink = sink if sink is not None else []

    def send(self, event: NotificationEvent, *, attempts: int) -> DeliveryAttempt:
        del attempts
        body = render_markdown(event)
        self.sink.append(body)
        LOGGER.info("notification delivered channel=github event_id=%s", event.event_id)
        return DeliveryAttempt("github", DeliveryStatus.DELIVERED, 1)


class WebhookChannel:
    """POST JSON to a webhook. URL is supplied at runtime, never committed."""

    name = "webhook"

    def __init__(
        self,
        url: str,
        *,
        timeout_seconds: float = 30.0,
        transport: WebhookTransport | None = None,
    ) -> None:
        if not url.startswith("https://") and not url.startswith("http://localhost"):
            raise ValueError("webhook URL must be https or localhost")
        self._url = url
        self._timeout = timeout_seconds
        self._transport = transport or UrllibWebhookTransport()

    def send(self, event: NotificationEvent, *, attempts: int) -> DeliveryAttempt:
        body = json.dumps(event_to_dict(event), separators=(",", ":")).encode("utf-8")
        headers = {"Content-Type": "application/json", "User-Agent": "FindUpdates/0.1"}
        last_error = "unspecified webhook failure"
        tries = max(1, attempts)
        for attempt in range(tries):
            try:
                status = self._transport.post(self._url, body, headers, self._timeout)
            except (TimeoutError, urllib.error.URLError, OSError) as exc:
                last_error = type(exc).__name__
                LOGGER.warning(
                    "notification webhook transport error attempt=%s event_id=%s",
                    attempt + 1,
                    event.event_id,
                )
                continue
            if 200 <= status < 300:
                LOGGER.info("notification delivered channel=webhook event_id=%s", event.event_id)
                return DeliveryAttempt("webhook", DeliveryStatus.DELIVERED, attempt + 1)
            last_error = f"HTTP {status}"
            if status not in {429, 500, 502, 503, 504} or attempt == tries - 1:
                break
            LOGGER.warning(
                "notification webhook retryable status=%s attempt=%s event_id=%s",
                status,
                attempt + 1,
                event.event_id,
            )
        LOGGER.error("notification delivery failed channel=webhook event_id=%s", event.event_id)
        return DeliveryAttempt("webhook", DeliveryStatus.FAILED, tries, last_error)


class UrllibWebhookTransport:
    """Standard-library POST transport."""

    def post(self, url: str, body: bytes, headers: dict[str, str], timeout: float) -> int:
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return int(getattr(response, "status", 200))
        except urllib.error.HTTPError as exc:
            return int(exc.code)


class MappingWebhookTransport:
    """Test double that returns scripted status codes per URL."""

    def __init__(self, statuses: dict[str, list[int]]) -> None:
        self._statuses = {key: list(value) for key, value in statuses.items()}
        self.bodies: list[bytes] = []

    def post(self, url: str, body: bytes, headers: dict[str, str], timeout: float) -> int:
        del headers, timeout
        self.bodies.append(body)
        queue = self._statuses.get(url)
        if not queue:
            return 404
        return queue.pop(0)
