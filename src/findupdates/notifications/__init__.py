"""Severity-aware notification adapters."""

from findupdates.notifications.channels import (
    GitHubCommentChannel,
    MappingWebhookTransport,
    MemoryChannel,
    WebhookChannel,
)
from findupdates.notifications.models import (
    SCHEMA_VERSION,
    AssessmentState,
    DeliveryAttempt,
    DeliveryStatus,
    NotificationEvent,
    NotificationKind,
    NotifyResult,
    RoutingPolicy,
)
from findupdates.notifications.policy import DEFAULT_POLICY_PATH, load_routing_policy
from findupdates.notifications.serialize import canonical_event_json, event_to_dict
from findupdates.notifications.service import MemoryNotificationLog, NotificationService
from findupdates.notifications.templates import render_markdown

__all__ = [
    "DEFAULT_POLICY_PATH",
    "SCHEMA_VERSION",
    "AssessmentState",
    "DeliveryAttempt",
    "DeliveryStatus",
    "GitHubCommentChannel",
    "MappingWebhookTransport",
    "MemoryChannel",
    "MemoryNotificationLog",
    "NotificationEvent",
    "NotificationKind",
    "NotificationService",
    "NotifyResult",
    "RoutingPolicy",
    "WebhookChannel",
    "canonical_event_json",
    "event_to_dict",
    "load_routing_policy",
    "render_markdown",
]
