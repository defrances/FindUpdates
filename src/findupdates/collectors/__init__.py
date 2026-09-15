"""Vendor and intelligence-source collectors."""

from findupdates.collectors.checkpoint import CollectionCheckpoint
from findupdates.collectors.errors import NotFoundError, ParseError, SourceUnavailableError
from findupdates.collectors.http import HttpClient, MappingTransport
from findupdates.collectors.metrics import CollectionMetrics
from findupdates.collectors.microsoft import MicrosoftCollector
from findupdates.collectors.result import CollectionResult

__all__ = [
    "CollectionCheckpoint",
    "CollectionMetrics",
    "CollectionResult",
    "HttpClient",
    "MappingTransport",
    "MicrosoftCollector",
    "NotFoundError",
    "ParseError",
    "SourceUnavailableError",
]
