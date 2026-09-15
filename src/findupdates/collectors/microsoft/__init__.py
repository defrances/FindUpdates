"""Microsoft MSRC collector."""

from findupdates.collectors.microsoft.collector import (
    DEFAULT_BASE_URL,
    MSRC_API_VERSION,
    MicrosoftCollector,
    cvrf_url,
    updates_url,
)
from findupdates.collectors.microsoft.cvrf import PARSER_VERSION, parse_cvrf_document

__all__ = [
    "DEFAULT_BASE_URL",
    "MSRC_API_VERSION",
    "PARSER_VERSION",
    "MicrosoftCollector",
    "cvrf_url",
    "parse_cvrf_document",
    "updates_url",
]
