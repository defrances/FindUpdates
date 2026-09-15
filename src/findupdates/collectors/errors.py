"""Collector failure types. Network loss must not be treated as an empty successful run."""

from __future__ import annotations


class SourceUnavailableError(RuntimeError):
    """Raised when a vendor source cannot be reached after retries."""


class ParseError(ValueError):
    """Raised when a single advisory payload cannot be normalized."""


class NotFoundError(LookupError):
    """HTTP 404 or empty lookup. This is not a source outage."""
