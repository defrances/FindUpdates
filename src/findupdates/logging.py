"""Structured-enough standard-library logging with correlation identifiers."""

from __future__ import annotations

import logging
from contextvars import ContextVar

_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="unassigned")


class CorrelationFormatter(logging.Formatter):
    """Render log records with the active execution-context correlation ID."""

    def format(self, record: logging.LogRecord) -> str:
        timestamp = self.formatTime(record)
        message = record.getMessage()
        return (
            f"{timestamp} level={record.levelname} logger={record.name} "
            f"correlation_id={_correlation_id.get()} message={message}"
        )


def configure_logging(level: str = "INFO") -> None:
    """Configure root logging without emitting secrets or domain payloads by default."""
    handler = logging.StreamHandler()
    handler.setFormatter(CorrelationFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())


def set_correlation_id(value: str) -> None:
    """Set the correlation ID for the current execution context."""
    if not value.strip():
        raise ValueError("correlation ID must not be empty")
    _correlation_id.set(value.strip())


def get_correlation_id() -> str:
    """Return the current execution-context correlation ID."""
    return _correlation_id.get()
