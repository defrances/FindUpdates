"""Structured-enough standard-library logging with correlation identifiers."""

from __future__ import annotations

import logging
from contextvars import ContextVar

from findupdates.agents.redaction import redact_text

_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="unassigned")
_advisory_id: ContextVar[str] = ContextVar("advisory_id", default="none")
_pipeline_stage: ContextVar[str] = ContextVar("pipeline_stage", default="none")


class CorrelationFormatter(logging.Formatter):
    """Render log records with the active execution-context correlation ID."""

    def format(self, record: logging.LogRecord) -> str:
        timestamp = self.formatTime(record)
        message, _changed = redact_text(record.getMessage())
        return (
            f"{timestamp} level={record.levelname} logger={record.name} "
            f"correlation_id={_correlation_id.get()} advisory_id={_advisory_id.get()} "
            f"stage={_pipeline_stage.get()} message={message}"
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


def set_log_context(*, advisory_id: str | None = None, stage: str | None = None) -> None:
    """Bind advisory and pipeline stage onto subsequent log lines."""
    if advisory_id is not None:
        _advisory_id.set(advisory_id.strip() or "none")
    if stage is not None:
        _pipeline_stage.set(stage.strip() or "none")


def get_log_context() -> tuple[str, str, str]:
    """Return correlation, advisory and stage for metrics/log joins."""
    return _correlation_id.get(), _advisory_id.get(), _pipeline_stage.get()
