"""Dead-letter queue for failed pipeline events. Exhaustion is not silent."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

from findupdates.ids import stable_id
from findupdates.ops.config import dead_letter_max_attempts
from findupdates.ops.errors import DeadLetterExhausted
from findupdates.ops.models import Alert, AlertCode, PipelineEvent, PipelineStage


class DeadLetterQueue:
    """Retry a bounded number of times, then quarantine the event."""

    def __init__(self, config: dict[str, Any]) -> None:
        self._max = dead_letter_max_attempts(config)
        self._events: dict[str, PipelineEvent] = {}
        self._poison: list[PipelineEvent] = []

    def submit(
        self,
        *,
        correlation_id: str,
        stage: PipelineStage,
        payload: dict[str, str],
    ) -> PipelineEvent:
        event = PipelineEvent(
            event_id=stable_id("dlq", correlation_id, stage.value, str(len(self._events) + 1)),
            correlation_id=correlation_id,
            stage=stage,
            payload=payload,
        )
        self._events[event.event_id] = event
        return event

    def retry(
        self,
        event: PipelineEvent,
        handler: Callable[[PipelineEvent], None],
        *,
        now: datetime,
    ) -> PipelineEvent:
        current = self._events.get(event.event_id, event)
        try:
            handler(current)
        except Exception as exc:
            attempts = current.attempts + 1
            failed = PipelineEvent(
                event_id=current.event_id,
                correlation_id=current.correlation_id,
                stage=current.stage,
                payload=current.payload,
                attempts=attempts,
                last_error=str(exc),
                poisoned=attempts >= self._max,
            )
            self._events[failed.event_id] = failed
            if failed.poisoned:
                self._poison.append(failed)
                alert = Alert(
                    code=AlertCode.DEAD_LETTER,
                    correlation_id=failed.correlation_id,
                    summary=f"{failed.stage.value} event quarantined after {attempts} attempts",
                    source=failed.stage.value,
                    advisory_id=failed.payload.get("advisory_id"),
                    recorded_at=now,
                )
                raise DeadLetterExhausted(alert.summary, alert=alert) from exc
            return failed
        succeeded = PipelineEvent(
            event_id=current.event_id,
            correlation_id=current.correlation_id,
            stage=current.stage,
            payload=current.payload,
            attempts=current.attempts + 1,
            last_error=None,
            poisoned=False,
        )
        self._events[succeeded.event_id] = succeeded
        return succeeded

    def poisoned(self) -> tuple[PipelineEvent, ...]:
        return tuple(self._poison)
