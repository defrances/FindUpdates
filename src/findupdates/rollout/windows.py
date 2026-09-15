"""Timezone-aware maintenance windows. Missing zone data fails closed."""

from __future__ import annotations

from datetime import datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from findupdates.rollout.errors import RolloutDenied
from findupdates.rollout.models import MaintenanceWindow, RolloutDevice

_WEEKDAY = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}


def in_maintenance_window(now: datetime, window: MaintenanceWindow) -> bool:
    """Return whether `now` falls in a configured local window."""
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    try:
        zone = ZoneInfo(window.timezone)
    except ZoneInfoNotFoundError as exc:
        raise RolloutDenied(f"unknown maintenance timezone {window.timezone}") from exc
    local = now.astimezone(zone)
    allowed = {_WEEKDAY[day] for day in window.days_of_week}
    hour, minute = (int(part) for part in window.start_local.split(":"))
    duration = timedelta(minutes=window.duration_minutes)
    for offset in (0, -1):
        day = local + timedelta(days=offset)
        start = day.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if start.weekday() in allowed and start <= local < start + duration:
            return True
    return False


def assert_maintenance(
    devices: tuple[RolloutDevice, ...],
    *,
    now: datetime,
    emergency: bool,
) -> None:
    """Refuse execution outside every member's window unless emergency is authorized."""
    if emergency:
        return
    closed = [
        item.device_id for item in devices if not in_maintenance_window(now, item.maintenance)
    ]
    if closed:
        raise RolloutDenied(f"maintenance window closed for {', '.join(closed)}")
