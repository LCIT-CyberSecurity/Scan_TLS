"""Next-occurrence computation for schedules (wall-clock in the schedule's time zone, DST-safe)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from croniter import croniter


class ScheduleError(ValueError):
    pass


def _hm(value: str) -> tuple[int, int]:
    try:
        hour, minute = (int(x) for x in value.split(":"))
        if not (0 <= hour < 24 and 0 <= minute < 60):
            raise ValueError
        return hour, minute
    except ValueError as error:
        raise ScheduleError("time must be HH:MM") from error


def validate(kind: str, params: dict[str, Any], tz: str) -> None:
    try:
        ZoneInfo(tz)
    except Exception as error:  # noqa: BLE001
        raise ScheduleError(f"unknown time zone: {tz}") from error
    if kind == "once":
        if not params.get("at"):
            raise ScheduleError("'at' is required")
        datetime.fromisoformat(params["at"])
    elif kind == "daily":
        _hm(params.get("time", ""))
    elif kind == "weekly":
        _hm(params.get("time", ""))
        if params.get("weekday") not in range(7):
            raise ScheduleError("weekday must be 0 (Monday) to 6")
    elif kind == "monthly":
        _hm(params.get("time", ""))
        if params.get("day") not in range(1, 29):
            raise ScheduleError("day must be 1 to 28")
    elif kind == "cron":
        expr = params.get("expr", "")
        if not croniter.is_valid(expr) or len(expr.split()) != 5:
            raise ScheduleError("invalid cron expression (5 fields)")
        first, second = croniter(expr, datetime(2026, 1, 1)).get_next(datetime), None
        second = croniter(expr, first).get_next(datetime)
        if second - first < timedelta(minutes=5):
            raise ScheduleError("cron frequency must be at least every 5 minutes")
    else:
        raise ScheduleError("unknown schedule kind")


def next_after(kind: str, params: dict[str, Any], tz: str, after: datetime) -> datetime | None:
    """First occurrence strictly after `after` (UTC). None when a one-shot is exhausted."""
    zone = ZoneInfo(tz)
    local = after.astimezone(zone)
    if kind == "once":
        at = datetime.fromisoformat(params["at"])
        at = at.replace(tzinfo=zone) if at.tzinfo is None else at
        return at.astimezone(UTC) if at.astimezone(UTC) > after else None
    if kind == "cron":
        return croniter(params["expr"], local).get_next(datetime).astimezone(UTC)
    hour, minute = _hm(params["time"])
    candidate = local.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if kind == "daily":
        while candidate <= local:
            candidate = (candidate.replace(tzinfo=None) + timedelta(days=1)).replace(tzinfo=zone)
        return candidate.astimezone(UTC)
    if kind == "weekly":
        days = (params["weekday"] - local.weekday()) % 7
        candidate = (candidate.replace(tzinfo=None) + timedelta(days=days)).replace(tzinfo=zone)
        if candidate <= local:
            candidate = (candidate.replace(tzinfo=None) + timedelta(days=7)).replace(tzinfo=zone)
        return candidate.astimezone(UTC)
    if kind == "monthly":
        year, month = local.year, local.month
        for _ in range(3):
            candidate = datetime(year, month, params["day"], hour, minute, tzinfo=zone)
            if candidate > local:
                return candidate.astimezone(UTC)
            year, month = (year + 1, 1) if month == 12 else (year, month + 1)
    raise ScheduleError("unknown schedule kind")
