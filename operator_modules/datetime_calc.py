"""High-precision datetime calculations, timezone conversions, duration diffs, and business day arithmetic for Jarvis."""

from __future__ import annotations

import calendar
import email.utils
import re
from datetime import date, datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

MIN_SAFE_YEAR = 1970
MAX_SAFE_YEAR = 2100
MAX_BUSINESS_DAY_STEPS = 3650  # 10-year loop ceiling

TZ_NAME_RE = re.compile(r"^[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*$")


def _get_timezone(tz_name: str | None) -> ZoneInfo:
    """Validate and resolve IANA timezone identifier safely."""
    if not tz_name:
        return ZoneInfo("UTC")

    tz_str = str(tz_name).strip()
    if not tz_str:
        return ZoneInfo("UTC")

    if not TZ_NAME_RE.fullmatch(tz_str) or ".." in tz_str or "\x00" in tz_str or tz_str.startswith("/"):
        raise ValueError(f"Invalid timezone identifier: {tz_name!r}")

    try:
        return ZoneInfo(tz_str)
    except ZoneInfoNotFoundError as err:
        raise ValueError(f"Unknown timezone identifier: {tz_str!r}") from err


def _parse_timestamp(ts_input: Any, default_tz: ZoneInfo | None = None) -> datetime:
    """Parse ISO8601, RFC2822, or Unix timestamp string into an aware datetime."""
    if default_tz is None:
        default_tz = ZoneInfo("UTC")

    if not isinstance(ts_input, str):
        raise ValueError("Timestamp must be a string")

    raw = ts_input.strip()
    if not raw:
        raise ValueError("Timestamp string cannot be empty")

    # 1. Check numeric Unix timestamp (seconds or milliseconds)
    try:
        val = float(raw)
        # If timestamp is very large (e.g. > 100 billion), assume milliseconds
        if val > 1e11:
            val = val / 1000.0
        dt = datetime.fromtimestamp(val, tz=timezone.utc)
        return dt.astimezone(default_tz)
    except (ValueError, OverflowError, OSError):
        pass

    # 2. Try ISO8601 format
    try:
        # Normalize trailing Z to UTC offset
        iso_str = raw
        if iso_str.endswith("Z") or iso_str.endswith("z"):
            iso_str = iso_str[:-1] + "+00:00"

        dt = datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=default_tz)
        return dt
    except ValueError:
        pass

    # 3. Try RFC2822 format (e.g. "Fri, 20 Nov 2026 19:30:00 +0000")
    try:
        dt = email.utils.parsedate_to_datetime(raw)
        if dt is not None:
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=default_tz)
            return dt
    except Exception:
        pass

    # 4. Try standard date-only YYYY-MM-DD
    try:
        parts = [int(p) for p in raw.split("-")]
        if len(parts) == 3:
            d = date(parts[0], parts[1], parts[2])
            return datetime(d.year, d.month, d.day, 0, 0, 0, tzinfo=default_tz)
    except Exception:
        pass

    raise ValueError(f"Unable to parse timestamp: {ts_input!r} (expected ISO8601, RFC2822, or Unix epoch)")


def _format_datetime_payload(dt: datetime) -> dict[str, Any]:
    """Construct structured datetime inspection record."""
    if dt.year < MIN_SAFE_YEAR or dt.year > MAX_SAFE_YEAR:
        raise ValueError(f"Year {dt.year} is outside safe operating range ({MIN_SAFE_YEAR}-{MAX_SAFE_YEAR})")

    tz_name = getattr(dt.tzinfo, "key", None) or dt.tzname() or "UTC"
    offset = dt.strftime("%z")
    formatted_offset = f"{offset[:3]}:{offset[3:]}" if len(offset) == 5 else offset

    unix_seconds = dt.timestamp()
    unix_ms = int(unix_seconds * 1000)

    weekday_idx = dt.weekday()
    weekday_name = calendar.day_name[weekday_idx]

    return {
        "iso8601": dt.isoformat(),
        "unix_timestamp": unix_seconds,
        "unix_ms": unix_ms,
        "timezone": tz_name,
        "utc_offset": formatted_offset,
        "year": dt.year,
        "month": dt.month,
        "day": dt.day,
        "hour": dt.hour,
        "minute": dt.minute,
        "second": dt.second,
        "day_of_week": weekday_name,
        "day_of_week_int": weekday_idx,
    }


def _calc_diff(dt_a: datetime, dt_b: datetime) -> dict[str, Any]:
    """Calculate duration difference and business days between two datetimes."""
    # Convert both to UTC for consistent diff calculation
    utc_a = dt_a.astimezone(timezone.utc)
    utc_b = dt_b.astimezone(timezone.utc)

    delta = utc_b - utc_a
    total_seconds = delta.total_seconds()
    is_negative = total_seconds < 0

    abs_sec = abs(total_seconds)
    days = int(abs_sec // 86400)
    hours = int((abs_sec % 86400) // 3600)
    minutes = int((abs_sec % 3600) // 60)
    seconds = int(abs_sec % 60)

    # Humanized string
    parts: list[str] = []
    if days > 0:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours > 0:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes > 0:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
    if seconds > 0 or not parts:
        parts.append(f"{seconds} second{'s' if seconds != 1 else ''}")

    humanized = ", ".join(parts)
    if is_negative:
        humanized = f"-({humanized})"

    # Calculate business days between calendar dates
    start_d = min(utc_a.date(), utc_b.date())
    end_d = max(utc_a.date(), utc_b.date())

    b_days = 0
    cur_d = start_d + timedelta(days=1)
    steps = 0
    while cur_d <= end_d:
        steps += 1
        if steps > MAX_BUSINESS_DAY_STEPS:
            break
        if cur_d.weekday() < 5:  # Monday=0 through Friday=4
            b_days += 1
        cur_d += timedelta(days=1)

    if is_negative:
        b_days = -b_days

    return {
        "total_seconds": total_seconds,
        "days": -days if is_negative else days,
        "hours": -hours if is_negative else hours,
        "minutes": -minutes if is_negative else minutes,
        "seconds": -seconds if is_negative else seconds,
        "business_days": b_days,
        "humanized": humanized,
        "start": _format_datetime_payload(dt_a),
        "end": _format_datetime_payload(dt_b),
    }


def _shift_datetime(dt: datetime, arguments: dict[str, Any], direction: int) -> dict[str, Any]:
    """Add or subtract calendar/business offsets from datetime."""
    days = float(arguments.get("days") or 0) * direction
    hours = float(arguments.get("hours") or 0) * direction
    minutes = float(arguments.get("minutes") or 0) * direction
    b_days_raw = arguments.get("business_days")

    current = dt

    # Apply standard timedelta offsets
    if days or hours or minutes:
        current += timedelta(days=days, hours=hours, minutes=minutes)

    # Apply business day offsets
    if b_days_raw is not None:
        try:
            b_days = int(b_days_raw)
        except (ValueError, TypeError):
            raise ValueError("Field 'business_days' must be an integer")

        target_b_days = abs(b_days)
        step_dir = 1 if (b_days * direction) >= 0 else -1
        applied = 0
        steps = 0

        while applied < target_b_days:
            current += timedelta(days=step_dir)
            steps += 1
            if steps > MAX_BUSINESS_DAY_STEPS:
                raise ValueError(f"Business day calculation exceeded step limit ({MAX_BUSINESS_DAY_STEPS} days)")
            if current.weekday() < 5:
                applied += 1

    return _format_datetime_payload(current)


def _datetime_calc_impl(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    action = arguments.get("action")
    if not action:
        return {"ok": False, "success": False, "data": None, "result": None, "error": "Missing required field 'action'"}

    tz = _get_timezone(arguments.get("timezone"))

    if action == "now":
        now_dt = datetime.now(tz=tz)
        data = _format_datetime_payload(now_dt)
        return {"ok": True, "success": True, "data": data, "result": data, "error": None}

    if action == "parse":
        ts_str = arguments.get("timestamp")
        if not ts_str:
            return {"ok": False, "success": False, "data": None, "result": None, "error": "Missing required field 'timestamp'"}
        parsed_dt = _parse_timestamp(ts_str, default_tz=tz)
        data = _format_datetime_payload(parsed_dt)
        return {"ok": True, "success": True, "data": data, "result": data, "error": None}

    if action == "diff":
        ts_a = arguments.get("timestamp")
        ts_b = arguments.get("timestamp_b")
        if not ts_a or not ts_b:
            return {
                "ok": False,
                "success": False,
                "data": None,
                "result": None,
                "error": "Action 'diff' requires both 'timestamp' and 'timestamp_b'",
            }
        dt_a = _parse_timestamp(ts_a, default_tz=tz)
        dt_b = _parse_timestamp(ts_b, default_tz=tz)
        data = _calc_diff(dt_a, dt_b)
        return {"ok": True, "success": True, "data": data, "result": data, "error": None}

    if action == "add":
        ts_str = arguments.get("timestamp")
        base_dt = _parse_timestamp(ts_str, default_tz=tz) if ts_str else datetime.now(tz=tz)
        data = _shift_datetime(base_dt, arguments, direction=1)
        return {"ok": True, "success": True, "data": data, "result": data, "error": None}

    if action == "subtract":
        ts_str = arguments.get("timestamp")
        base_dt = _parse_timestamp(ts_str, default_tz=tz) if ts_str else datetime.now(tz=tz)
        data = _shift_datetime(base_dt, arguments, direction=-1)
        return {"ok": True, "success": True, "data": data, "result": data, "error": None}

    if action == "convert_tz":
        ts_str = arguments.get("timestamp")
        if not ts_str:
            return {"ok": False, "success": False, "data": None, "result": None, "error": "Missing required field 'timestamp'"}
        tz_target_str = arguments.get("timezone")
        if not tz_target_str:
            return {"ok": False, "success": False, "data": None, "result": None, "error": "Missing required field 'timezone'"}
        target_tz = _get_timezone(tz_target_str)
        source_dt = _parse_timestamp(ts_str)
        converted_dt = source_dt.astimezone(target_tz)
        data = _format_datetime_payload(converted_dt)
        return {"ok": True, "success": True, "data": data, "result": data, "error": None}

    return {"ok": False, "success": False, "data": None, "result": None, "error": f"Unsupported action: {action!r}"}


def datetime_calc(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute high-precision datetime math, timezone conversion, duration diffs, and business day calculations."""
    try:
        return _datetime_calc_impl(arguments, context)
    except Exception as err:
        return {
            "ok": False,
            "success": False,
            "data": None,
            "result": None,
            "error": f"Datetime calculation error: {type(err).__name__}: {err}",
        }


TOOL = {
    "name": "datetime_calc",
    "description": (
        "High-precision datetime calculations, timezone conversions (IANA via zoneinfo), "
        "duration diffs, and business day arithmetic. Enforces overflow bounds (1970-2100) "
        "and timezone format validation."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["now", "parse", "diff", "add", "subtract", "convert_tz"],
                "description": "Datetime calculation operation to perform.",
            },
            "timestamp": {
                "type": "string",
                "description": "Primary ISO8601, RFC2822, or Unix timestamp string.",
            },
            "timestamp_b": {
                "type": "string",
                "description": "Secondary timestamp string for action='diff'.",
            },
            "timezone": {
                "type": "string",
                "description": "Target IANA timezone (e.g. 'UTC', 'Europe/Warsaw', 'America/New_York').",
            },
            "days": {
                "type": "number",
                "description": "Days offset for add/subtract.",
            },
            "hours": {
                "type": "number",
                "description": "Hours offset for add/subtract.",
            },
            "minutes": {
                "type": "number",
                "description": "Minutes offset for add/subtract.",
            },
            "business_days": {
                "type": "integer",
                "description": "Business days offset for add/subtract (excludes weekends).",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": datetime_calc,
    "approval": False,
}
