"""Pure standard library crontab scheduler, validator, recurrence calculator, and describer."""

from __future__ import annotations

import calendar
import datetime
import re
import zoneinfo
from typing import Any

ALIASES: dict[str, str] = {
    "@yearly": "0 0 1 1 *",
    "@annually": "0 0 1 1 *",
    "@monthly": "0 0 1 * *",
    "@weekly": "0 0 * * 0",
    "@daily": "0 0 * * *",
    "@midnight": "0 0 * * *",
    "@hourly": "0 * * * *",
}

MONTH_NAMES: dict[str, int] = {
    "JAN": 1, "FEB": 2, "MAR": 3, "APR": 4, "MAY": 5, "JUN": 6,
    "JUL": 7, "AUG": 8, "SEP": 9, "OCT": 10, "NOV": 11, "DEC": 12,
}

DOW_NAMES: dict[str, int] = {
    "SUN": 0, "MON": 1, "TUE": 2, "WED": 3, "THU": 4, "FRI": 5, "SAT": 6,
}

DOW_LABELS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
MONTH_LABELS = [
    "", "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"
]

TZ_NAME_RE = re.compile(r"^[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*$")


class CronParseError(ValueError):
    """Raised when a cron expression cannot be parsed or validated."""


def _parse_field(field_str: str, min_val: int, max_val: int, name_map: dict[str, int] | None = None) -> tuple[set[int], bool]:
    """Parse a single crontab field into a set of integers.

    Returns (allowed_integers, is_wildcard).
    """
    field = field_str.strip().upper()
    if not field:
        raise CronParseError("Empty field encountered in cron expression.")

    if field == "*":
        return set(range(min_val, max_val + 1)), True

    if name_map:
        for name, val in name_map.items():
            field = field.replace(name, str(val))

    values: set[int] = set()
    parts = field.split(",")
    for part in parts:
        part = part.strip()
        if not part:
            raise CronParseError(f"Invalid empty item in comma-separated list: {field_str!r}")

        step = 1
        if "/" in part:
            subparts = part.split("/")
            if len(subparts) != 2:
                raise CronParseError(f"Invalid step expression: {part!r}")
            range_part, step_str = subparts[0], subparts[1]
            if not step_str.isdigit() or int(step_str) <= 0:
                raise CronParseError(f"Step must be a positive integer: {step_str!r}")
            step = int(step_str)
        else:
            range_part = part

        if range_part == "*":
            start, end = min_val, max_val
        elif "-" in range_part:
            bounds = range_part.split("-")
            if len(bounds) != 2 or not bounds[0].isdigit() or not bounds[1].isdigit():
                raise CronParseError(f"Invalid range in field: {part!r}")
            start, end = int(bounds[0]), int(bounds[1])
            if start > end:
                raise CronParseError(f"Range start ({start}) cannot exceed end ({end})")
        elif range_part.isdigit():
            # Vixie-cron step semantics: a single value with an
            # explicit step ("N/step") means "N-max/step", e.g. "1/5"
            # in the minute field = 1,6,...,56. Without a step the
            # field stays a single value.
            start = int(range_part)
            end = max_val if step > 1 else start
        else:
            raise CronParseError(f"Invalid token in field: {part!r}")

        if start < min_val or end > max_val:
            raise CronParseError(f"Value out of bounds ({start}..{end}) for allowed range {min_val}..{max_val}")

        for val in range(start, end + 1, step):
            values.add(val)

    if not values:
        raise CronParseError(f"No valid values produced for field: {field_str!r}")

    return values, False


def _parse_expression(expr: str) -> dict[str, Any]:
    """Parse full 5-part cron expression or alias."""
    clean_expr = expr.strip()
    if clean_expr in ALIASES:
        clean_expr = ALIASES[clean_expr]

    tokens = clean_expr.split()
    if len(tokens) != 5:
        raise CronParseError(
            f"Expected 5 fields (minute, hour, day-of-month, month, day-of-week), got {len(tokens)}: {expr!r}"
        )

    minutes, min_wild = _parse_field(tokens[0], 0, 59)
    hours, hour_wild = _parse_field(tokens[1], 0, 23)
    doms, dom_wild = _parse_field(tokens[2], 1, 31)
    months, mon_wild = _parse_field(tokens[3], 1, 12, MONTH_NAMES)
    dows, dow_wild = _parse_field(tokens[4], 0, 7, DOW_NAMES)

    # Standardize Sunday: both 0 and 7 are Sunday
    if 7 in dows:
        dows.add(0)
    if 0 in dows:
        dows.add(7)

    return {
        "raw": expr,
        "normalized": clean_expr,
        "minute": sorted(minutes),
        "hour": sorted(hours),
        "day_of_month": sorted(doms),
        "month": sorted(months),
        "day_of_week": sorted(dows),
        "wildcards": {
            "minute": min_wild,
            "hour": hour_wild,
            "day_of_month": dom_wild,
            "month": mon_wild,
            "day_of_week": dow_wild,
        },
    }


def _matches_day(dt: datetime.datetime, parsed: dict[str, Any]) -> bool:
    """Check day of month and day of week compliance using standard cron rules."""
    dom_wild = parsed["wildcards"]["day_of_month"]
    dow_wild = parsed["wildcards"]["day_of_week"]
    doms = parsed["day_of_month"]
    dows = parsed["day_of_week"]

    # Python weekday(): Mon=0..Sun=6. Cron: Sun=0 or 7, Mon=1..Sat=6.
    cron_dow = (dt.weekday() + 1) % 7

    dom_match = dt.day in doms
    dow_match = cron_dow in dows or (cron_dow == 0 and 7 in dows)

    if dom_wild and dow_wild:
        return True
    if dom_wild and not dow_wild:
        return dow_match
    if not dom_wild and dow_wild:
        return dom_match
    # Standard POSIX: when both are specified, either matching suffices
    return dom_match or dow_match


def _matches_dt(dt: datetime.datetime, parsed: dict[str, Any]) -> bool:
    """Check if given datetime matches all 5 cron fields."""
    if dt.month not in parsed["month"]:
        return False
    if not _matches_day(dt, parsed):
        return False
    if dt.hour not in parsed["hour"]:
        return False
    if dt.minute not in parsed["minute"]:
        return False
    return True


def _describe_schedule(parsed: dict[str, Any]) -> str:
    """Generate human-readable description of the schedule."""
    raw = parsed.get("raw", "")
    wild = parsed["wildcards"]

    if wild["minute"] and wild["hour"] and wild["day_of_month"] and wild["month"] and wild["day_of_week"]:
        return "Every minute"

    parts = []
    # Time description
    if wild["hour"] and not wild["minute"]:
        if len(parsed["minute"]) == 1:
            parts.append(f"At minute {parsed['minute'][0]} of every hour")
        else:
            parts.append(f"At minutes {', '.join(map(str, parsed['minute']))} of every hour")
    elif not wild["hour"] and not wild["minute"]:
        time_strs = [f"{h:02d}:{m:02d}" for h in parsed["hour"] for m in parsed["minute"]]
        if len(time_strs) == 1:
            parts.append(f"At {time_strs[0]}")
        else:
            parts.append(f"At {', '.join(time_strs[:6])}{'...' if len(time_strs) > 6 else ''}")
    elif wild["minute"] and not wild["hour"]:
        parts.append(f"Every minute during hours {', '.join(map(str, parsed['hour']))}")

    # Day of month / week description
    if not wild["day_of_week"] and wild["day_of_month"]:
        dow_names = [DOW_LABELS[d % 7] for d in sorted(set(d % 7 for d in parsed["day_of_week"]))]
        parts.append(f"on {', '.join(dow_names)}")
    elif not wild["day_of_month"] and wild["day_of_week"]:
        parts.append(f"on day {', '.join(map(str, parsed['day_of_month']))} of the month")
    elif not wild["day_of_month"] and not wild["day_of_week"]:
        dow_names = [DOW_LABELS[d % 7] for d in sorted(set(d % 7 for d in parsed["day_of_week"]))]
        parts.append(f"on day {', '.join(map(str, parsed['day_of_month']))} and on {', '.join(dow_names)}")

    # Month description
    if not wild["month"]:
        m_names = [MONTH_LABELS[m] for m in parsed["month"]]
        parts.append(f"in {', '.join(m_names)}")

    return " ".join(parts) if parts else f"Cron schedule: {raw}"


def _get_timezone(tz_name: str | None) -> zoneinfo.ZoneInfo:
    """Resolve and validate IANA timezone."""
    tz_str = (tz_name or "UTC").strip()
    if not TZ_NAME_RE.fullmatch(tz_str) or ".." in tz_str:
        raise ValueError(f"Invalid timezone identifier: {tz_str!r}")
    try:
        return zoneinfo.ZoneInfo(tz_str)
    except zoneinfo.ZoneInfoNotFoundError:
        if tz_str.upper() == "UTC":
            return zoneinfo.ZoneInfo("UTC")
        raise ValueError(f"Timezone not found on system: {tz_str!r}")


def _parse_from_time(from_time_arg: str | None, tz: zoneinfo.ZoneInfo) -> datetime.datetime:
    """Parse ISO8601 or reference time."""
    if not from_time_arg:
        return datetime.datetime.now(tz).replace(microsecond=0)

    raw = from_time_arg.strip()
    try:
        dt = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=tz)
        else:
            dt = dt.astimezone(tz)
        return dt.replace(microsecond=0)
    except ValueError as err:
        raise ValueError(f"Invalid ISO8601 timestamp for 'from_time': {raw!r}") from err


def _calculate_next_runs(parsed: dict[str, Any], start_dt: datetime.datetime, count: int) -> list[str]:
    """Calculate next `count` occurrences with hierarchical skipping and 5-year ceiling."""
    runs: list[str] = []
    # Start strictly after start_dt
    dt = start_dt.replace(second=0, microsecond=0) + datetime.timedelta(minutes=1)
    max_year = start_dt.year + 5
    tz = start_dt.tzinfo

    minutes_set = set(parsed["minute"])
    hours_set = set(parsed["hour"])
    months_set = set(parsed["month"])

    steps = 0
    max_steps = 100_000

    while len(runs) < count and dt.year <= max_year and steps < max_steps:
        steps += 1
        # 1. Month check
        if dt.month not in months_set:
            # Advance to 1st of next month
            if dt.month == 12:
                dt = datetime.datetime(dt.year + 1, 1, 1, 0, 0, tzinfo=tz)
            else:
                dt = datetime.datetime(dt.year, dt.month + 1, 1, 0, 0, tzinfo=tz)
            continue

        # 2. Day check
        if not _matches_day(dt, parsed):
            # Advance to next day at 00:00
            dt = (dt + datetime.timedelta(days=1)).replace(hour=0, minute=0)
            continue

        # 3. Hour check
        if dt.hour not in hours_set:
            # Advance to next hour at minute 0
            dt = (dt + datetime.timedelta(hours=1)).replace(minute=0)
            continue

        # 4. Minute check
        if dt.minute in minutes_set:
            runs.append(dt.isoformat())
            dt += datetime.timedelta(minutes=1)
        else:
            # Find next valid minute in the same hour
            next_mins = [m for m in parsed["minute"] if m > dt.minute]
            if next_mins:
                dt = dt.replace(minute=min(next_mins))
            else:
                dt = (dt + datetime.timedelta(hours=1)).replace(minute=0)

    return runs


def _calculate_prev_runs(parsed: dict[str, Any], start_dt: datetime.datetime, count: int) -> list[str]:
    """Calculate previous `count` occurrences with hierarchical stepping and 5-year floor."""
    runs: list[str] = []
    dt = start_dt.replace(second=0, microsecond=0) - datetime.timedelta(minutes=1)
    min_year = start_dt.year - 5
    tz = start_dt.tzinfo

    minutes_set = set(parsed["minute"])
    hours_set = set(parsed["hour"])
    months_set = set(parsed["month"])

    steps = 0
    max_steps = 100_000

    while len(runs) < count and dt.year >= min_year and steps < max_steps:
        steps += 1
        # 1. Month check
        if dt.month not in months_set:
            # Step back to last minute of previous month
            if dt.month == 1:
                year = dt.year - 1
                month = 12
            else:
                year = dt.year
                month = dt.month - 1
            last_day = calendar.monthrange(year, month)[1]
            dt = datetime.datetime(year, month, last_day, 23, 59, tzinfo=tz)
            continue

        # 2. Day check
        if not _matches_day(dt, parsed):
            # Step back to previous day at 23:59
            prev_day_dt = dt - datetime.timedelta(days=1)
            dt = prev_day_dt.replace(hour=23, minute=59)
            continue

        # 3. Hour check
        if dt.hour not in hours_set:
            # Step back to previous hour at minute 59
            prev_hour_dt = dt - datetime.timedelta(hours=1)
            dt = prev_hour_dt.replace(minute=59)
            continue

        # 4. Minute check
        if dt.minute in minutes_set:
            runs.append(dt.isoformat())
            dt -= datetime.timedelta(minutes=1)
        else:
            prev_mins = [m for m in parsed["minute"] if m < dt.minute]
            if prev_mins:
                dt = dt.replace(minute=max(prev_mins))
            else:
                prev_hour_dt = dt - datetime.timedelta(hours=1)
                dt = prev_hour_dt.replace(minute=59)

    return runs


def cron_scheduler(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Cron scheduling, validation, next/previous runs calculation, and pattern matching."""
    del context
    try:
        args = arguments or {}
        action = str(args.get("action") or "").strip().lower()
        if not action:
            return {"ok": False, "success": False, "data": None, "result": None, "error": "Missing required 'action' parameter."}

        expression = args.get("expression")
        if not expression or not isinstance(expression, str):
            return {"ok": False, "success": False, "data": None, "result": None, "error": "Parameter 'expression' must be a non-empty string."}

        parsed = _parse_expression(expression)
        tz = _get_timezone(args.get("timezone"))
        count = max(1, min(int(args.get("count") if args.get("count") is not None else 5), 100))

        if action == "validate":
            description = _describe_schedule(parsed)
            payload = {
                "valid": True,
                "expression": expression,
                "normalized": parsed["normalized"],
                "description": description,
                "fields": {
                    "minute": parsed["minute"],
                    "hour": parsed["hour"],
                    "day_of_month": parsed["day_of_month"],
                    "month": parsed["month"],
                    "day_of_week": parsed["day_of_week"],
                },
            }
            return {"ok": True, "success": True, "data": payload, "result": payload, "error": None}

        elif action == "describe":
            description = _describe_schedule(parsed)
            payload = {
                "expression": expression,
                "description": description,
                "normalized": parsed["normalized"],
            }
            return {"ok": True, "success": True, "data": payload, "result": payload, "error": None}

        elif action == "next_runs":
            start_dt = _parse_from_time(args.get("from_time"), tz)
            runs = _calculate_next_runs(parsed, start_dt, count)
            if not runs:
                return {
                    "ok": False,
                    "success": False,
                    "data": None,
                    "result": None,
                    "error": "No matching occurrences found within 5-year search horizon (possibly impossible schedule combination).",
                }
            payload = {
                "expression": expression,
                "timezone": str(tz),
                "from_time": start_dt.isoformat(),
                "count": len(runs),
                "runs": runs,
            }
            return {"ok": True, "success": True, "data": payload, "result": payload, "error": None}

        elif action == "prev_runs":
            start_dt = _parse_from_time(args.get("from_time"), tz)
            runs = _calculate_prev_runs(parsed, start_dt, count)
            if not runs:
                return {
                    "ok": False,
                    "success": False,
                    "data": None,
                    "result": None,
                    "error": "No matching occurrences found within 5-year search horizon.",
                }
            payload = {
                "expression": expression,
                "timezone": str(tz),
                "from_time": start_dt.isoformat(),
                "count": len(runs),
                "runs": runs,
            }
            return {"ok": True, "success": True, "data": payload, "result": payload, "error": None}

        elif action == "matches":
            check_dt = _parse_from_time(args.get("from_time"), tz)
            matches = _matches_dt(check_dt, parsed)
            payload = {
                "expression": expression,
                "timestamp": check_dt.isoformat(),
                "timezone": str(tz),
                "matches": matches,
            }
            return {"ok": True, "success": True, "data": payload, "result": payload, "error": None}

        else:
            return {
                "ok": False,
                "success": False,
                "data": None,
                "result": None,
                "error": f"Unsupported action: {action!r}. Supported actions: validate, next_runs, prev_runs, describe, matches.",
            }

    except Exception as err:
        return {
            "ok": False,
            "success": False,
            "data": None,
            "result": None,
            "error": f"{type(err).__name__}: {err}",
        }


TOOL = {
    "name": "cron_scheduler",
    "description": (
        "Pure Python crontab expression parsing, recurrence calculation (next/prev runs), "
        "human-readable schedule description, schedule validation, and timestamp matching."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["validate", "next_runs", "prev_runs", "describe", "matches"],
                "description": "Operation to perform.",
            },
            "expression": {"type": "string", "description": "Standard 5-part crontab expression or alias (@daily, etc.)."},
            "from_time": {"type": "string", "description": "Reference ISO8601 timestamp (defaults to current time)."},
            "count": {
                "type": "integer",
                "minimum": 1,
                "maximum": 100,
                "description": "Number of occurrences to calculate (1-100, default: 5).",
            },
            "timezone": {"type": "string", "description": "Target IANA timezone (default: 'UTC')."},
        },
        "required": ["action", "expression"],
        "additionalProperties": False,
    },
    "handler": cron_scheduler,
    "approval": False,
}
