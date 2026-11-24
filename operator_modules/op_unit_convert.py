"""Unit conversion operator module for Jarvis.

Standard library only. Design adapted from the well-established base-unit
pattern used by MIT/BSD-licensed unit libraries (pint/unyt): every unit maps
to its category's base unit through a multiplicative factor, and temperature
scales use the affine transform they genuinely require (an offset plus a
factor) instead of the plain multiplication that silently produces wrong
results for °C/°F.

Envelope contract (PROJECT.md): every action returns the standardized
five-key envelope.
"""
from __future__ import annotations

import difflib
import re
from typing import Any

# A unit definition: symbol -> (category, factor_to_base, label, extra aliases)
# factor is multiplicative: value_base = value * factor  (temperature adds an offset)
UNITS: dict[str, tuple[str, float, str]] = {}


def _register(category: str, base_symbol: str, label: str, table: dict[str, tuple[float, str]]) -> None:
    for symbol, (factor, unit_label) in table.items():
        UNITS[symbol] = (category, factor, unit_label)
    UNITS.setdefault(base_symbol, (category, 1.0, label))


_register("length", "m", "meter", {
    "m": (1.0, "meter"),
    "km": (1000.0, "kilometer"),
    "cm": (0.01, "centimeter"),
    "mm": (0.001, "millimeter"),
    "um": (1e-6, "micrometer"),
    "mi": (1609.344, "mile"),
    "yd": (0.9144, "yard"),
    "ft": (0.3048, "foot"),
    "in": (0.0254, "inch"),
    "nmi": (1852.0, "nautical mile"),
    "ly": (9.4607304725808e15, "light year"),
})
_register("mass", "kg", "kilogram", {
    "kg": (1.0, "kilogram"),
    "g": (0.001, "gram"),
    "mg": (1e-6, "milligram"),
    "t": (1000.0, "metric ton"),
    "lb": (0.45359237, "pound"),
    "oz": (0.028349523125, "ounce"),
    "st": (6.35029318, "stone"),
})
_register("volume", "l", "liter", {
    "l": (1.0, "liter"),
    "ml": (0.001, "milliliter"),
    "m3": (1000.0, "cubic meter"),
    "ft3": (28.316846592, "cubic foot"),
    "gal_us": (3.785411784, "US gallon"),
    "gal_uk": (4.54609, "imperial gallon"),
    "qt": (0.946352946, "US quart"),
    "cup": (0.2365882365, "US cup"),
    "floz_us": (0.0295735295625, "US fluid ounce"),
})
_register("speed", "m/s", "meter per second", {
    "m/s": (1.0, "meter per second"),
    "km/h": (1.0 / 3.6, "kilometer per hour"),
    "mph": (0.44704, "mile per hour"),
    "kn": (0.514444444, "knot"),
    "ft/s": (0.3048, "foot per second"),
})
_register("time", "s", "second", {
    "s": (1.0, "second"),
    "ms": (0.001, "millisecond"),
    "min": (60.0, "minute"),
    "h": (3600.0, "hour"),
    "d": (86400.0, "day"),
    "wk": (604800.0, "week"),
})
_register("area", "m2", "square meter", {
    "m2": (1.0, "square meter"),
    "km2": (1e6, "square kilometer"),
    "ha": (10000.0, "hectare"),
    "ft2": (0.09290304, "square foot"),
    "mi2": (2589988.110336, "square mile"),
    "ac": (4046.8564224, "acre"),
})
_register("energy", "J", "joule", {
    "J": (1.0, "joule"),
    "kJ": (1000.0, "kilojoule"),
    "MJ": (1e6, "megajoule"),
    "cal": (4.184, "calorie (thermochemical)"),
    "kcal": (4184.0, "kilocalorie"),
    "Wh": (3600.0, "watt hour"),
    "kWh": (3.6e6, "kilowatt hour"),
    "BTU": (1055.05585262, "British thermal unit"),
    "eV": (1.602176634e-19, "electron volt"),
})
_register("power", "W", "watt", {
    "W": (1.0, "watt"),
    "kW": (1000.0, "kilowatt"),
    "MW": (1e6, "megawatt"),
    "hp": (745.6998715822702, "horsepower (mechanical)"),
})
_register("pressure", "Pa", "pascal", {
    "Pa": (1.0, "pascal"),
    "hPa": (100.0, "hectopascal"),
    "kPa": (1000.0, "kilopascal"),
    "bar": (100000.0, "bar"),
    "atm": (101325.0, "standard atmosphere"),
    "psi": (6894.757293168, "pound per square inch"),
    "mmHg": (133.322387415, "millimeter of mercury"),
})
_register("data", "B", "byte", {
    "B": (1.0, "byte"),
    "kB": (1000.0, "kilobyte (SI)"),
    "MB": (1e6, "megabyte (SI)"),
    "GB": (1e9, "gigabyte (SI)"),
    "TB": (1e12, "terabyte (SI)"),
    "KiB": (1024.0, "kibibyte"),
    "MiB": (1048576.0, "mebibyte"),
    "GiB": (1073741824.0, "gibibyte"),
    "TiB": (1099511627776.0, "tebibyte"),
})

# Temperature is affine, not multiplicative: base kelvin = value * factor + offset.
# The pint/unyt documentation ("non-multiplicative units") is the reference
# pattern; plain multiplication is wrong for °C/°F.
TEMP_OFFSETS: dict[str, float] = {}
TEMPERATURE: dict[str, tuple[float, float, str]] = {
    # symbol -> (factor from value to kelvin, kelvin offset, label)
    "K": (1.0, 0.0, "kelvin"),
    "degC": (1.0, 273.15, "degree Celsius"),
    "degF": (5.0 / 9.0, 459.67 * 5.0 / 9.0, "degree Fahrenheit"),
    "degR": (5.0 / 9.0, 0.0, "degree Rankine"),
}


def _err(message: str) -> dict[str, Any]:
    return {"ok": False, "success": False, "data": None, "result": None, "error": message}


def _ok(payload: dict[str, Any]) -> dict[str, Any]:
    data = dict(payload)
    return {"ok": True, "success": True, "data": data, "result": data, "error": None}


def _suggest(unit: str) -> str:
    known = [*UNITS, *TEMPERATURE]
    matches = difflib.get_close_matches(unit, known, n=3, cutoff=0.5)
    if matches:
        return f" Did you mean: {', '.join(matches)}?"
    return ""


def _parse_number(raw: Any) -> float:
    if isinstance(raw, bool) or raw is None:
        raise ValueError("A numeric value is required.")
    if isinstance(raw, (int, float)):
        return float(raw)
    text = str(raw).strip().replace(",", ".")
    if not re.fullmatch(r"[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?", text):
        raise ValueError(f"'{raw}' is not a number.")
    return float(text)


def _category_of(unit: str) -> str:
    if unit in TEMPERATURE:
        return "temperature"
    return UNITS[unit][0]


def handle_tool_call(args: dict[str, Any], context: dict | None = None) -> dict[str, Any]:
    args = args or {}
    action = str(args.get("action") or "").strip()
    if not action:
        return _err("UnitError: 'action' is required (convert or list_units).")

    if action == "list_units":
        categories: dict[str, list[dict[str, str]]] = {}
        for symbol, (category, _factor, label) in UNITS.items():
            categories.setdefault(category, []).append({"unit": symbol, "description": label})
        categories["temperature"] = [
            {"unit": symbol, "description": label} for symbol, (_f, _o, label) in TEMPERATURE.items()
        ]
        return _ok({"categories": categories, "count": sum(len(v) for v in categories.values())})

    if action != "convert":
        return _err(f"UnitError: Unsupported action '{action}'. Use convert or list_units.")

    try:
        value = _parse_number(args.get("value"))
    except ValueError as error:
        return _err(f"UnitError: {error}")

    source_raw = str(args.get("from") or "").strip()
    target_raw = str(args.get("to") or "").strip()
    source = source_raw or ""
    target = target_raw or ""
    # Friendly temperature spellings: C/F/'c' map onto degC/degF.
    if source.lstrip("°") == "C":
        source = "degC"
    if source.lstrip("°") == "F":
        source = "degF"
    if source.lstrip("°") == "K":
        source = "K"
    if target.lstrip("°") == "C":
        target = "degC"
    if target.lstrip("°") == "F":
        target = "degF"
    if target.lstrip("°") == "K":
        target = "K"

    known_source = source in UNITS or source in TEMPERATURE
    known_target = target in UNITS or target in TEMPERATURE
    if not known_source and not known_target:
        return _err(f"UnitError: Unknown units '{source_raw}' and '{target_raw}'."
                    f"{_suggest(source_raw)}{_suggest(target_raw)}")
    if not known_source:
        return _err(f"UnitError: Unknown unit '{source_raw}'.{_suggest(source_raw)}")
    if not known_target:
        return _err(f"UnitError: Unknown unit '{target_raw}'.{_suggest(target_raw)}")

    source_category = _category_of(source)
    target_category = _category_of(target)
    if source_category != target_category:
        return _err(
            f"UnitError: Cannot convert {source_category} to {target_category} ('{source_raw}' to '{target_raw}').")

    precision_raw = args.get("precision")
    precision = 6
    if precision_raw is not None:
        try:
            precision = int(precision_raw)
        except (TypeError, ValueError):
            return _err("UnitError: 'precision' must be an integer between 0 and 12.")
        if not 0 <= precision <= 12:
            return _err("UnitError: 'precision' must be between 0 and 12.")

    if source_category == "temperature":
        factor_s, offset_s, label_s = TEMPERATURE[source]
        factor_t, offset_t, label_t = TEMPERATURE[target]
        kelvin = value * factor_s + offset_s
        result_value = (kelvin - offset_t) / factor_t
    else:
        _category, factor_s, label_s = UNITS[source]
        _category, factor_t, label_t = UNITS[target]
        result_value = value * factor_s / factor_t

    rounded = round(result_value, precision)
    if rounded == int(rounded) and abs(rounded) < 1e15:
        rounded = int(rounded)
    return _ok({
        "value": rounded,
        "from": {"unit": source, "description": label_s, "input": value},
        "to": {"unit": target, "description": label_t},
        "category": source_category,
        "precision": precision,
        "expression": f"{value} {source_raw or source} = {rounded} {target_raw or target}",
    })


TOOL = {
    "name": "unit_convert",
    "description": (
        "Convert values between units of the same category: length, mass, "
        "volume, speed, time, area, energy, power, pressure, data (SI and "
        "binary), and temperature (affine C/F/K transforms). Supports a "
        "precision argument and suggests close matches for misspelt units. "
        "Use 'list_units' to enumerate every supported symbol."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["convert", "list_units"],
                       "description": "Either 'convert' or 'list_units'. Values: 'convert', 'list_units'."},
            "value": {"type": ["number", "string"],
                      "description": "Value to convert (comma decimal separator accepted)."},
            "from": {"type": "string", "description": "Source unit symbol (e.g. km, lb, degC, m/s, MiB)."},
            "to": {"type": "string", "description": "Target unit symbol (e.g. mi, kg, degF, mph, MB)."},
            "precision": {"type": "integer", "minimum": 0, "maximum": 12,
                          "description": "Decimal places in the result (default: 6)."},
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": handle_tool_call,
    "approval": False,
}
