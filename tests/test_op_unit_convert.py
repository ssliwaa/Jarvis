"""Unit-conversion operator: physics-pinned factors and the affine temperature rule.

The factor table and the affine temperature transform follow the base-unit
pattern (the MIT/BSD pint/unyt design); the classic home-made converter bug
is multiplying °C/°F like lengths, which these tests pin against known pairs.
"""
import unittest

import tool_registry
from operator_modules import op_unit_convert as uc


def convert(value, source, target, **extra):
    return uc.handle_tool_call({"action": "convert", "value": value,
                                "from": source, "to": target, **extra})


class ContractTests(unittest.TestCase):
    def test_tool_declaration_and_registry_discovery(self):
        schema = uc.TOOL["input_schema"]
        self.assertEqual(schema["additionalProperties"], False)
        self.assertIn("convert", schema["properties"]["action"]["enum"])
        registry = tool_registry.ToolRegistry()
        self.assertTrue(registry.has("unit_convert"))
        out = registry.run("unit_convert", {"action": "convert", "value": 1, "from": "km", "to": "m"})
        # registry.run completes the envelope (iteration E).
        self.assertEqual(set(out) >= {"ok", "success", "data", "result", "error"}, True)

    def test_error_and_success_paths_use_the_five_key_envelope(self):
        for res in (convert(10, "km", "kg"),
                    uc.handle_tool_call({}),
                    uc.handle_tool_call({"action": "nope"})):
            self.assertEqual(res["ok"], False)
            self.assertEqual(res["success"], False)
            self.assertIsNone(res["data"] or None)
            self.assertIn("UnitError", res["error"])
        good = convert(1, "km", "m")
        self.assertEqual(good["ok"], True)
        self.assertEqual(good["data"], good["result"])
        self.assertIsNone(good["error"])


class LengthMassVolumeTests(unittest.TestCase):
    def test_known_pairs(self):
        cases = [
            (1, "km", "m", 1000),
            (21.0975, "km", "mi", 13.109379),      # half-marathon
            (1, "mi", "km", 1.609344),
            (70, "kg", "lb", 154.323584),           # 70 kg in pounds
            (1, "lb", "kg", 0.45359237),
            (1, "t", "kg", 1000),
            (1, "gal_us", "l", 3.785412),           # US gallon
            (1, "gal_uk", "l", 4.54609),            # imperial gallon differs
        ]
        for value, source, target, expected in cases:
            with self.subTest(f"{value} {source} -> {target}"):
                out = convert(value, source, target)
                self.assertTrue(out["ok"], out)
                self.assertAlmostEqual(out["result"]["value"], expected, places=4)

    def test_roundtrip_restores_the_value(self):
        for value, source, target in [(12.345, "m", "ft"), (0.5, "t", "oz"), (99, "kn", "mph")]:
            one = convert(value, source, target)["result"]["value"]
            back = convert(one, target, source)["result"]["value"]
            self.assertAlmostEqual(back, value, places=6)


class AffineTemperatureTests(unittest.TestCase):
    def test_celsius_fahrenheit_known_pairs(self):
        for celsius, fahrenheit in [(0, 32), (100, 212), (37, 98.6), (-40, -40)]:
            with self.subTest(f"{celsius}C"):
                out = convert(celsius, "degC", "degF", precision=4)
                self.assertAlmostEqual(out["result"]["value"], fahrenheit, places=4)

    def test_kelvin_offsets(self):
        self.assertAlmostEqual(convert(0, "degC", "K")["result"]["value"], 273.15, places=5)
        self.assertAlmostEqual(convert(0, "K", "degC")["result"]["value"], -273.15, places=5)
        # 0 degF = 255.372 K exactly (459.67 * 5/9)
        self.assertAlmostEqual(convert(0, "degF", "K")["result"]["value"],
                               459.67 * 5 / 9, places=5)

    def test_friendly_degree_spellings(self):
        for spelling in ("°C", "C", "degC"):
            out = convert(100, spelling, "degF")
            self.assertTrue(out["ok"], out)
            self.assertAlmostEqual(out["result"]["value"], 212, places=6)


class MiscCategoryTests(unittest.TestCase):
    def test_speed_time_energy_pressure_data(self):
        cases = [
            (30, "m/s", "km/h", 108),            # 30 m/s
            (1, "mph", "km/h", 1.609344),
            (1, "kWh", "MJ", 3.6),              # energy
            (1, "atm", "bar", 1.01325),          # pressure
            (100, "MB", "MiB", 95.367432),       # SI vs binary bytes
            (1, "GiB", "MiB", 1024),
            (1, "h", "min", 60),
            (1, "ha", "m2", 10000),              # area
            (1, "hp", "kW", 0.7457),             # power
        ]
        for value, source, target, expected in cases:
            with self.subTest(f"{value} {source} -> {target}"):
                out = convert(value, source, target, precision=6)
                self.assertTrue(out["ok"], out)
                self.assertAlmostEqual(out["result"]["value"], expected, places=4)

    def test_list_units_action(self):
        out = uc.handle_tool_call({"action": "list_units"})
        self.assertTrue(out["ok"])
        cats = out["result"]["categories"]
        self.assertIn("temperature", cats)
        self.assertIn({"unit": "km", "description": "kilometer"}, cats["length"])


class ValidationTests(unittest.TestCase):
    def test_comma_decimal_and_string_numbers(self):
        out = convert("12,5", "km", "m")
        self.assertTrue(out["ok"], out)
        self.assertEqual(out["result"]["value"], 12500)

    def test_cross_category_is_refused_with_categories(self):
        out = convert(5, "km", "kg")
        self.assertFalse(out["ok"])
        self.assertIn("length", out["error"])
        self.assertIn("mass", out["error"])

    def test_unknown_units_suggest_close_matches(self):
        out = convert(5, "kilometer", "mile")
        self.assertFalse(out["ok"])
        self.assertIn("Did you mean", out["error"])

    def test_precision_is_clamped_and_honoured(self):
        out = convert(1, "m", "ft", precision=0)
        self.assertEqual(out["result"]["value"], 3)
        self.assertIn("precision", out["result"])
        for bad in (13, -1, "few"):
            res = convert(1, "m", "ft", precision=bad)
            self.assertFalse(res["ok"], bad)

    def test_integer_whole_results_stay_integers(self):
        out = convert(2, "km", "m")
        self.assertIsInstance(out["result"]["value"], int)
        self.assertEqual(out["result"]["value"], 2000)

    def test_temperature_requires_both_categories(self):
        out = convert(10, "degC", "J")
        self.assertFalse(out["ok"])
        self.assertIn("temperature", out["error"])


if __name__ == "__main__":
    unittest.main()
