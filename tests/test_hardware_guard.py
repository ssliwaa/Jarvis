"""Unit tests for `hardware_guard.py` — hwmon/thermal parsing, meminfo math, state thresholds.

Osiągnięcie AGENT_LOG / twardy wymóg iteracji AU: dotąd moduł był tylko wyśmiewany w
obcych suite'ach (task_planner, automation_engine, wave5 hardware spike). Tu testujemy
go w pełni odizolowanie na fałszywym drzewie sysfs i fałszywej magistrali zdarzeń
(prawdziwy `event_bus` NIGDY nie jest dotykany; publish tylko przez patch.dict(sys.modules)).
"""
from __future__ import annotations

import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, ".")

import hardware_guard as hg  # noqa: E402


class _FakeBus:
    """Minimalna magistrala zliczająca publikacje; opcjonalnie rzuca przy publish."""

    def __init__(self, fail: bool = False) -> None:
        self.published: list[tuple[str, dict]] = []
        self.fail = fail

    def publish(self, topic: str, payload: dict) -> None:
        if self.fail:
            raise RuntimeError("fake bus down")
        self.published.append((topic, payload))


class HardwareGuardTest(unittest.TestCase):
    """Bazowe narzędzia: świeży tmp per test + pomocniki na konstrukcję sysfs."""

    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.base, True)

    def _hwmon(self, dirname: str, files: dict, chip_name: str | None = None) -> Path:
        d = self.base / "sys" / "class" / "hwmon" / dirname
        d.mkdir(parents=True)
        if chip_name is not None:
            (d / "name").write_text(chip_name, encoding="utf-8")
        for fname, content in files.items():
            (d / fname).write_text(str(content), encoding="utf-8")
        return d

    def _thermal(self, zones: dict[str, tuple[str, str]]) -> None:
        root = self.base / "sys" / "class" / "thermal"
        for zname, (temp, kind) in zones.items():
            d = root / zname
            d.mkdir(parents=True)
            if temp is not None:
                (d / "temp").write_text(temp, encoding="utf-8")
            if kind is not None:
                (d / "type").write_text(kind, encoding="utf-8")

    def _meminfo(self, text: str) -> Path:
        p = self.base / "meminfo"
        p.write_text(text, encoding="utf-8")
        return p


class ReadTemperaturesTests(HardwareGuardTest):
    def test_hwmon_parsing_units_labels_chips_and_garbage(self):
        """42000 m°C → 42.0°C; raw<=200 traktowany jako °C; śmieci/poza zakresem pomijane."""
        self._hwmon(
            "hwmon0",
            {"temp1_input": "42000", "temp1_label": "Tctl",
             "temp2_input": "21",                      # as-is 21.0°C
             "temp3_input": "garbage",                 # ValueError → skip
             "temp4_input": "99999999",                 # 99999.9°C poza [-10, 130] → skip
             "temp5_input": "-5",                       # -5.0°C ∈ zakres → OK
             "temp6_input": "200000"},                   # 200.0°C poza zakresem → skip
            chip_name="k10temp",
        )
        self._hwmon("hwmon1", {"temp1_input": "60000"})  # brak name → chip = nazwa katalogu
        res = hg.read_temperatures_c(self.base / "sys")

        self.assertEqual(res["peak_temp_c"], 60.0)
        self.assertEqual(
            res["sensors"],
            [
                {"chip": "k10temp", "label": "Tctl", "temp_c": 42.0},
                {"chip": "k10temp", "label": "temp2_input", "temp_c": 21.0},
                {"chip": "k10temp", "label": "temp5_input", "temp_c": -5.0},
                {"chip": "hwmon1", "label": "temp1_input", "temp_c": 60.0},
            ],
        )

    def test_thermal_fallback_only_when_hwmon_has_no_sensors(self):
        """Bez czytelnych hwmon → strefy thermal_zone*; chip stały 'thermal', label = type."""
        self._hwmon("hwmon0", {"temp1_input": "garbage"})  # żaden żywy sensor hwmon
        self._thermal({
            "thermal_zone0": ("45600", "x86_pkg_temp"),
            "thermal_zone1": (None, "gpu"),               # brak pliku temp → skip
            "thermal_zone2": ("abc", None),               # ValueError → skip
        })
        res = hg.read_temperatures_c(self.base / "sys")
        self.assertEqual(res["peak_temp_c"], 45.6)
        self.assertEqual(res["sensors"], [{"chip": "thermal", "label": "x86_pkg_temp", "temp_c": 45.6}])

    def test_thermal_ignored_when_hwmon_sensors_exist(self):
        """Czysta kolejność źródeł: hwmon wygrywa, gorące strefy thermal są ignorowane."""
        self._hwmon("hwmon0", {"temp1_input": "60000"}, chip_name="acpitz")
        self._thermal({"thermal_zone0": ("90000", "hot_zone")})  # 90.0°C — dystraktor
        res = hg.read_temperatures_c(self.base / "sys")
        self.assertEqual(res["peak_temp_c"], 60.0)
        self.assertEqual(len(res["sensors"]), 1)

    def test_sensors_capped_at_twelve_but_peak_from_full_list(self):
        """>12 sensorów → sensors[:12]; peak liczony na pełnej liście (zgodnie ze źródłem)."""
        zones = {f"thermal_zone{i:02d}": (str(10000 + i * 1000), f"z{i}") for i in range(15)}
        self._thermal(zones)
        res = hg.read_temperatures_c(self.base / "sys")
        self.assertEqual(len(res["sensors"]), 12)
        self.assertEqual([s["label"] for s in res["sensors"]], [f"z{i}" for i in range(12)])
        self.assertEqual(res["peak_temp_c"], 24.0)  # zone14 = 24°C, wycięty z listy

    def test_empty_sys_root_yields_none_peak(self):
        res = hg.read_temperatures_c(self.base / "nothing")
        self.assertIsNone(res["peak_temp_c"])
        self.assertEqual(res["sensors"], [])


class ReadMemoryPressureTests(HardwareGuardTest):
    def test_parses_kb_to_mb_and_ignores_malformed_lines(self):
        p = self._meminfo(
            "MemTotal:       16000000 kB\n"
            "MemAvailable:    3999744 kB\n"
            "SwapTotal:       2097148 kB\n"
            "SwapFree:       2097148 kB\n"
            ":junk line\n"           # klucz pusty/bez części liczbowej → pominięte
            "Bogus: xyz kB\n"        # niedigit → pominięte
            "VmallocUsed: 0 kB\n"
        )
        self.assertEqual(
            hg.read_memory_pressure(p),
            {"mem_total_mb": 15625.0, "mem_available_mb": 3906.0, "swap_used_mb": 0.0},
        )

    def test_swap_math_clamps_and_uses_mb(self):
        p = self._meminfo("SwapTotal: 2048 kB\nSwapFree: 0 kB\n")
        self.assertEqual(hg.read_memory_pressure(p)["swap_used_mb"], 2.0)
        p2 = self._meminfo("SwapTotal: 100 kB\nSwapFree: 900 kB\n")  # free > total → clamp 0
        self.assertEqual(hg.read_memory_pressure(p2)["swap_used_mb"], 0.0)
        p3 = self._meminfo("SwapTotal: 0 kB\nSwapFree: 0 kB\n")      # brak swapu → 0.0
        self.assertEqual(hg.read_memory_pressure(p3)["swap_used_mb"], 0.0)

    def test_missing_file_yields_nones(self):
        res = hg.read_memory_pressure(self.base / "nope")
        self.assertEqual(res, {"mem_total_mb": None, "mem_available_mb": None, "swap_used_mb": 0.0})


class SnapshotTests(HardwareGuardTest):
    def _snapshot(self, bus: _FakeBus):
        with mock.patch.dict(sys.modules, {"event_bus": bus}):
            return hg.snapshot(sys_root=self.base / "sys", proc_meminfo=self.base / "meminfo")

    def _make(self, temp_raw: str, mem_kb: str) -> None:
        self._hwmon("hwmon0", {"temp1_input": temp_raw}, chip_name="pkg")
        self._meminfo(f"MemAvailable: {mem_kb} kB\n")

    def test_nominal_when_no_data_at_all(self):
        """Pusty sysfs + brak meminfo → nominal, zero powodów, brak publikacji."""
        bus = _FakeBus()
        before = time.time()
        res = self._snapshot(bus)
        self.assertEqual(res["ok"], True)
        self.assertEqual(res["state"], "nominal")
        self.assertEqual(res["reasons"], [])
        self.assertIsNone(res["peak_temp_c"])
        self.assertIsNone(res["mem_total_mb"])
        self.assertIsNone(res["mem_available_mb"])
        self.assertEqual(res["swap_used_mb"], 0.0)
        self.assertEqual(res["recommended_max_parallel_agents"], 3)
        self.assertTrue(res["allow_heavy_background"])
        self.assertEqual(res["sensors"], [])
        self.assertIsInstance(res["checked_at"], float)
        self.assertAlmostEqual(res["checked_at"], before, delta=10.0)
        self.assertEqual(bus.published, [])

    def test_warm_temperature_boundary_and_no_publish(self):
        """78.0°C (raw 78000) == WARM_TEMP_C → warm; brak publikacji, background dozwolony."""
        self._make("78000", "3999744")
        bus = _FakeBus()
        res = self._snapshot(bus)
        self.assertEqual(res["state"], "warm")
        self.assertEqual(res["reasons"], ["wysoka temperatura czujnika (78.0°C)"])
        self.assertEqual(res["recommended_max_parallel_agents"], 1)
        self.assertTrue(res["allow_heavy_background"])
        self.assertEqual(bus.published, [])

    def test_just_below_warm_threshold_is_nominal(self):
        self._make("77000", "3999744")
        res = self._snapshot(_FakeBus())
        self.assertEqual(res["state"], "nominal")
        self.assertEqual(res["reasons"], [])

    def test_critical_temperature_publishes_alert_with_payload(self):
        self._make("88000", "3999744")  # 88.0°C == CRITICAL_TEMP_C; mem 3906.0 MB
        bus = _FakeBus()
        res = self._snapshot(bus)
        self.assertEqual(res["state"], "critical")
        self.assertEqual(res["recommended_max_parallel_agents"], 1)
        self.assertFalse(res["allow_heavy_background"])
        self.assertTrue(res["ok"])
        self.assertEqual(
            bus.published,
            [("hardware.alert", {
                "state": "critical",
                "peak_temp_c": 88.0,
                "mem_available_mb": 3906.0,
                "reasons": ["wysoka temperatura czujnika (88.0°C)"],
            })],
        )

    def test_memory_thresholds_warm_and_critical(self):
        # 1433600 kB → dokładnie 1400.0 MB (<= LOW → warm)
        self._make("10000", "1433600")
        res = self._snapshot(_FakeBus())
        self.assertEqual(res["state"], "warm")
        self.assertEqual(res["reasons"], ["niska dostępna pamięć RAM (1400.0 MB)"])

        # 1434624 kB → 1401.0 MB (> LOW → nominal)
        self._meminfo("MemAvailable: 1434624 kB\n")
        res = self._snapshot(_FakeBus())
        self.assertEqual(res["state"], "nominal")

        # 614400 kB → dokładnie 600.0 MB (<= CRITICAL → critical + publish)
        bus = _FakeBus()
        self._meminfo("MemAvailable: 614400 kB\n")
        res = self._snapshot(bus)
        self.assertEqual(res["state"], "critical")
        self.assertFalse(res["allow_heavy_background"])
        self.assertEqual(bus.published[0][0], "hardware.alert")
        self.assertEqual(bus.published[0][1]["mem_available_mb"], 600.0)
        self.assertEqual(len(bus.published[0][1]["reasons"]), 1)

    def test_both_reasons_presented_in_stable_order(self):
        """Gorący czujnik + mało RAM → oba powody: najpierw temperatura, potem pamięć."""
        self._make("80000", "1300000")  # 80.0°C + 1269.5 MB
        res = self._snapshot(_FakeBus())
        self.assertEqual(res["state"], "warm")
        self.assertEqual(
            res["reasons"],
            ["wysoka temperatura czujnika (80.0°C)", "niska dostępna pamięć RAM (1269.5 MB)"],
        )

    def test_publish_failure_is_silent(self):
        """Awaria magistrali (import/publish rzuca) nie wybucha — snapshot zwraca wynik."""
        self._make("88000", "3999744")
        bus = _FakeBus(fail=True)
        res = self._snapshot(bus)
        self.assertEqual(res["state"], "critical")
        self.assertTrue(res["ok"])
        self.assertEqual(res["recommended_max_parallel_agents"], 1)

    def test_constant_thresholds_match_documented_values(self):
        self.assertEqual(hg.WARM_TEMP_C, 78.0)
        self.assertEqual(hg.CRITICAL_TEMP_C, 88.0)
        self.assertEqual(hg.LOW_MEM_AVAILABLE_MB, 1400.0)
        self.assertEqual(hg.CRITICAL_MEM_AVAILABLE_MB, 600.0)


if __name__ == "__main__":
    unittest.main()
