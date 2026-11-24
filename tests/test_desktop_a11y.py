"""Offline characterization tests for operator_modules/desktop_a11y.py.

Audit finding: the only operator module registered live by tool_registry's
directory discovery that had zero test coverage. Everything here runs
offline - subprocess calls are bounded to the mocked _run seam and binary
probing goes through a patched shutil.which. The one live integration test
loads the module through the real ToolRegistry pointed at an isolated
directory, because that is exactly how production discovers this tool.
"""
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import tool_registry
import operator_modules.desktop_a11y as da

MODULE_PATH = Path(da.__file__).resolve()


def _fake_run(outputs):
    """Build a _run stub returning (code, stdout) from a list per call."""
    outputs = list(outputs)
    seen = []

    def fake_run(argv, timeout=3.0):
        seen.append((tuple(argv), timeout))
        if outputs:
            return outputs.pop(0)
        return 1, ""

    fake_run.seen = seen
    return fake_run


class ToolContractTests(unittest.TestCase):
    def test_tool_dict_satisfies_registry_contract(self):
        self.assertEqual(da.TOOL["name"], "desktop_a11y")
        self.assertTrue(tool_registry.NAME_RE.fullmatch(da.TOOL["name"]))
        self.assertTrue(da.TOOL["description"].strip())
        schema = da.TOOL["input_schema"]
        self.assertEqual(schema.get("type"), "object")
        self.assertEqual(schema["properties"]["action"]["enum"],
                         ["inspect", "windows"])
        self.assertFalse(schema.get("additionalProperties", True))
        self.assertIs(da.TOOL["handler"], da.desktop_a11y)
        self.assertTrue(callable(da.TOOL["handler"]))
        self.assertFalse(da.TOOL["approval"])

    def test_module_registers_through_real_tool_registry(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "desktop_a11y.py"
            os.symlink(MODULE_PATH, target)
            registry = tool_registry.ToolRegistry(
                directory=Path(tmp), state_path=Path(tmp) / "state.json")
            self.assertEqual(registry.errors, [])
            self.assertTrue(registry.has("desktop_a11y"))
            self.assertFalse(registry.get("desktop_a11y").approval)
            declaration = registry.get("desktop_a11y").declaration()
            self.assertEqual(declaration["name"], "desktop_a11y")
            self.assertIn("input_schema", declaration)


class ActiveWindowTests(unittest.TestCase):
    def _patch_shutil(self, present=()):
        present = set(present)

        def fake_which(name_or_path):
            if name_or_path in present:
                return name_or_path if name_or_path.startswith("/") \
                    else f"/usr/bin/{name_or_path}"
            return None

        patcher = patch.object(da, "shutil",
                               SimpleNamespace(which=fake_which))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_xdotool_missing_returns_empty_structure(self):
        self._patch_shutil(present=[])
        result = da._active_window()
        self.assertEqual(result, {"window_id": None, "title": "",
                                   "geometry": {}})

    def test_xdotool_reports_title_and_geometry(self):
        self._patch_shutil(present=("xdotool",))
        runner = _fake_run([
            (0, "12345"),
            (0, "My Window"),
            (0, "X=10\nY=25\nWIDTH=300\nHEIGHT=200\nSCREEN=0"),
        ])
        with patch.object(da, "_run", runner):
            result = da._active_window()
        self.assertEqual(result["window_id"], "12345")
        self.assertEqual(result["title"], "My Window")
        self.assertEqual(result["geometry"],
                         {"x": 10, "y": 25, "width": 300,
                          "height": 200, "screen": 0})
        argvs = [argv for argv, _ in runner.seen]
        self.assertEqual(argvs, [
            ("xdotool", "getactivewindow"),
            ("xdotool", "getwindowname", "12345"),
            ("xdotool", "getwindowgeometry", "--shell", "12345"),
        ])

    def test_getactivewindow_failure_returns_empty_structure(self):
        self._patch_shutil(present=("xdotool",))
        with patch.object(da, "_run", _fake_run([(2, "")])):
            result = da._active_window()
        self.assertEqual(result["window_id"], None)
        self.assertEqual(result["geometry"], {})

    def test_geometry_parsing_skips_non_numeric_values(self):
        self._patch_shutil(present=("xdotool",))
        runner = _fake_run([
            (0, "99"),
            (0, "T"),
            (0, "X=abc\nY=5"),
        ])
        with patch.object(da, "_run", runner):
            result = da._active_window()
        self.assertEqual(result["geometry"], {"y": 5})


class ListWindowsTests(unittest.TestCase):
    WMCTRL_ROWS = (
        "0x02a00001  0  100  100  800  600  host Alpha\n"
        "0x02b00002  1  120  140  640  480  host Beta\n"
        "0x02c00003 -1  10  10  100  50  host\n"
    )

    def test_wmctrl_rows_parsed_with_limit_cap(self):
        with patch.object(da, "shutil",
                          SimpleNamespace(which=lambda n: "/usr/bin/wmctrl")):
            runner = _fake_run([(0, self.WMCTRL_ROWS)])
            with patch.object(da, "_run", runner):
                rows = da._list_windows(limit=2)
        # The sticky window without a title has no 8th field: dropped.
        self.assertEqual([r["id"] for r in rows],
                         ["0x02a00001", "0x02b00002"])
        first = rows[0]
        self.assertEqual(
            (first["desktop"], first["x"], first["y"], first["width"],
             first["height"], first["title"]),
            ("0", 100, 100, 800, 600, "Alpha"))
        self.assertEqual(runner.seen[0][0], ("wmctrl", "-lG"))

    def test_falls_back_to_active_window_without_wmctrl(self):
        active = {"window_id": "77", "title": "Solo",
                  "geometry": {"x": 1}}
        with patch.object(da, "_active_window", return_value=active):
            with patch.object(da, "shutil",
                              SimpleNamespace(which=lambda n: None)):
                rows = da._list_windows()
        self.assertEqual(rows, [active])

    def test_no_tools_yields_empty_list(self):
        with patch.object(da, "_active_window",
                          return_value={"window_id": None}):
            with patch.object(da, "shutil",
                              SimpleNamespace(which=lambda n: None)):
                self.assertEqual(da._list_windows(), [])


class AtspiProbeTests(unittest.TestCase):
    def _probe(self, atspi_output, limit=60, python3=True):
        present = {"/usr/bin/python3"} if python3 else set()

        def fake_which(name_or_path):
            return name_or_path if name_or_path in present else None

        runner = _fake_run([(0, atspi_output)])
        with patch.object(da, "shutil",
                          SimpleNamespace(which=fake_which)):
            with patch.object(da, "_run", runner):
                data = da._inspect_atspi(limit=limit)
        return data, runner.seen

    def test_probes_python_with_limit_forwarded(self):
        payload = '{"available": true, "elements": [{"role": "push button"}]}'
        data, seen = self._probe(payload, limit=77)
        argv, timeout = seen[0]
        self.assertEqual(argv[0], "/usr/bin/python3")
        self.assertEqual(argv[2], da._ATSPI_SCRIPT)
        self.assertEqual(argv[3], "77")
        self.assertGreater(timeout, 3.0)
        self.assertTrue(data["available"])
        self.assertEqual(data["elements"], [{"role": "push button"}])

    def test_last_line_is_the_json_payload(self):
        payload = 'warning: something minor\n{"available": false, "reason": "no desktop"}'
        data, _ = self._probe(payload)
        self.assertFalse(data["available"])
        self.assertEqual(data["reason"], "no desktop")

    def test_invalid_json_reports_unavailable(self):
        for junk in ("not json at all", '{"available": true, "elements": "x"'):
            data, _ = self._probe(junk)
            self.assertEqual(data, {"available": False, "elements": []})

    def test_failure_exit_reports_unavailable(self):
        with patch.object(da, "shutil",
                          SimpleNamespace(which=lambda n: n)):
            runner = _fake_run([(1, "")])
            with patch.object(da, "_run", runner):
                data = da._inspect_atspi()
        self.assertEqual(data, {"available": False, "elements": []})

    def test_python3_fallback_when_usr_bin_missing(self):
        data, seen = self._probe('{"available": false}',
                                 python3=False)
        self.assertEqual(seen[0][0][0], "python3")
        self.assertFalse(data["available"])


class HandlerTests(unittest.TestCase):
    def test_inspect_action_shapes_envelope(self):
        active = {"window_id": "5", "title": "T", "geometry": {}}
        atspi = {"available": True,
                 "elements": [{"app": "a", "role": "text"}]}
        with patch.object(da, "_active_window", return_value=active), \
                patch.object(da, "_inspect_atspi", return_value=atspi):
            result = da.desktop_a11y({"action": "inspect", "limit": 10})
        self.assertTrue(result["ok"])
        self.assertEqual(result["action"], "inspect")
        self.assertIs(result["active_window"], active)
        self.assertTrue(result["atspi_available"])
        self.assertEqual(result["elements"], [{"app": "a", "role": "text"}])

    def test_default_action_and_null_arguments_are_inspect(self):
        with patch.object(da, "_active_window",
                          return_value={"window_id": None}), \
                patch.object(da, "_inspect_atspi",
                             return_value={"available": False}):
            result = da.desktop_a11y(None, context={"state_root": "x"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["action"], "inspect")
        self.assertFalse(result["atspi_available"])
        self.assertEqual(result["elements"], [])

    def test_windows_action_lists_windows(self):
        rows = [{"id": "0x1", "title": "A"}]
        with patch.object(da, "_list_windows", return_value=rows) as lists:
            result = da.desktop_a11y({"action": "WINDOWS", "limit": 7})
        lists.assert_called_once_with(limit=7)
        self.assertTrue(result["ok"])
        self.assertEqual(result["action"], "windows")
        self.assertEqual(result["count"], 1)
        self.assertIs(result["windows"], rows)

    def test_unsupported_action_rejected(self):
        result = da.desktop_a11y({"action": "frobnicate"})
        self.assertFalse(result["ok"])
        self.assertIn("Unsupported action", result["error"])
        self.assertIn("frobnicate", result["error"])

    def test_limit_clamped_into_probe_range(self):
        cases = {0: 50, 1: 1, -3: 1, 60: 60, 999: 150, 150: 150}
        for given, expected in cases.items():
            with patch.object(da, "_inspect_atspi",
                              return_value={"available": False}) as probe:
                da.desktop_a11y({"action": "inspect", "limit": given})
            probe.assert_called_once_with(limit=expected)

    def test_garbage_limit_raises_for_registry_envelope(self):
        with self.assertRaises(ValueError):
            da.desktop_a11y({"action": "inspect", "limit": "abc"})

    def test_numeric_string_limit_is_coerced(self):
        with patch.object(da, "_inspect_atspi",
                          return_value={"available": False}) as probe:
            da.desktop_a11y({"action": "inspect", "limit": "60"})
        probe.assert_called_once_with(limit=60)

    def test_live_xdotool_header_matches_helper_contract(self):
        # The AT-SPI probe is a subprocess: its inline script must keep the
        # `limit` argv contract used above, so pin the script's signature.
        self.assertIn("sys.argv[1]", da._ATSPI_SCRIPT)
        self.assertIn("Atspi", da._ATSPI_SCRIPT)
        self.assertNotIn("eval", da._ATSPI_SCRIPT)
        self.assertNotIn("exec", da._ATSPI_SCRIPT)


if __name__ == "__main__":
    unittest.main()
