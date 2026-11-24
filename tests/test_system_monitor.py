"""System diagnostics contract on the real Linux /proc source."""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import system_monitor


class SystemMonitorTests(unittest.TestCase):
    def test_snapshot_has_real_bounded_metrics(self):
        data = system_monitor.snapshot()
        self.assertGreater(data["memory"]["total"], 0)
        self.assertGreaterEqual(data["disk"]["total"], data["disk"]["free"])
        self.assertEqual(len(data["load"]), 3)
        self.assertGreaterEqual(data["cpu_count"], 1)
        self.assertLessEqual(len(data["processes"]), 10)
        for row in data["processes"]:
            self.assertIsInstance(row["pid"], int)
            self.assertIsInstance(row["rss"], int)

    def test_processes_with_spaces_in_comm_are_parsed_correctly(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            pid_dir = proc / "4242"
            pid_dir.mkdir()
            fields = ["S"] + ["0"] * 10 + ["120", "30"] + ["0"] * 25
            (pid_dir / "stat").write_text("4242 (Web Content) " + " ".join(fields))
            (pid_dir / "status").write_text("Name:\tWeb Content\nVmRSS:\t2048 kB\n")
            with mock.patch.object(system_monitor, "PROC", proc):
                rows = system_monitor._processes(5)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["pid"], 4242)
            self.assertEqual(rows[0]["state"], "S")
            self.assertEqual(rows[0]["cpu_ticks"], 150)


if __name__ == "__main__":
    unittest.main()
