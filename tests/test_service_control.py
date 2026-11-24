import unittest
from types import SimpleNamespace
from unittest import mock

import service_control


class ServiceControlTests(unittest.TestCase):
    def test_a_failed_systemctl_is_not_reported_as_success(self):
        failed = SimpleNamespace(returncode=1, stdout="", stderr="Unit not found")
        with mock.patch.object(service_control.subprocess, "run", return_value=failed), \
                mock.patch.object(service_control, "available", return_value=True):
            with self.assertRaises(service_control.ServiceError):
                service_control._run("restart", service_control.UNIT_NAME)
            status = service_control.status()
            self.assertIn("error", status)

    def test_unit_is_local_and_has_no_secret(self):
        text = service_control.unit_text()
        self.assertIn("Restart=always", text)
        self.assertIn("WatchdogSec=30", text)
        self.assertIn("server.py", text)
        self.assertNotIn("API_KEY", text)
        self.assertNotIn("sk-", text)

    def test_status_has_a_stable_shape(self):
        status = service_control.status()
        self.assertIn("available", status)
        self.assertIn("active", status)
        self.assertIn("unit", status)


if __name__ == "__main__":
    unittest.main()
