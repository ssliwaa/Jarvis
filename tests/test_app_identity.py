"""Desktop identity parser tests; no window is launched or closed."""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import app_identity


class AppIdentityTests(unittest.TestCase):
    def test_user_desktop_entry_wins_over_the_system_copy(self):
        with tempfile.TemporaryDirectory() as user_dir, tempfile.TemporaryDirectory() as system_dir:
            user, system = Path(user_dir), Path(system_dir)
            entry = "[Desktop Entry]\nType=Application\nName={name}\nExec={exe}\n"
            (user / "demo.desktop").write_text(entry.format(name="User Demo", exe="/usr/bin/user-demo"),
                                               encoding="utf-8")
            (system / "demo.desktop").write_text(entry.format(name="System Demo", exe="/usr/bin/system-demo"),
                                                 encoding="utf-8")
            with mock.patch.object(app_identity, "APP_ROOTS", (user, system)):
                found = app_identity.find("demo")
            self.assertEqual(len(found["apps"]), 1)
            self.assertEqual(found["apps"][0]["name"], "User Demo")

    def test_exec_field_codes_expand_without_a_shell(self):
        command = app_identity._command({"exec": 'demo --label=%%U %U %f "two words"'})
        self.assertEqual(command, ["demo", "--label=%U", "two words"])

    def test_empty_query_never_means_every_window(self):
        # find('') intentionally lists everything, but the mutating actions must
        # never interpret an empty name as "the first app/window in the list".
        with mock.patch.object(app_identity, "find") as find, \
                mock.patch.object(app_identity.subprocess, "run") as run, \
                mock.patch.object(app_identity.subprocess, "Popen") as popen:
            self.assertEqual(app_identity.launch("")["outcome"], "refused")
            self.assertEqual(app_identity.focus("  ")["outcome"], "refused")
            self.assertEqual(app_identity.close("", confirm=True)["outcome"], "refused")
            find.assert_not_called()
            run.assert_not_called()
            popen.assert_not_called()

    def test_desktop_entry_parsing_and_protected_close(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "demo.desktop").write_text(
                "[Desktop Entry]\nType=Application\nName=Demo App\nExec=demo %U\n"
                "Keywords=demo;test;\nNoDisplay=false\n", encoding="utf-8")
            with mock.patch.object(app_identity, "APP_ROOTS", (root,)), \
                 mock.patch.object(app_identity, "_windows", return_value=[]), \
                 mock.patch.object(app_identity, "_processes", return_value=[]):
                found = app_identity.find("demo")
                self.assertEqual(found["apps"][0]["name"], "Demo App")
                self.assertFalse(app_identity.close("demo", confirm=False)["ok"])
            with mock.patch.object(app_identity, "find", return_value={"windows": [
                    {"id": "0x1", "class": "jarvis", "title": "Jarvis", "desktop": "0", "host": "x"}]}):
                result = app_identity.close("jarvis", confirm=True)
                self.assertFalse(result["ok"])
                self.assertEqual(result["outcome"], "failed")


if __name__ == "__main__":
    unittest.main()
