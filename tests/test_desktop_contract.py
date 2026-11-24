"""No-launch contracts for the Jarvis desktop shell."""
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DESKTOP = ROOT / "desktop"


class DesktopContract(unittest.TestCase):
    def test_main_uses_a_single_local_window_and_server_lifecycle(self):
        main = (DESKTOP / "main.js").read_text(encoding="utf-8")
        self.assertIn("new BrowserWindow", main)
        self.assertIn("http://127.0.0.1:4700", main)
        self.assertIn("spawn(PYTHON", main)
        self.assertIn("stopServer", main)
        self.assertIn("requestSingleInstanceLock", main)

    def test_global_talk_key_uses_a_private_preload_bridge(self):
        main = (DESKTOP / "main.js").read_text(encoding="utf-8")
        preload = (DESKTOP / "preload.js").read_text(encoding="utf-8")
        self.assertIn("globalShortcut.register", main)
        self.assertIn("preload: path.join(__dirname, 'preload.js')", main)
        self.assertIn("backgroundThrottling: false", main)
        self.assertIn("onPushToTalk", preload)
        self.assertNotIn("nodeIntegration: true", main)

    def test_permissions_and_navigation_are_default_deny(self):
        main = (DESKTOP / "main.js").read_text(encoding="utf-8")
        self.assertIn("const ALLOWED_PERMISSIONS", main)
        self.assertIn("clipboard-sanitized-write", main)
        self.assertIn("return callback(false)", main)
        self.assertIn("setDevicePermissionHandler(() => false)", main)
        for event in ("will-navigate", "will-redirect", "will-frame-navigate",
                      "will-attach-webview", "web-contents-created"):
            self.assertIn(event, main)

    def test_launcher_package_and_desktop_entry_are_pinned(self):
        package = json.loads((DESKTOP / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(package["main"], "main.js")
        self.assertEqual(package["dependencies"]["electron"], "45.0.0")
        launcher = DESKTOP / "jarvis-app.sh"
        self.assertTrue(launcher.is_file())
        self.assertTrue(launcher.stat().st_mode & 0o111)
        icon = DESKTOP / "icon.png"
        self.assertEqual(icon.read_bytes()[:8], b"\x89PNG\r\n\x1a\n")
        entry = (DESKTOP / "Jarvis.desktop").read_text(encoding="utf-8")
        self.assertIn("Exec=jarvis-app", entry)
        self.assertIn("Icon=jarvis", entry)
        self.assertIn("Terminal=false", entry)


if __name__ == "__main__":
    unittest.main()
