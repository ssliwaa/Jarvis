"""Structure checks only; the actual preflight always makes live calls."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


class PreflightContract(unittest.TestCase):
    def test_every_runtime_helper_is_fingerprinted(self):
        import server
        required = {
            'context_budget.py', 'plan_files.py', 'web_runner.py', 'web_backends.py',
            'ocr_runner.py', 'ocr_backends.py', 'evolution.py', 'stt.py',
            'usage_meter.py', 'net_guard.py', 'sqlite_guard.py',
        }
        self.assertLessEqual(required, set(server.RUNTIME_SOURCES))

    def test_readme_counts_match_the_live_registries(self):
        import browser_agent
        import preflight
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(f"**{len(browser_agent.TOOLS)}** names", readme)
        self.assertIn(f"now {len(preflight.CHECKS)} checks", readme)
        package = __import__("json").loads((ROOT / "desktop/package.json").read_text(encoding="utf-8"))
        self.assertIn(f"Electron `{package['dependencies']['electron']}`", readme)

    def test_a_retired_model_is_refused_before_any_live_call(self):
        import preflight
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config.json").write_text(json.dumps(
                {"provider": "deepseek", "model": "deepseek-chat"}), encoding="utf-8")
            probe = object.__new__(preflight.Preflight)
            probe.config_hash = None
            with mock.patch.object(preflight, "ROOT", root), \
                    mock.patch.object(preflight, "load_deepseek_key",
                                      return_value="sk-" + "a" * 30):
                with self.assertRaises(preflight.Failure) as caught:
                    probe.configuration()
        self.assertIn("retired", str(caught.exception))
        self.assertIn("deepseek-flash", str(caught.exception))

    def test_heartbeat_has_a_live_preflight_check(self):
        import preflight
        self.assertIn('heartbeat', [item[0] for item in preflight.CHECKS])

    def test_desktop_mcp_has_a_live_preflight_check(self):
        import preflight
        self.assertIn('desktop_mcp', [item[0] for item in preflight.CHECKS])

    def test_vision_has_a_live_preflight_check(self):
        import preflight
        self.assertIn('vision', [item[0] for item in preflight.CHECKS])

    def test_wakeword_has_a_live_preflight_check(self):
        import preflight
        self.assertIn('wakeword', [item[0] for item in preflight.CHECKS])

    def test_personal_briefing_has_a_live_preflight_check(self):
        import preflight
        self.assertIn('personal_briefing', [item[0] for item in preflight.CHECKS])

    def test_live_check_registry_is_extensible_and_in_requested_order(self):
        self.assertTrue((ROOT / 'preflight.py').is_file(), 'preflight.py must implement the live harness')
        import preflight
        expected = ['server','graph','chat','capabilities','routing','retrieval','key','model','remember','files','config','mute','voice','tts','agent','p1','p2','p3','selfmod','teardown','browser','evidence','teardown_note','teardown_panel','kit','offline','chrome_clean','webbackends','context','checkpoints','ocr','planfiles']
        self.assertEqual([check[0] for check in preflight.CHECKS][:len(expected)], expected)
        for _, _, method in preflight.CHECKS:
            self.assertTrue(callable(getattr(preflight.Preflight, method, None)))
        source = (ROOT / 'preflight.py').read_text()
        for forbidden in ('unittest.mock', 'MockTransport', 'route.fulfill', 'page.route('):
            self.assertNotIn(forbidden, source, 'the live harness must not replace the real system')


if __name__ == '__main__':
    unittest.main()
