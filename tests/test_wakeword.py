"""Local wake-word processing; no microphone or network in unit tests."""
import unittest
from pathlib import Path
from unittest.mock import MagicMock


class WakeWordTests(unittest.TestCase):
    def test_detector_uses_pcm_and_detects_model_score(self):
        import wakeword
        model = MagicMock()
        model.predict.return_value = {'hey_jarvis_v0.1': 0.91}
        detector = wakeword.Detector(loader=lambda: model)
        result = detector.process(b'\x00\x00' * 1280)
        self.assertTrue(result['detected'])
        self.assertEqual(result['engine'], 'openwakeword')
        self.assertEqual(model.predict.call_args.args[0].size, 1280)

    def test_rejects_unbounded_or_misaligned_audio(self):
        import wakeword
        detector = wakeword.Detector(loader=MagicMock())
        for audio in (b'', b'\x00', b'\x00' * 64002):
            with self.assertRaises(ValueError):
                detector.process(audio)

    def test_batches_check_each_80ms_block_for_a_trigger(self):
        import wakeword
        model = MagicMock()
        model.predict.side_effect = [{'hey_jarvis_v0.1': 0.9}, {'hey_jarvis_v0.1': 0.0}]
        detector = wakeword.Detector(loader=lambda: model)
        self.assertTrue(detector.process(b'\x00\x00' * 2560)['detected'])
        self.assertEqual(model.predict.call_count, 2)

    def test_silence_does_not_activate(self):
        import wakeword
        model = MagicMock()
        model.predict.return_value = {'hey_jarvis_v0.1': 0.01}
        self.assertFalse(wakeword.Detector(loader=lambda: model).process(b'\x00\x00' * 1280)['detected'])


class WakeViewerContractTests(unittest.TestCase):
    """The browser half of the wake word: standby, batch size and stop behaviour."""

    def test_browser_wake_controller_stays_off_until_started(self):
        import subprocess

        from tests.node_support import node_binary
        node = node_binary()
        if node is None:
            self.skipTest("Node is used only as a test runner; set JARVIS_NODE or install Node")
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run([node, str(root / 'tests/test_wake.js')],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
