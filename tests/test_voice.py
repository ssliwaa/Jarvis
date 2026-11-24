"""Browser voice contract, deterministic event/timer tests, and microphone policy."""
import os
import subprocess
import threading
import unittest
from pathlib import Path
from urllib.request import urlopen

from tests.node_support import node_binary

ROOT = Path(__file__).resolve().parents[1]


class VoiceTests(unittest.TestCase):
    def run_scenario(self, scenario):
        node = node_binary()
        if node is None:
            self.skipTest("Node is used only as a test runner; set JARVIS_NODE or install Node")
        result = subprocess.run([node, str(ROOT / 'tests/test_voice.js'), scenario],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_gesture_mute_british_voice_and_speech_status(self):
        self.run_scenario('speaking')

    def test_recognition_language_follows_the_system_and_is_remembered(self):
        self.run_scenario('language')

    def test_finish_window_fragments_interim_and_recognition_end(self):
        self.run_scenario('listening')

    def test_instant_interrupts_and_extensible_routes_before_brain(self):
        self.run_scenario('routes')

    def test_unsupported_permission_errors_and_thinking_status(self):
        self.run_scenario('errors')

    def test_teardown_routes_are_address_gated_and_do_not_contact_brain(self):
        self.run_scenario('teardown-routes')

    def test_spoken_addresses_preserve_first_letter_and_drop_non_addresses(self):
        self.run_scenario('addresses')

    def test_self_echo_guard_drops_own_speech_but_keeps_user_turns(self):
        self.run_scenario('echo')

    def test_push_to_talk_and_selected_output_voice(self):
        self.run_scenario('parity')

    def test_desktop_talk_key_toggles_and_barges_in(self):
        self.run_scenario('desktop')

    def test_voice_dispatch_carries_the_reply_language_hint(self):
        self.run_scenario('reply-language')

    def test_voice_controls_and_app_integration(self):
        html = (ROOT / 'viewer/index.html').read_text()
        self.assertIn('src="voice.js"', html)
        self.assertLess(html.index('src="voice.js"'), html.index('src="app.js"'))
        for identifier in ('mic-button', 'voice-status', 'voice-transcript', 'voice-language', 'voice-output', 'mic-level'):
            self.assertIn(f'id="{identifier}"', html)
        self.assertIn('Ctrl', html)
        app = (ROOT / 'viewer/app.js').read_text()
        self.assertIn('createGalaxyVoice', app)
        self.assertIn('voice.speak(payload.answer)', app)
        # The streamed answer is accumulated for the panel and fed to the voice
        # sentence by sentence; the final result only contributes its tail.
        self.assertIn('voice.speakStream(streamed)', app)
        self.assertIn('voice.finishStream(payload.answer)', app)
        self.assertIn('streamed = partial.startsWith(streamed) ? partial : streamed + partial', app)

    def test_edge_tts_request_blob_fallback_and_cancellation(self):
        node = node_binary()
        if node is None:
            self.skipTest("Node is used only as a test runner; set JARVIS_NODE or install Node")
        result = subprocess.run([node, str(ROOT / 'tests/test_edge_voice.js')],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_local_transcription_sends_language_and_applies_the_echo_guard(self):
        source = (ROOT / 'viewer/voice.js').read_text()
        self.assertIn('fetch(`/voice/transcribe?language=', source)
        self.assertIn('if (isEcho(text))', source)
        self.assertIn('startingRecording', source)
        self.assertIn('transcribeAbort', source)

    @unittest.skipIf(os.environ.get("JARVIS_VERIFY_SANDBOX") == "1",
                     "create_server writes viewer/persona.js into the read-only tree")
    def test_microphone_allowed_only_for_own_origin(self):
        import tempfile

        from server import create_server
        self._state = tempfile.TemporaryDirectory()
        self.addCleanup(self._state.cleanup)
        httpd = create_server(root=ROOT, port=0, state_root=self._state.name,
                              enable_agent=False, enable_scheduler=False,
                              enable_memory_capture=False)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            with urlopen(f'http://127.0.0.1:{httpd.server_port}/') as response:
                policy = response.headers['Permissions-Policy']
                self.assertIn('microphone=(self)', policy)
                self.assertIn('camera=()', policy)
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join()


if __name__ == '__main__':
    unittest.main()
