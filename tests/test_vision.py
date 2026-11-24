"""Explicit image analysis, with no real network or desktop calls."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from PIL import Image


class VisionTests(unittest.TestCase):
    def test_file_is_sent_to_existing_provider_without_exposing_data_to_result(self):
        from operator_modules import vision
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'image.png'
            Image.new('RGB', (20, 20), 'red').save(source)
            job = SimpleNamespace(key='synthetic', model='deepseek-flash',
                                  service=SimpleNamespace(app=SimpleNamespace(read_provider=lambda: 'deepseek')))
            client = MagicMock()
            client.messages.create.return_value = SimpleNamespace(content=[SimpleNamespace(type='text', text='A red square.')])
            with patch.object(vision.provider_client, 'DeepSeekClient', return_value=client):
                result = vision.vision_analyze({'source': 'file', 'path': str(source), 'question': 'Co widać?'}, {'job': job})
            self.assertTrue(result['ok'])
            self.assertEqual(result['answer'], 'A red square.')
            args = client.messages.create.call_args.kwargs
            self.assertEqual(args['messages'][0]['content'][1]['type'], 'image')
            self.assertNotIn('base64', str(result))
            client.close.assert_called_once()

    def test_nonimage_is_rejected_before_model_call(self):
        from operator_modules import vision
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'not.png'
            source.write_bytes(b'not an image')
            job = SimpleNamespace(key='synthetic', model='deepseek-flash',
                                  service=SimpleNamespace(app=SimpleNamespace(read_provider=lambda: 'deepseek')))
            with patch.object(vision.provider_client, 'DeepSeekClient') as client:
                result = vision.vision_analyze({'source': 'file', 'path': str(source)}, {'job': job})
            self.assertFalse(result['ok'])
            client.assert_not_called()

    def test_image_analysis_requires_user_approval_even_in_full_mode(self):
        import browser_agent
        job = object.__new__(browser_agent.AgentJob)
        job.mode = 'full'
        job.remote = False
        reason = job._guard('vision_analyze', {'source': 'screen'})
        self.assertIn('approv', reason.lower())


if __name__ == '__main__':
    unittest.main()
