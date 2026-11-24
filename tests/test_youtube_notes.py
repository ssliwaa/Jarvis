"""Offline tests for the YouTube transcript preview Operator tool."""
import tempfile
import unittest
from pathlib import Path

import tool_registry
from operator_modules import youtube_notes

ROOT = Path(__file__).resolve().parents[1]


class YouTubeNotesTests(unittest.TestCase):
    def test_youtube_url_allowlist_rejects_spoofs_and_ambiguous_ids(self):
        valid = ["https://www.youtube.com/watch?v=abcdefghijk&t=23",
                 "https://youtu.be/abcdefghijk?si=test",
                 "https://m.youtube.com/shorts/abcdefghijk",
                 "https://youtube.com/embed/abcdefghijk",
                 "https://youtube.com/live/abcdefghijk"]
        invalid = ["abcdefghijk", "http://youtube.com/watch?v=abcdefghijk",
                   "https://youtube.com.evil.test/watch?v=abcdefghijk",
                   "https://youtube.com@evil.test/watch?v=abcdefghijk",
                   "https://youtube.com:443/watch?v=abcdefghijk",
                   "https://youtube.com/watch?v=abcdefghijk&v=abcdefghijk",
                   "https://youtu.be/abcdefghijk/extra",
                   "https://youtube.com/watch?v=abc%2Fdefghij",
                   "https://youtube.com/watch?v=abcdefghijk\n"]
        for url in valid:
            with self.subTest(url=url):
                self.assertEqual(youtube_notes.video_id(url), "abcdefghijk")
        for url in invalid:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    youtube_notes.video_id(url)

    def test_operator_discovers_preview_tool(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = tool_registry.ToolRegistry(ROOT / "operator_modules", Path(directory) / "state.json")
            self.assertTrue(registry.has("youtube_notes"), registry.errors)
            self.assertEqual(registry.get("youtube_notes").schema["type"], "object")


if __name__ == "__main__":
    unittest.main()
