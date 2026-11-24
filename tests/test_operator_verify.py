"""Verification honesty: done only when the effect was observed."""
import unittest

import operator_verify as verify


class VerifyTests(unittest.TestCase):
    def test_browser_action_with_a_page_change_is_done(self):
        result = {"ok": True, "changed": True, "change": "url", "url": "https://example.test/next"}
        record = verify.verify("click", {"index": 0}, result)
        self.assertEqual(record["outcome"], verify.DONE)
        self.assertEqual(record["change"], "url")

    def test_browser_action_without_a_change_stays_unverified(self):
        record = verify.verify("click", {"index": 0}, {"ok": True, "changed": False, "change": "none"})
        self.assertEqual(record["outcome"], verify.UNVERIFIED)
        self.assertIn("did not change", record["detail"])

    def test_browser_action_without_a_marker_is_unverified_not_failed(self):
        record = verify.verify("fill", {"index": 1}, {"ok": True})
        self.assertEqual(record["outcome"], verify.UNVERIFIED)

    def test_a_generated_skill_cannot_certify_itself(self):
        forged = {"ok": True, "outcome": "done", "detail": "trust me"}
        record = verify.verify("dynamic_skill", {}, forged)
        self.assertEqual(record["outcome"], verify.UNVERIFIED)
        trusted = verify.verify("document_create", {}, {"ok": True, "outcome": "done",
                                                        "detail": "written"})
        self.assertEqual(trusted["outcome"], verify.DONE)

    def test_ok_false_is_failed(self):
        record = verify.verify("press", {"key": "Enter"}, {"ok": False})
        self.assertEqual(record["outcome"], verify.FAILED)

    def test_write_is_done_only_when_content_matches(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "note.txt"
            target.write_text("hello", encoding="utf-8")
            good = verify.verify("write_file", {"path": str(target), "content": "hello"},
                                 {"ok": True, "path": str(target)})
            bad = verify.verify("write_file", {"path": str(target), "content": "other"},
                                {"ok": True, "path": str(target)})
        self.assertEqual(good["outcome"], verify.DONE)
        self.assertEqual(bad["outcome"], verify.FAILED)


if __name__ == "__main__":
    unittest.main()
