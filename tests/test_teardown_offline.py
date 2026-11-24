"""Offline teardown-kit checks; no browser or network."""
import os
import unittest

import teardown_offline

SANDBOXED = os.environ.get("JARVIS_VERIFY_SANDBOX") == "1"


class OfflineTeardownTests(unittest.TestCase):
    @unittest.skipIf(SANDBOXED, "Node is hidden in the verification sandbox")
    def test_addresses_fingerprints_and_attribution(self):
        result = teardown_offline.run_checks()
        self.assertEqual(result['addresses'], 5)
        self.assertEqual(result['fingerprints']['Three.js'], '165')
        self.assertEqual(result['fingerprints']['GSAP'], '3.12.5')
        self.assertGreater(result['digest_lines'], 0)
        self.assertIn('Three.js r165', result['summary'])

    def test_digest_never_has_an_unattributed_nonblank_line(self):
        import evidence_bay
        import teardown_brain
        evidence = teardown_offline.synthetic_evidence()
        evidence['digest_text'] = evidence_bay.render_digest(evidence)
        digest = teardown_brain.build_digest(evidence, 'example.com', 'How?')
        lines = [line for line in digest.splitlines() if line.strip()]
        self.assertTrue(lines)
        for line in lines:
            self.assertRegex(line, r'^\s*\[(REA|Jarvis)\]')


if __name__ == '__main__':
    unittest.main()
