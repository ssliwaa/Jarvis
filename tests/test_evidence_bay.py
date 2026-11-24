"""Evidence bay pure functions: target select, sources, fingerprints, assets, digest."""
import unittest
from unittest import mock

import evidence_bay


def normalized(targets=None, scripts=None):
    return {"normalized_result": {"targets": targets or [],
                                  "scripts": {"items": scripts or []}}}


def script_item(url="https://example.com/app.js", sha="abc", text=None):
    item = {"url": url, "cdp_hash": sha}
    if text is not None:
        item["source"] = {"artifact": {"text": text, "sha256": sha}}
    return item


class SelectTargetTests(unittest.TestCase):
    TARGETS = [
        {"target_id": "worker", "type": "worker", "url": "https://example.com/app.js"},
        {"target_id": "page-a", "type": "page", "url": "https://www.example.com/"},
        {"target_id": "page-b", "type": "page", "url": "https://other.test/"},
    ]

    def test_preferred_id_wins(self):
        picked = evidence_bay.select_target(normalized(self.TARGETS), "https://other.test/",
                                            preferred_id="page-a")
        self.assertEqual(picked["target_id"], "page-a")

    def test_host_match_ignores_www_and_skips_non_pages(self):
        picked = evidence_bay.select_target(normalized(self.TARGETS), "https://example.com/page")
        self.assertEqual(picked["target_id"], "page-a")

    def test_falls_back_to_the_first_page(self):
        picked = evidence_bay.select_target(normalized(self.TARGETS), "https://unrelated.test/")
        self.assertEqual(picked["target_id"], "page-a")

    def test_missing_page_raises(self):
        with self.assertRaises(evidence_bay.EvidenceError):
            evidence_bay.select_target(normalized([]), "https://example.com/")


class ExtractSourcesTests(unittest.TestCase):
    def test_artifact_text_is_deduped_by_hash(self):
        item = script_item(text="console.log(1)")
        sources = evidence_bay.extract_sources(normalized(scripts=[item, dict(item)]))
        self.assertEqual(len(sources), 1)
        self.assertEqual(sources[0]["captured_by"], "REA")
        self.assertEqual(sources[0]["text"], "console.log(1)")

    def test_missing_text_without_http_url_is_skipped_without_network(self):
        item = script_item(url="file:///tmp/app.js", text=None)
        self.assertEqual(evidence_bay.extract_sources(normalized(scripts=[item])), [])

    def test_a_private_fallback_url_is_never_fetched(self):
        item = script_item(url="http://127.0.0.1:4700/self/forge", text=None)
        with mock.patch.object(evidence_bay.web_research, "_pinned_open") as opener:
            self.assertEqual(evidence_bay.extract_sources(normalized(scripts=[item])), [])
        opener.assert_not_called()

    def test_the_fallback_uses_the_dns_pinned_public_opener(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def geturl(self):
                return "https://8.8.8.8/app.js"

            def read(self, _limit):
                return b"pinned body"

        with mock.patch.object(evidence_bay.web_research, "_pinned_open",
                               return_value=Response()) as opener, \
                mock.patch.object(evidence_bay.net_guard, "is_public_url", return_value=True):
            self.assertEqual(evidence_bay._fetch_public("https://8.8.8.8/app.js", 5, 100),
                             b"pinned body")
        opener.assert_called_once()

    def test_a_private_fallback_url_never_reaches_the_opener(self):
        with mock.patch.object(evidence_bay.web_research, "_pinned_open") as opener:
            self.assertIsNone(evidence_bay._fetch_public("http://127.0.0.1/x", 5, 100))
        opener.assert_not_called()

    def test_unhashed_scripts_keep_all_of_their_text(self):
        first = {"url": "https://example.com/a.js", "source": {"artifact": {"text": "Three.js"}}}
        second = {"url": "https://example.com/b.js", "source": {"artifact": {"text": "GSAP 3.12.5"}}}
        sources = evidence_bay.extract_sources(normalized(scripts=[first, second]))
        self.assertEqual(len(sources), 2)
        self.assertEqual({source["text"] for source in sources}, {"Three.js", "GSAP 3.12.5"})


class FingerprintTests(unittest.TestCase):
    def test_three_js_revision_and_gsap_version(self):
        text = ("/*! Three.js Authors\n * REVISION = '165' */\n"
                "GSAP 3.12.5 Copyright")
        results = evidence_bay.scan_fingerprints(
            [{"url": "https://example.com/lib.js", "sha256": "abc", "text": text,
              "captured_by": "REA"}])
        by_name = {item["name"]: item for item in results}
        self.assertEqual(by_name["Three.js"]["version"], "165")
        self.assertEqual(by_name["Three.js"]["scanned_by"], "Jarvis")
        self.assertEqual(by_name["GSAP"]["version"], "3.12.5")

    def test_requires_gate_skips_gsap_without_the_name(self):
        results = evidence_bay.scan_fingerprints(
            [{"url": "https://example.com/lib.js", "sha256": "a", "text": "version = '3.12.5'",
              "captured_by": "REA"}])
        self.assertNotIn("GSAP", {item["name"] for item in results})

    def test_banner_scan_dedupes(self):
        source = {"url": "https://example.com/a.js", "text": "/*! lib v1 */\n/*! lib v1 */",
                  "captured_by": "REA"}
        banners = evidence_bay.other_banners([source])
        self.assertEqual(len(banners), 1)
        self.assertIn("lib v1", banners[0]["banner"])


class ClassifyAssetTests(unittest.TestCase):
    def test_suffix_kinds(self):
        self.assertEqual(evidence_bay.classify_asset("https://x.test/a.js"), "scripts")
        self.assertEqual(evidence_bay.classify_asset("https://x.test/a.ktx2"), "compressed textures")
        self.assertEqual(evidence_bay.classify_asset("https://x.test/a.woff2"), "fonts")

    def test_initiator_fallbacks(self):
        self.assertEqual(evidence_bay.classify_asset("https://x.test/api", initiator="fetch"),
                         "data / API")
        self.assertEqual(evidence_bay.classify_asset("https://x.test/page", initiator="navigation"),
                         "document")
        self.assertEqual(evidence_bay.classify_asset("https://x.test/thing"), "other")


class RenderDigestTests(unittest.TestCase):
    RESULT = {
        "title": "Example",
        "url": "https://example.com/",
        "rea": {
            "target": {"target_id": "T1", "url": "https://example.com/"},
            "inspect": {"scripts": 3, "resources": 5, "observation_ms": 7000},
            "analyze": {
                "scripts_observed": 3, "scripts_analyzed": 2, "routes": ["/", "/about"],
                "scripts": [{"url": "https://example.com/app.js", "bytes": 2048}],
                "edges": [{"from": "https://example.com/app.js",
                           "to": "https://example.com/lib.js", "kind": "import"}],
            },
            "screenshot": {"path": "artifacts/evidence/J1/snapshot.png", "bytes": 1000,
                           "sha256": "a" * 64, "png_width": 1280, "png_height": 620},
        },
        "digest": {
            "code_signals": [{"name": "Three.js", "meaning": "3D scene", "captured_by": "REA"}],
            "stack": [{"name": "Three.js", "version": "165", "scanned_by": "Jarvis",
                       "captured_by": "REA"}],
            "asset_totals": {
                "resources": 5, "known_bytes": 4096, "unknown_sizes": 1,
                "origins": {"https://example.com": {"bytes": 4096, "count": 5}},
                "kinds": {"scripts": {"bytes": 4096, "count": 2}},
                "top": [{"url": "https://example.com/app.js", "kind": "scripts", "size": 2048}],
            },
        },
        "jarvis": {"other_banners": [],
                   "assets": {"all_path": "artifacts/evidence/J1/assets.json"}},
        "cleanup": {"ok": True, "profile_removed": True, "port_released": True},
    }

    def test_every_line_is_attributed(self):
        digest = evidence_bay.render_digest(self.RESULT)
        for line in digest.splitlines():
            if line.strip():
                self.assertTrue(line.strip().startswith(("[REA]", "[Jarvis]")), line)

    def test_digest_carries_stack_assets_and_screenshot(self):
        digest = evidence_bay.render_digest(self.RESULT)
        self.assertIn("Three.js r165", digest)
        self.assertIn("ASSETS: 5 resource entries", digest)
        self.assertIn("1 unknown sizes", digest)
        self.assertIn("SCREENSHOT", digest)
        self.assertIn("snapshot.png", digest)


if __name__ == "__main__":
    unittest.main()
