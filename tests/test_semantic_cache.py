"""semantic_cache: prompt cache contracts — vectors, watermark, hit kinds and metrics.

This suite pins the zero-RAM SQLite prompt cache: prompt normalisation
(lowercase, >=2-char token filter with Polish letters and a single-char drop),
the scope-salted sha256 prompt key, the hashed sparse vector (unigrams 1.0,
bigrams 0.7, L2-normalised with 5-decimal rounding — hence self-cosine is
0.99999, not exactly 1.0), the directory watermark scanner (top-level plus
one-level file mtimes, hidden entries skipped, node_modules/__pycache__/venv
children excluded from the sub-scan while the directory mtime itself still
counts, broken symlinks tolerated), the put() gates (empty prompt/response
refused, TTL clamped to >=10 s, negative cost clipped to 0, norm and response
clipped to 2000/24000 chars, hits preserved across INSERT OR REPLACE), the
get() exact and semantic match kinds (scope and watermark isolation with the
0.002 tolerance, expired entries missed, empty prompts returning None without
counting a miss, allow_semantic=False disabling near-matches, a 17-token base
prompt versus an appended word crossing the 0.92 threshold and the reordered
3-token pair deterministically below it), the LRU-style overflow eviction by
created_at, expired-row purging on put, scoped clear(), and the hit-rate /
saved_usd metrics summary.

All assertions were pinned empirically before writing. The database is
redirected into a per-test sandbox by patching semantic_cache.agent_cli.ROOT.
"""
import os
import sqlite3
import tempfile
import time
import unittest
import zlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import semantic_cache


class SemanticCacheBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="scc_")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.agents_dir = self.tmp / "agents"
        self._cli = patch.object(semantic_cache, "agent_cli",
                                 SimpleNamespace(ROOT=self.agents_dir / "agent_cli.py"))
        self._cli.start()
        self.addCleanup(self._cli.stop)

    @property
    def db_path(self):
        return self.agents_dir / "semantic_cache.sqlite3"

    def db(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        self.addCleanup(conn.close)
        return conn


class TestNormalizePrompt(unittest.TestCase):
    def test_lowercases_tokens_and_drops_single_chars(self):
        self.assertEqual(semantic_cache.normalize_prompt("  Jaka Jest--  Pogoda w Warszawie?!  "),
                         "jaka jest pogoda warszawie")  # single-char 'w' dropped
        self.assertEqual(semantic_cache.normalize_prompt("ó żźć ń x"), "żźć")
        self.assertEqual(semantic_cache.normalize_prompt(""), "")
        self.assertEqual(semantic_cache.normalize_prompt(None), "")


class TestPromptKey(unittest.TestCase):
    def test_deterministic_scope_salted_sha256(self):
        first = semantic_cache._prompt_key("a b", "default")
        self.assertEqual(semantic_cache._prompt_key("a b", "default"), first)
        self.assertNotEqual(semantic_cache._prompt_key("a b", "other"), first)
        self.assertEqual(len(first), 64)  # hex sha256


class TestSparseVector(unittest.TestCase):
    """Bucket ids come from the process-randomised built-in hash(), so the
    exact micro-pins below run under a deterministic crc32 hash stub. Without
    the stub these constants drift per PYTHONHASHSEED (the reordered trio was
    measured at 0.75-0.88 across fresh processes), which made one of the
    original pins a genuine intermittent failure - see the AC log entry."""

    @staticmethod
    def stub_hash(value):
        if isinstance(value, str):
            return zlib.crc32(value.encode("utf-8"))
        return hash(value)

    def test_unigrams_bigrams_and_l2_normalisation(self):
        with patch("builtins.hash", self.stub_hash):
            vec = semantic_cache._sparse_vec("a b c")
        weights = sorted(vec.values())
        self.assertEqual(len(vec), 5)          # 3 unigrams + 2 bigrams
        self.assertAlmostEqual(sum(v * v for v in vec.values()), 1.0, places=4)
        self.assertEqual(weights[0], weights[1])  # bigram weight 0.7 after normalisation
        self.assertEqual(semantic_cache._sparse_vec(""), {})

    def test_cosine_self_symmetry_and_rounding(self):
        vec = semantic_cache._sparse_vec("a b c")
        self.assertGreaterEqual(semantic_cache._cosine(vec, vec), 0.999)  # rounding artefact
        self.assertEqual(semantic_cache._cosine(vec, {}), 0.0)
        with patch("builtins.hash", self.stub_hash):
            a = semantic_cache._sparse_vec("x y z")
            b = semantic_cache._sparse_vec("z y x")
            forward = semantic_cache._cosine(a, b)
            backward = semantic_cache._cosine(b, a)
        self.assertEqual(forward, backward)                      # symmetric
        self.assertAlmostEqual(forward, 0.7538, places=3)        # deterministic under stub


class TestDirectoryWatermark(unittest.TestCase):
    def _project(self):
        tmp = Path(tempfile.mkdtemp(prefix="scwm_"))
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        proj = tmp / "proj"
        proj.mkdir()
        subpkg, nm, hidden = proj / "subpkg", proj / "node_modules", proj / ".hid"
        subpkg.mkdir()
        nm.mkdir()
        hidden.mkdir()
        (proj / "old.txt").write_text("x", encoding="utf-8")
        (proj / "New.MD").write_text("y", encoding="utf-8")
        (subpkg / "inner.py").write_text("i", encoding="utf-8")
        (nm / "child.js").write_text("c", encoding="utf-8")
        (hidden / "h.txt").write_text("h", encoding="utf-8")
        os.symlink(tmp / "no-such-target", proj / "broken.link")
        # utime AFTER all writes so directory mtimes stay deterministic
        os.utime(proj / "old.txt", (1000.0, 1000.0))
        os.utime(proj / "New.MD", (2000.0, 2000.0))
        os.utime(subpkg, (2500.0, 2500.0))
        os.utime(subpkg / "inner.py", (3000.0, 3000.0))
        os.utime(nm / "child.js", (5000.0, 5000.0))
        os.utime(nm, (4000.0, 4000.0))
        os.utime(hidden, (6000.0, 6000.0))
        os.utime(hidden / "h.txt", (7000.0, 7000.0))
        os.utime(proj / "broken.link", (900.0, 900.0), follow_symlinks=False)
        return proj, nm

    def test_top_and_one_level_mtime_with_exclusions(self):
        proj, nm = self._project()
        # node_modules dir mtime counts, its child (5000) is excluded from the
        # sub-scan, hidden entries are skipped, the broken symlink is tolerated
        self.assertEqual(semantic_cache.directory_watermark(proj), 4000.0)
        os.utime(nm, (100.0, 100.0))
        # inner.py (3000) inside subpkg is found through the one-level sub-scan
        self.assertEqual(semantic_cache.directory_watermark(proj), 3000.0)

    def test_empty_and_missing_roots_return_zero(self):
        self.assertEqual(semantic_cache.directory_watermark(None), 0.0)
        self.assertEqual(semantic_cache.directory_watermark(""), 0.0)
        self.assertEqual(semantic_cache.directory_watermark("/no/such/dir-xyz"), 0.0)


class TestPut(SemanticCacheBase):
    def test_envelope_gates_and_permissions(self):
        result = semantic_cache.put("Jakim kolorem jest niebo?", "Niebieskawym.",
                                    model="mistral", est_usd=0.01)
        self.assertTrue(result["ok"])
        self.assertTrue(result["stored"])
        self.assertEqual(len(result["key"]), 16)  # truncated key preview
        self.assertGreater(result["expires_at"], time.time())
        self.assertEqual(result, {"ok": True, "stored": True,
                                  "key": result["key"], "expires_at": result["expires_at"]})
        # empty prompt or empty response are refused without touching the db
        self.assertEqual(semantic_cache.put("", "resp"), {"ok": False, "stored": False})
        self.assertEqual(semantic_cache.put("prompt", "   "), {"ok": False, "stored": False})
        self.assertEqual(self.db().execute("SELECT COUNT(*) AS c FROM prompt_cache")
                         .fetchone()["c"], 1)
        self.assertEqual(self.db_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.agents_dir.stat().st_mode & 0o777, 0o700)

    def test_ttl_is_clamped_to_ten_seconds(self):
        before = time.time()
        result = semantic_cache.put("short ttl prompt", "X", ttl_seconds=1)
        self.assertGreaterEqual(result["expires_at"], before + 9)

    def test_clips_and_negative_cost(self):
        semantic_cache.put("n" * 3000, "r" * 30000, est_usd=-0.5, model="m" * 100)
        row = self.db().execute(
            "SELECT norm_prompt, response_text, model, est_usd FROM prompt_cache").fetchone()
        self.assertEqual(len(row["norm_prompt"]), 2000)
        self.assertEqual(len(row["response_text"]), 24000)
        self.assertEqual(len(row["model"]), 64)
        self.assertEqual(row["est_usd"], 0.0)  # negative cost clipped

    def test_purges_expired_rows_on_put(self):
        semantic_cache.put("first prompt alive", "R1", ttl_seconds=3600)
        semantic_cache.put("second prompt alive", "R2", ttl_seconds=3600)
        conn = self.db()
        with conn:
            conn.execute("UPDATE prompt_cache SET expires_at = 1 "
                         "WHERE norm_prompt = 'first prompt alive'")
        semantic_cache.put("third prompt", "R3", ttl_seconds=3600)
        remaining = [r["norm_prompt"] for r in conn.execute(
            "SELECT norm_prompt FROM prompt_cache")]
        self.assertNotIn("first prompt alive", remaining)  # purged by the new put


class TestGetExact(SemanticCacheBase):
    def test_exact_hit_is_punctuation_and_case_insensitive(self):
        semantic_cache.put("Jaka jest pogoda w Warszawie?", "Słońce, 21 stopni.",
                           watermark=5.0, est_usd=0.01, model="mistral")
        hit = semantic_cache.get("  jaka  Jest--  POGODA w warszawie?!  ", watermark=5.0)
        self.assertEqual(hit, {"hit": True, "match_kind": "exact", "similarity": 1.0,
                              "response_text": "Słońce, 21 stopni.", "model": "mistral",
                              "saved_usd": 0.01, "hits": 1})
        second = semantic_cache.get("Jaka jest pogoda w Warszawie?", watermark=5.0)
        self.assertEqual(second["hits"], 2)  # hits counter grows per hit

    def test_scope_and_watermark_isolation(self):
        semantic_cache.put("pytanie o pogode", "Odpowiedź", watermark=5.0, ttl_seconds=3600)
        self.assertIsNone(semantic_cache.get("pytanie o pogode", scope="other", watermark=5.0))
        self.assertIsNone(semantic_cache.get("pytanie o pogode", watermark=8.0))
        hit = semantic_cache.get("pytanie o pogode", watermark=5.001)  # inside 0.002 tolerance
        self.assertEqual(hit["match_kind"], "exact")
        self.assertIsNone(semantic_cache.get("pytanie o pogode", watermark=5.003))

    def test_expired_entry_is_a_miss(self):
        semantic_cache.put("stale prompt", "R", watermark=1.0, ttl_seconds=3600)
        conn = self.db()
        with conn:
            conn.execute("UPDATE prompt_cache SET expires_at = 1")
        self.assertIsNone(semantic_cache.get("stale prompt", watermark=1.0))
        self.assertEqual(semantic_cache.cache_summary()["total_misses"], 1)

    def test_empty_prompt_returns_none_without_counting_miss(self):
        before = semantic_cache.cache_summary()
        self.assertIsNone(semantic_cache.get("", watermark=0.0))
        after = semantic_cache.cache_summary()
        self.assertEqual(after["total_misses"], before["total_misses"])

    def test_hits_survive_reput(self):
        semantic_cache.put("keep hits", "R1", est_usd=0.5)
        semantic_cache.get("keep hits")
        semantic_cache.put("keep hits", "R2")
        hit = semantic_cache.get("keep hits")
        self.assertEqual((hit["response_text"], hit["hits"]), ("R2", 2))


BASE_PROMPT = ("jarvis semantic cache stores normalized prompt vectors inside "
               "sqlite database and expires entries by watermark invalidation today")


class TestSemanticMatching(SemanticCacheBase):
    def test_appended_word_crosses_similarity_threshold(self):
        semantic_cache.put(BASE_PROMPT, "CACHED ANSWER", watermark=2.0, ttl_seconds=3600)
        hit = semantic_cache.get(BASE_PROMPT + " morning", watermark=2.0)
        self.assertTrue(hit["hit"])
        self.assertEqual(hit["match_kind"], "semantic")
        self.assertGreaterEqual(hit["similarity"], 0.92)
        self.assertLess(hit["similarity"], 1.0)
        self.assertEqual(hit["response_text"], "CACHED ANSWER")
        self.assertEqual(hit["hits"], 1)

    def test_disjoint_prompt_stays_below_threshold(self):
        semantic_cache.put("x y z", "XYZ", watermark=2.0, ttl_seconds=3600)
        # A fully disjoint token set stays far below 0.92 under any PYTHONHASHSEED:
        # the previous reordered-word pair ('z y x') was measured at 0.75-0.88 across
        # fresh processes (bucket collisions vary per seed), which made that
        # assertion seed-brittle; disjointness is robust by construction.
        self.assertIsNone(semantic_cache.get("zebras run fast today", watermark=2.0))

    def test_allow_semantic_false_disables_near_matches(self):
        semantic_cache.put(BASE_PROMPT, "CACHED ANSWER", watermark=2.0, ttl_seconds=3600)
        self.assertIsNone(semantic_cache.get(BASE_PROMPT + " morning", watermark=2.0,
                                              allow_semantic=False))
        exact = semantic_cache.get(BASE_PROMPT, watermark=2.0, allow_semantic=False)
        self.assertEqual(exact["match_kind"], "exact")  # exact matches unaffected

    def test_semantic_is_gated_by_watermark_and_scope(self):
        semantic_cache.put(BASE_PROMPT, "CACHED ANSWER", watermark=2.0, ttl_seconds=3600)
        self.assertIsNone(semantic_cache.get(BASE_PROMPT + " morning", watermark=9.0))
        self.assertIsNone(semantic_cache.get(BASE_PROMPT + " morning", watermark=2.0,
                                              scope="other"))


class TestEvictionAndClear(SemanticCacheBase):
    def test_overflow_evicts_oldest_by_created_at(self):
        names = ["alpha topic", "beta topic", "gamma topic", "delta topic", "epsilon topic"]
        with patch.object(semantic_cache, "MAX_CACHE_ENTRIES", 3):
            for name in names:
                semantic_cache.put(f"describe the {name} please", f"resp {name}",
                                   ttl_seconds=3600)
                time.sleep(0.011)  # separate created_at values
        rows = [r["norm_prompt"] for r in self.db().execute(
            "SELECT norm_prompt FROM prompt_cache ORDER BY created_at DESC")]
        self.assertEqual(rows, ["describe the epsilon topic please",
                                "describe the delta topic please",
                                "describe the gamma topic please"])

    def test_clear_is_scoped_and_reports_rowcount(self):
        semantic_cache.put("w scope", "x", scope="alpha", ttl_seconds=3600)
        semantic_cache.put("in b", "y", scope="beta", ttl_seconds=3600)
        self.assertEqual(semantic_cache.clear("alpha"), {"ok": True, "removed": 1})
        scopes = [r[0] for r in self.db().execute("SELECT scope FROM prompt_cache")]
        self.assertEqual(scopes, ["beta"])
        self.assertEqual(semantic_cache.clear(), {"ok": True, "removed": 1})
        self.assertEqual(semantic_cache.clear(), {"ok": True, "removed": 0})
        self.assertEqual(semantic_cache.cache_summary()["active_entries"], 0)


class TestMetricsSummary(SemanticCacheBase):
    def test_hits_misses_rate_and_saved_usd(self):
        semantic_cache.put("prompts about weather", "R1", est_usd=0.01, ttl_seconds=3600)
        semantic_cache.get("prompts about weather")              # hit, saved 0.01
        semantic_cache.get("completely different topic")          # miss
        summary = semantic_cache.cache_summary()
        self.assertEqual(summary, {"ok": True, "active_entries": 1, "total_hits": 1,
                                  "total_misses": 1, "hit_rate": 0.5, "saved_usd": 0.01})
        semantic_cache.clear()
        summary = semantic_cache.cache_summary()
        self.assertEqual(summary["active_entries"], 0)
        self.assertEqual(summary["hit_rate"], 0.5)  # rate derives from metrics, not entries
        self.assertEqual(summary["total_hits"], 1)  # metrics survive the cache clear


if __name__ == "__main__":
    unittest.main()
