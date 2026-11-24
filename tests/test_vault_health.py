"""Unit tests for `operator_modules/vault_health.py` — audytor sejfu Obsidian.

Modul o ZERO pokrycia przed ta iteracja (897 linii, 6 funkcji publicznych).
Izolacja krytyczna: STATE_ROOT (prawdziwe bazy embeddings na hoscie!) i
BACKUPS_DIR patchowane na tmp per test; _NOTE_CACHE czyszczony (statystyki mtime
moga zbiegac przy szybkich zapisach); vault to wlasne drzewo .md w tmp.
"""
from __future__ import annotations

import shutil
import sys
import unittest
from pathlib import Path
from tempfile import mkdtemp
from unittest import mock

sys.path.insert(0, ".")
sys.path.insert(0, "operator_modules")

import vault_health as vh  # noqa: E402


class VaultHealthBase(unittest.TestCase):
    def setUp(self) -> None:
        self.base = Path(mkdtemp())
        self.addCleanup(shutil.rmtree, self.base, True)
        self.vault = self.base / "vault"
        self.vault.mkdir()
        self.backup_root = self.base / "backups"
        self.backup_root.mkdir()
        self.state_root = self.base / "state"
        patches = [
            mock.patch.object(vh, "STATE_ROOT", self.state_root),
            mock.patch.object(vh, "BACKUPS_DIR", self.backup_root),
            mock.patch.object(vh, "_NOTE_CACHE", {}),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def write_note(self, rel: str, content: str) -> Path:
        p = self.vault / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p


class AuditVaultTests(VaultHealthBase):
    def test_graph_orphans_and_moc_candidates(self):
        self.write_note("A.md", "---\ntitle: \"Nota A\"\n---\nLink do [[B]].\n")
        self.write_note("B.md", "# Nota B\nTreść.\n")
        self.write_note("C.md", "---\ntitle: Samotna\n---\nBrak linków.\n")
        for i in range(4):
            self.write_note(f"Tematy/t{i}.md", f"---\ntitle: T{i} Temat\n---\nTreść.\n")

        res = vh.audit_vault(limit=10, vault=self.vault)
        self.assertTrue(res["ok"])
        self.assertEqual(res["total_notes"], 7)
        self.assertEqual(res["orphan_count"], 5)                      # A-B połączone
        orphan_paths = {o["path"] for o in res["orphans"]}
        self.assertEqual(orphan_paths,
                         {"C.md", "Tematy/t0.md", "Tematy/t1.md", "Tematy/t2.md", "Tematy/t3.md"})
        self.assertEqual(res["moc_candidates"][0]["cluster"], "Tematy")
        self.assertEqual(res["moc_candidates"][0]["note_count"], 4)
        self.assertEqual(res["semantic_duplicates"], [])               # brak embeddings db

    def test_scan_skips_hidden_and_external_symlinks(self):
        self.write_note("ok.md", "---\ntitle: Ok\n---\nTreść.\n")
        self.write_note(".obsidian/config.md", "ukryte\n")
        self.write_note(".trash/old.md", "kosz\n")
        outside = self.base / "outside.md"
        outside.write_text("poza vault", encoding="utf-8")
        link = self.vault / "symlink.md"
        link.symlink_to(outside)
        res = vh.audit_vault(limit=10, vault=self.vault)
        self.assertEqual(res["total_notes"], 1)
        self.assertEqual(res["orphans"][0]["path"], "ok.md")

    def test_audit_missing_vault(self):
        self.write_note("x.md", "x")                                  # vault istnieje wiec...
        res = vh.audit_vault(limit=5, vault=self.base / "nie-ma")
        self.assertEqual(res["total_notes"], 0)                       # pusty skan, ok=True


class SynthesizeMocTests(VaultHealthBase):
    def test_validation_paths(self):
        self.assertFalse(vh.synthesize_moc("", vault=self.vault)["ok"])
        self.assertFalse(vh.synthesize_moc("   ", vault=self.vault)["ok"])
        res = vh.synthesize_moc("nieistniejacy-temat-xyz", vault=self.vault)
        self.assertFalse(res["ok"])
        self.assertIn("No notes matched", res["error"])

    def test_scoring_markdown_and_write_with_backup_on_overwrite(self):
        self.write_note("C.md", "---\ntitle: Solar Panel\n---\nKolektor słoneczny.\n")
        res = vh.synthesize_moc("solar", vault=self.vault)
        self.assertTrue(res["ok"])
        self.assertEqual(res["matched_count"], 1)
        self.assertEqual(res["filename"], "MOC - solar.md")
        self.assertFalse(res["written"])
        self.assertIn("type: moc", res["markdown"])
        self.assertIn("# MOC: solar", res["markdown"])
        self.assertIn("[[C|Solar Panel]]", res["markdown"])

        res2 = vh.synthesize_moc("solar", vault=self.vault, write=True,
                                 backup_root=self.backup_root)
        self.assertTrue(res2["written"])
        saved = Path(res2["saved_path"])
        self.assertTrue(saved.is_file())
        self.assertFalse(res2["backup"])                              # nowy plik bez backupu

        res3 = vh.synthesize_moc("solar", vault=self.vault, write=True,
                                 backup_root=self.backup_root)
        self.assertTrue(res3["backup"])                               # nadpis -> backup
        self.assertTrue(Path(res3["backup"]).is_file())

    def test_atomic_write_guards(self):
        with self.assertRaises(ValueError):
            vh._atomic_vault_write(self.vault, "../escape.md", "x")
        with self.assertRaises(ValueError):
            vh._atomic_vault_write(self.vault, "../x", "x")
        with self.assertRaises(ValueError):
            vh._atomic_vault_write(self.vault, "sub/../x.md", "x")
        with self.assertRaises(ValueError):
            vh._atomic_vault_write(self.base / "nie-ma", "x.md", "x")
        (self.vault / "linksym").symlink_to(self.backup_root)
        with self.assertRaises(ValueError):
            vh._atomic_vault_write(self.vault, "linksym", "x")
        (self.vault / "reg.md").write_text("y", encoding="utf-8")
        (self.vault / "dir.md").mkdir()
        with self.assertRaises(ValueError):
            vh._atomic_vault_write(self.vault, "dir.md", "x")        # katalog zamiast pliku


class AutoLinkTests(VaultHealthBase):
    def test_preview_and_apply_with_wikilink_label(self):
        self.write_note("C.md", "---\ntitle: Solar Panel\n---\nTreść solar.\n")
        self.write_note("D.md", "Wzmianka o Solar Panel bez linku.\n")

        res = vh.auto_link_vault(vault=self.vault, limit=10, write=False)
        self.assertTrue(res["ok"])
        self.assertEqual(res["mode"], "preview")
        self.assertEqual(res["files_with_candidates"], 1)
        self.assertEqual(res["changes"][0]["source"], "D.md")
        self.assertFalse(res["changes"][0]["written"])
        self.assertEqual((self.vault / "D.md").read_text(encoding="utf-8"),
                         "Wzmianka o Solar Panel bez linku.\n")        # preview nie rusza

        res2 = vh.auto_link_vault(vault=self.vault, limit=10, write=True,
                                  backup_root=self.backup_root)
        self.assertEqual(res2["mode"], "applied")
        self.assertEqual(res2["files_modified"], 1)
        self.assertEqual(res2["changes"][0]["linked_targets"], ["C.md"])
        self.assertTrue(res2["backups"])                              # nadpisano istniejacy D.md

    def test_injection_respects_protected_spans(self):
        """Kodem, wikilink, naglowek i URL odporne na podmiane (pragma antywstrzyknieciowy)."""
        self.write_note("B.md", "---\ntitle: Celnik\n---\nopis\n")
        note_text = (
            "# Nagłówek z Celnik\n"                                    # naglowek — chroniony
            "```\nCelnik w bloku kodu\n```\n"                          # code span — chroniony
            "Mention `Celnik` inline.\n"                              # inline code — chroniony
            "Zwykłe zdanie o Celnik w tekście.\n"                     # DO podmiany
        )
        self.write_note("A.md", note_text)
        res = vh.auto_link_vault(vault=self.vault, limit=10, write=True,
                                 backup_root=self.backup_root)
        updated = (self.vault / "A.md").read_text(encoding="utf-8")
        self.assertEqual(res["files_modified"], 1)
        self.assertIn("# Nagłówek z Celnik\n", updated)                # naglowek nietkniety
        self.assertIn("Celnik w bloku kodu\n```", updated)             # blok nietkniety
        self.assertIn("`Celnik` inline.", updated)                    # inline nietkniety
        self.assertIn("Zwykłe zdanie o [[B|Celnik]] w tekście.", updated)

    def test_missing_vault(self):
        res = vh.auto_link_vault(vault=self.base / "pusto", limit=5)
        self.assertFalse(res["ok"])
        self.assertIn("does not exist", res["error"])


class ClusterOrphansTests(VaultHealthBase):
    def test_token_fallback_single_cluster(self):
        for i in range(3):
            self.write_note(f"o{i}.md",
                            f"---\ntitle: Orfans{i} Kolektor\n---\n"
                            f"Kolektor słoneczny instalacja numer {i}.\n")
        res = vh.cluster_orphans(vault=self.vault, threshold=0.9, write=False)
        self.assertTrue(res["ok"])
        self.assertEqual(res["orphan_count"], 3)
        self.assertEqual(res["cluster_count"], 1)
        cluster = res["clusters"][0]
        self.assertEqual(cluster["note_count"], 3)
        self.assertFalse(cluster["written"])
        self.assertEqual(res["written_mocs"], [])

    def test_single_orphan_yields_no_clusters(self):
        self.write_note("solo.md", "---\ntitle: Solo\n---\nTreść.\n")
        res = vh.cluster_orphans(vault=self.vault)
        self.assertEqual(res["cluster_count"], 0)
        self.assertEqual(res["orphan_count"], 1)
        self.assertEqual(res["clusters"], [])

    def test_write_mode_appends_to_written_mocs(self):
        for i in range(2):
            self.write_note(f"w{i}.md",
                            f"---\ntitle: Wektor{i} Silnik\n---\nSilnik spalinowy wytwarza moment obrotowy {i}.\n")
        res = vh.cluster_orphans(vault=self.vault, threshold=0.95, write=True,
                                backup_root=self.backup_root)
        self.assertEqual(res["cluster_count"], 1)
        self.assertEqual(len(res["written_mocs"]), 1)
        saved = Path(res["written_mocs"][0])
        self.assertTrue(saved.is_file())
        self.assertIn("Silnik", saved.read_text(encoding="utf-8"))


class DetectContradictionsTests(VaultHealthBase):
    def test_conflicting_facts_across_related_notes(self):
        self.write_note("e1.md",
                        "---\ntitle: Bateria litowa\nstatus: sprawna\npower: 100W\n---\n"
                        "Bateria litowa w obudowie.\n")
        self.write_note("e2.md",
                        "---\ntitle: Bateria litowa v2\nstatus: zepsuta\npower: 200W\n---\n"
                        "Bateria litowa po wymianie.\n")
        res = vh.detect_contradictions(vault=self.vault)
        self.assertTrue(res["ok"])
        self.assertEqual(res["count"], 2)
        fields = {c["field"] for c in res["contradictions"]}
        self.assertEqual(fields, {"power", "status"})
        by_field = {c["field"]: c for c in res["contradictions"]}
        self.assertEqual(by_field["power"]["value_a"], "100W")
        self.assertEqual(by_field["power"]["value_b"], "200W")

    def test_agreeing_values_and_too_few_notes(self):
        self.write_note("jeden.md", "---\ntitle: X\nk: 1\n---\ntreść\n")
        self.assertEqual(vh.detect_contradictions(vault=self.vault)["count"], 0)  # 1 nota
        self.write_note("dwa-a.md", "---\ntitle: A\nk: 5\n---\ntreść\n")
        self.write_note("dwa-b.md", "---\ntitle: B\nk: 5\n---\ntreść inna dziedzina\n")
        # identyczne wartosci -> zero kontradycji
        self.assertEqual(vh.detect_contradictions(vault=self.vault)["count"], 0)

    def test_missing_vault(self):
        self.assertFalse(vh.detect_contradictions(vault=self.base / "brak")["ok"])


class HandlerTests(VaultHealthBase):
    def test_dispatch_and_validation(self):
        self.write_note("h.md", "---\ntitle: H testowy\n---\nTreść testowa.\n")
        with mock.patch.object(vh, "audit_vault", return_value={"ok": True, "spy": 1}) as spy:
            res = vh.vault_health_handler({"action": "audit", "limit": 999})
            self.assertEqual(res["spy"], 1)
            self.assertEqual(spy.call_args.kwargs["limit"], 50)      # clamp limit 50

        res = vh.vault_health_handler({"action": "audit", "limit": "x"})
        self.assertFalse(res["ok"])
        self.assertIn("must be an integer", res["error"])

        with mock.patch.object(vh, "cluster_orphans", return_value={"ok": True, "t": 1}) as spy:
            res = vh.vault_health_handler({"action": "cluster_orphans", "threshold": 5.0})
            self.assertEqual(spy.call_args.kwargs["threshold"], 0.99)   # clamp gorny
            res = vh.vault_health_handler({"action": "cluster_orphans", "threshold": 0.1})
            self.assertEqual(spy.call_args.kwargs["threshold"], 0.3)    # clamp dolny
            res = vh.vault_health_handler({"action": "cluster_orphans", "threshold": "abc"})
        self.assertFalse(res["ok"])
        self.assertIn("must be a number", res["error"])

        res = vh.vault_health_handler({"action": "nieznana"})
        self.assertIn("Unsupported action", res["error"])

    def test_approval_predicate_matrix(self):
        self.assertTrue(vh._requires_approval({"action": "synthesize_moc", "write": True}))
        self.assertTrue(vh._requires_approval({"action": "auto_link", "write": True}))
        self.assertTrue(vh._requires_approval({"action": "cluster_orphans", "write": True}))
        self.assertFalse(vh._requires_approval({"action": "synthesize_moc", "write": False}))
        self.assertFalse(vh._requires_approval({"action": "audit", "write": True}))
        self.assertFalse(vh._requires_approval({"action": "contradictions", "write": True}))
        self.assertFalse(vh._requires_approval({}))
        self.assertFalse(vh._requires_approval(None))


if __name__ == "__main__":
    unittest.main()
