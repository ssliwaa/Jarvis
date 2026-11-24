"""Unit tests for BM25 score presentation in context packs (P4 feature, iteracja BE).

`episodic_memory.recall_episodes` od dawna liczyla score BM25, ale
`code_index.build_context_pack` tracil te wartosc przy budowie Markdown. Now:
trafność jest wypisywana przy epizodach FTS; epizody bez score (latest) i score
nienumeryczne pozostaja bez etykiety. Izolacja: episodic_memory/agent_notes
wstrzykiwane falszywami przez patch.dict(sys.modules) (importy wewnatrz funkcji);
search_context bez root_dir zwraca 0 trafien, wiec pack buduja tylko epizody.
"""
from __future__ import annotations

import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, ".")

import code_index  # noqa: E402


def _episode(**overrides) -> dict:
    base = {"kind": "decision", "title": "Tytul", "summary": "opis"}
    base.update(overrides)
    return base


def _pack(episodes: list[dict], notes: list | None = None) -> str:
    fake_ep = SimpleNamespace(recall_episodes=lambda q, limit: episodes)
    fake_notes = SimpleNamespace(search=lambda q: notes if notes is not None else [])
    with mock.patch.dict(sys.modules, {"episodic_memory": fake_ep,
                                       "agent_notes": fake_notes}), \
            mock.patch.object(code_index, "search_context", return_value=[]):
        return code_index.build_context_pack("jakie kolwiek zadanie", root_dir=None)


class ContextPackEpisodeScoreTests(unittest.TestCase):
    def test_search_score_presented_with_full_precision(self):
        pack = _pack([_episode(score=2.31), _episode(score=0.00175)])
        self.assertIn("**Tytul** (trafność: 2.31): opis", pack)
        self.assertIn("**Tytul** (trafność: 0.00175): opis", pack)

    def test_zero_score_is_still_presented(self):
        """BM25 moze dac 0.0 (pin: min_score filtr >= przepuszcza zera) — i to widac."""
        pack = _pack([_episode(score=0.0)])
        self.assertIn("(trafność: 0.0)", pack)

    def test_latest_episodes_without_score_have_no_label(self):
        pack = _pack([_episode()])                       # bez klucza score
        self.assertIn("[decision] **Tytul**: opis", pack)
        self.assertNotIn("trafność", pack)

    def test_non_numeric_score_is_ignored_gracefully(self):
        pack = _pack([_episode(score="2.31"), _episode(score=None)])
        self.assertNotIn("trafność", pack)
        self.assertEqual(pack.count("[decision] **Tytul**"), 2)   # oba wypisane

    def test_missing_fields_use_defaults(self):
        """Zachowanie istniejace (przed ta iteracja tez): None drukowany jako tekst."""
        pack = _pack([{"title": None, "summary": None, "score": 1.5}])
        self.assertIn("[note] **None** (trafność: 1.5): None", pack)

    def test_empty_recall_returns_empty_pack(self):
        self.assertEqual(_pack([]), "")

    def test_notes_section_still_works_alongside(self):
        pack = _pack([_episode(score=3.0)],
                     notes=[{"title": "Notatka A", "path": "n.md"}])
        self.assertIn("(trafność: 3.0)", pack)
        self.assertIn("Powiązane wcześniejsze notatki agentów", pack)
        self.assertIn("- Notatka A", pack)


if __name__ == "__main__":
    unittest.main()
