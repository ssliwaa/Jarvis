"""Automated test suite for operator_modules/op_state_graph.py.

Tests the dispatch contract, db_path security guardrails (ALLOWED_ROOTS
perimeter, sensitive-path blocklist, default /tmp database), graph CRUD
(create_graph upsert semantics, add_node, add_edge condition persistence),
single stepping (override, state_delta merge, conditional edge routing,
terminal handling), run_graph loops (linear completion, cycle with
max_steps guardrail, bounds validation), checkpointing (custom save,
rollback by checkpoint_id and by step number, not-found errors), and
list/get/reset actions. Fully isolated: every test uses its own
TemporaryDirectory SQLite database; the default-db test uses a unique
graph_id and resets it afterwards (WAL + 30 s timeout handle concurrent
suites safely).
"""

from __future__ import annotations

import tempfile
import unittest
import uuid

import operator_modules.op_state_graph as sg


def _gid(prefix: str = "g") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


class TestDispatch(unittest.TestCase):
    """Handler contract: argument validation and action routing."""

    def test_rejects_non_dict_arguments(self):
        res = sg.state_graph("nope")
        self.assertFalse(res["ok"])
        self.assertIn("Arguments must be a dictionary", res["error"])

    def test_rejects_unknown_argument(self):
        with tempfile.TemporaryDirectory() as td:
            res = sg.state_graph({"action": "get_state", "graph_id": _gid(),
                                  "db_path": td + "/db.sqlite3", "rogue": 1})
        self.assertFalse(res["ok"])
        self.assertIn("Unknown argument 'rogue'", res["error"])

    def test_missing_action_is_error(self):
        with tempfile.TemporaryDirectory() as td:
            res = sg.state_graph({"graph_id": _gid(),
                                  "db_path": td + "/db.sqlite3"})
        self.assertFalse(res["ok"])
        self.assertIn("Missing required parameter 'action'", res["error"])

    def test_invalid_action_is_error(self):
        with tempfile.TemporaryDirectory() as td:
            res = sg.state_graph({"action": "explode", "graph_id": _gid(),
                                  "db_path": td + "/db.sqlite3"})
        self.assertFalse(res["ok"])
        self.assertIn("Invalid or unsupported action 'explode'", res["error"])

    def test_success_envelope_shape(self):
        with tempfile.TemporaryDirectory() as td:
            res = sg.state_graph({"action": "create_graph",
                                  "graph_id": _gid(), "initial_state": {},
                                  "db_path": td + "/db.sqlite3"})
        self.assertEqual(set(res), {"ok", "success", "data", "result", "error"})
        self.assertTrue(res["ok"])
        self.assertTrue(res["success"])
        self.assertIsNone(res["error"])
        self.assertEqual(res["data"], res["result"])


class TestDbPathGuardrails(unittest.TestCase):
    """db_path validation: perimeter, sensitive blocklist, default path."""

    def test_outside_allowed_roots_rejected(self):
        res = sg.state_graph({"action": "create_graph", "graph_id": _gid(),
                              "db_path": "/proc/forbidden/db.sqlite3"})
        self.assertFalse(res["ok"])
        self.assertIn("PathSecurityError", res["error"])
        self.assertIn("outside allowed roots", res["error"])

    def test_sensitive_path_rejected(self):
        res = sg.state_graph({"action": "create_graph", "graph_id": _gid(),
                              "db_path": "/tmp/sg_probe/.ssh/db.sqlite3"})
        self.assertFalse(res["ok"])
        self.assertIn("SensitivePathError", res["error"])

    def test_default_db_path_is_shared_tmp(self):
        gid = _gid("defaultdb")
        try:
            res = sg.state_graph({"action": "create_graph",
                                  "graph_id": gid, "initial_state": {}})
            self.assertTrue(res["ok"])
            self.assertTrue(res["data"]["db_path"].endswith(
                "jarvis_state_graphs.sqlite3"))
        finally:
            cleanup = sg.state_graph({"action": "reset", "graph_id": gid})
            self.assertTrue(cleanup["ok"])


class TestCreateGraph(unittest.TestCase):
    """create_graph/init: validation, checkpoint seed, upsert semantics."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.db = self._td.name + "/db.sqlite3"

    def tearDown(self):
        self._td.cleanup()

    def test_init_with_custom_start_node(self):
        gid = _gid()
        res = sg.state_graph({"action": "create_graph", "graph_id": gid,
                              "initial_state": {"alpha": 1},
                              "node_name": "ORIGIN", "db_path": self.db})
        data = res["data"]
        self.assertTrue(res["ok"])
        self.assertEqual(data["status"], "initialized")
        self.assertEqual(data["current_node"], "ORIGIN")
        self.assertEqual(data["current_step"], 0)
        self.assertEqual(data["state"], {"alpha": 1})
        self.assertTrue(data["checkpoint_id"].startswith("chk_0_"))

    def test_init_requires_nonempty_graph_id(self):
        res = sg.state_graph({"action": "init", "graph_id": "",
                              "db_path": self.db})
        self.assertFalse(res["ok"])
        self.assertIn("'graph_id' must be a non-empty string", res["error"])

    def test_init_requires_state_dictionary(self):
        res = sg.state_graph({"action": "create_graph", "graph_id": _gid(),
                              "initial_state": "not-a-dict",
                              "db_path": self.db})
        self.assertFalse(res["ok"])
        self.assertIn("'initial_state' must be a dictionary", res["error"])

    def test_reinit_upserts_existing_graph(self):
        gid = _gid()
        sg.state_graph({"action": "create_graph", "graph_id": gid,
                        "initial_state": {"counter": 0},
                        "db_path": self.db})
        sg.state_graph({"action": "step", "graph_id": gid,
                        "node_name": "somewhere", "db_path": self.db})
        res = sg.state_graph({"action": "init", "graph_id": gid,
                              "initial_state": {"counter": 99},
                              "db_path": self.db})
        data = res["data"]
        self.assertTrue(res["ok"])
        self.assertEqual(data["state"], {"counter": 99})
        self.assertEqual(data["current_step"], 0)
        self.assertEqual(data["current_node"], "START")
        # Old start checkpoint preserved, new one appended
        r2 = sg.state_graph({"action": "get_state", "graph_id": gid,
                             "db_path": self.db})
        self.assertEqual(r2["data"]["state"], {"counter": 99})


class TestNodesAndEdges(unittest.TestCase):
    """add_node/add_edge: graph existence check, auto-node creation."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.db = self._td.name + "/db.sqlite3"
        self.gid = _gid()
        sg.state_graph({"action": "create_graph", "graph_id": self.gid,
                        "initial_state": {}, "db_path": self.db})

    def tearDown(self):
        self._td.cleanup()

    def test_add_node_requires_existing_graph(self):
        res = sg.state_graph({"action": "add_node", "graph_id": _gid("ghost"),
                              "node_name": "n1", "db_path": self.db})
        self.assertFalse(res["ok"])
        self.assertIn("does not exist", res["error"])
        self.assertIn("create_graph first", res["error"])

    def test_add_node_success(self):
        res = sg.state_graph({"action": "add_node", "graph_id": self.gid,
                              "node_name": "process", "db_path": self.db})
        data = res["data"]
        self.assertTrue(res["ok"])
        self.assertEqual(data["node_name"], "process")
        self.assertEqual(data["status"], "node_added")

    def test_add_edge_persists_condition_and_autocreates_nodes(self):
        cond = {"field": "status", "op": "==", "value": "ready"}
        res = sg.state_graph({"action": "add_edge", "graph_id": self.gid,
                              "node_name": "START", "target_node": "work",
                              "condition": cond, "db_path": self.db})
        data = res["data"]
        self.assertTrue(res["ok"])
        self.assertEqual(data["status"], "edge_added")
        self.assertEqual(data["condition"], cond)
        # Routing honours the persisted condition
        sg.state_graph({"action": "step", "graph_id": self.gid,
                        "state_delta": {"status": "ready"},
                        "db_path": self.db})
        r2 = sg.state_graph({"action": "get_state", "graph_id": self.gid,
                             "db_path": self.db})
        self.assertEqual(r2["data"]["current_node"], "work")


class TestStep(unittest.TestCase):
    """step: override, delta merge, conditional routing, terminal guard."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.db = self._td.name + "/db.sqlite3"
        self.gid = _gid()
        sg.state_graph({"action": "create_graph", "graph_id": self.gid,
                        "initial_state": {"counter": 5},
                        "db_path": self.db})

    def tearDown(self):
        self._td.cleanup()

    def test_step_with_explicit_override_node(self):
        res = sg.state_graph({"action": "step", "graph_id": self.gid,
                              "node_name": "manual_target",
                              "db_path": self.db})
        data = res["data"]
        self.assertTrue(res["ok"])
        self.assertEqual(data["previous_node"], "START")
        self.assertEqual(data["current_node"], "manual_target")
        self.assertEqual(data["current_step"], 1)
        self.assertTrue(data["checkpoint_id"].startswith("chk_1_"))
        self.assertFalse(data["is_terminal"])

    def test_step_merges_state_delta(self):
        res = sg.state_graph({"action": "step", "graph_id": self.gid,
                              "node_name": "n",
                              "state_delta": {"counter": 6, "extra": True},
                              "db_path": self.db})
        self.assertEqual(res["data"]["state"],
                         {"counter": 6, "extra": True})

    def test_step_routes_by_first_matching_condition(self):
        sg.state_graph({"action": "add_edge", "graph_id": self.gid,
                        "node_name": "START", "target_node": "slow_lane",
                        "condition": {"field": "counter", "op": ">", "value": 100},
                        "db_path": self.db})
        sg.state_graph({"action": "add_edge", "graph_id": self.gid,
                        "node_name": "START", "target_node": "fast_lane",
                        "condition": {"field": "counter", "op": "<", "value": 100},
                        "db_path": self.db})
        res = sg.state_graph({"action": "step", "graph_id": self.gid,
                              "db_path": self.db})
        self.assertEqual(res["data"]["current_node"], "fast_lane")

    def test_step_without_edges_goes_to_end(self):
        res = sg.state_graph({"action": "step", "graph_id": self.gid,
                              "db_path": self.db})
        data = res["data"]
        self.assertEqual(data["current_node"], "END")
        self.assertTrue(data["is_terminal"])
        self.assertEqual(data["status"], "completed")
        # Stepping a completed graph returns terminal guard message
        res2 = sg.state_graph({"action": "step", "graph_id": self.gid,
                               "db_path": self.db})
        self.assertTrue(res2["data"]["is_terminal"])
        self.assertIn("already completed", res2["data"]["message"])

    def test_step_requires_existing_graph(self):
        res = sg.state_graph({"action": "step", "graph_id": _gid("ghost"),
                              "db_path": self.db})
        self.assertFalse(res["ok"])
        self.assertIn("does not exist", res["error"])


class TestRunGraph(unittest.TestCase):
    """run_graph/run_until_complete: loops, cycles, max_steps bounds."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.db = self._td.name + "/db.sqlite3"

    def tearDown(self):
        self._td.cleanup()

    @staticmethod
    def _linear(gid, db):
        sg.state_graph({"action": "create_graph", "graph_id": gid,
                        "initial_state": {}, "db_path": db})
        sg.state_graph({"action": "add_edge", "graph_id": gid,
                        "node_name": "START", "target_node": "A",
                        "db_path": db})
        sg.state_graph({"action": "add_edge", "graph_id": gid,
                        "node_name": "A", "target_node": "END",
                        "db_path": db})

    def test_linear_run_completes_with_history(self):
        gid = _gid("lin")
        self._linear(gid, self.db)
        res = sg.state_graph({"action": "run_graph", "graph_id": gid,
                              "db_path": self.db})
        data = res["data"]
        self.assertTrue(res["ok"])
        self.assertEqual(data["steps_executed"], 2)
        self.assertEqual(data["current_node"], "END")
        self.assertEqual(data["status"], "completed")
        self.assertTrue(data["is_terminal"])
        self.assertEqual(len(data["history"]), 2)
        self.assertEqual(data["history"][0]["to_node"], "A")
        self.assertEqual(data["history"][1]["to_node"], "END")

    def test_cycle_stops_at_max_steps(self):
        gid = _gid("cyc")
        sg.state_graph({"action": "create_graph", "graph_id": gid,
                        "initial_state": {}, "db_path": self.db})
        for src, dst in (("START", "A"), ("A", "B"), ("B", "A")):
            sg.state_graph({"action": "add_edge", "graph_id": gid,
                            "node_name": src, "target_node": dst,
                            "db_path": self.db})
        res = sg.state_graph({"action": "run_until_complete",
                              "graph_id": gid, "max_steps": 5,
                              "db_path": self.db})
        data = res["data"]
        self.assertEqual(data["steps_executed"], 5)
        self.assertEqual(data["current_node"], "A")
        self.assertEqual(data["status"], "running")
        self.assertFalse(data["is_terminal"])
        self.assertEqual(len(data["history"]), 5)

    def test_max_steps_bounds_validated(self):
        gid = _gid("lin")
        self._linear(gid, self.db)
        res0 = sg.state_graph({"action": "run_graph", "graph_id": gid,
                               "max_steps": 0, "db_path": self.db})
        self.assertFalse(res0["ok"])
        self.assertIn("between 1 and 500", res0["error"])
        res501 = sg.state_graph({"action": "run_graph", "graph_id": gid,
                                 "max_steps": 501, "db_path": self.db})
        self.assertFalse(res501["ok"])


class TestCheckpoints(unittest.TestCase):
    """save/rollback: custom ids, digit-step targeting, not-found errors."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.db = self._td.name + "/db.sqlite3"
        self.gid = _gid("chk")
        sg.state_graph({"action": "create_graph", "graph_id": self.gid,
                        "initial_state": {"v": 1}, "db_path": self.db})
        sg.state_graph({"action": "add_edge", "graph_id": self.gid,
                        "node_name": "START", "target_node": "work",
                        "db_path": self.db})
        sg.state_graph({"action": "add_edge", "graph_id": self.gid,
                        "node_name": "work", "target_node": "END",
                        "db_path": self.db})
        sg.state_graph({"action": "add_edge", "graph_id": self.gid,
                        "node_name": "START", "target_node": "work",
                        "db_path": self.db})

    def tearDown(self):
        self._td.cleanup()

    def test_save_checkpoint_with_custom_id(self):
        res = sg.state_graph({"action": "save_checkpoint",
                              "graph_id": self.gid,
                              "checkpoint_id": "milestone_ok",
                              "db_path": self.db})
        data = res["data"]
        self.assertTrue(res["ok"])
        self.assertEqual(data["checkpoint_id"], "milestone_ok")
        self.assertEqual(data["step"], 0)
        self.assertEqual(data["node"], "START")
        self.assertTrue(data["saved"])

    def test_rollback_by_checkpoint_id(self):
        sg.state_graph({"action": "save_checkpoint",
                        "graph_id": self.gid,
                        "checkpoint_id": "milestone_ok",
                        "db_path": self.db})
        sg.state_graph({"action": "step", "graph_id": self.gid,
                        "db_path": self.db})
        self.assertEqual(
            sg.state_graph({"action": "step", "graph_id": self.gid,
                            "db_path": self.db})["data"]["status"],
            "completed")
        res = sg.state_graph({"action": "rollback", "graph_id": self.gid,
                              "checkpoint_id": "milestone_ok",
                              "db_path": self.db})
        data = res["data"]
        self.assertTrue(res["ok"])
        self.assertEqual(data["status"], "rolled_back")
        self.assertEqual(data["current_step"], 0)
        self.assertEqual(data["current_node"], "START")
        self.assertEqual(data["state"], {"v": 1})

    def test_rollback_by_step_number_selects_latest(self):
        run = sg.state_graph({"action": "run_graph", "graph_id": self.gid,
                              "db_path": self.db})
        self.assertEqual(run["data"]["current_node"], "END")
        res = sg.state_graph({"action": "rollback_checkpoint",
                              "graph_id": self.gid, "checkpoint_id": "1",
                              "db_path": self.db})
        data = res["data"]
        self.assertTrue(res["ok"])
        self.assertEqual(data["current_step"], 1)
        self.assertEqual(data["current_node"], "work")

    def test_rollback_errors(self):
        res_missing = sg.state_graph({"action": "rollback",
                                      "graph_id": self.gid,
                                      "db_path": self.db})
        self.assertFalse(res_missing["ok"])
        self.assertIn("'checkpoint_id' must be specified",
                      res_missing["error"])
        res_404 = sg.state_graph({"action": "rollback",
                                  "graph_id": self.gid,
                                  "checkpoint_id": "chk_nope",
                                  "db_path": self.db})
        self.assertFalse(res_404["ok"])
        self.assertIn("not found", res_404["error"])


class TestListGetReset(unittest.TestCase):
    """list_checkpoints/get_state/reset: inspection and lifecycle."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.db = self._td.name + "/db.sqlite3"
        self.gid = _gid("mgr")
        sg.state_graph({"action": "create_graph", "graph_id": self.gid,
                        "initial_state": {"alpha": 1}, "db_path": self.db})

    def tearDown(self):
        self._td.cleanup()

    def test_get_state_returns_full_snapshot(self):
        res = sg.state_graph({"action": "get_state", "graph_id": self.gid,
                              "db_path": self.db})
        data = res["data"]
        self.assertTrue(res["ok"])
        self.assertEqual(data["current_node"], "START")
        self.assertEqual(data["current_step"], 0)
        self.assertEqual(data["state"], {"alpha": 1})
        self.assertEqual(data["status"], "running")
        self.assertIn("created_at", data)
        self.assertIn("updated_at", data)

    def test_list_checkpoints_reports_state_keys(self):
        res = sg.state_graph({"action": "list_checkpoints",
                              "graph_id": self.gid, "db_path": self.db})
        data = res["data"]
        self.assertTrue(res["ok"])
        self.assertEqual(data["count"], 1)
        chk = data["checkpoints"][0]
        self.assertEqual(chk["step"], 0)
        self.assertEqual(chk["node"], "START")
        self.assertEqual(chk["state_keys"], ["alpha"])
        self.assertTrue(chk["checkpoint_id"].startswith("chk_0_"))

    def test_reset_clears_graph_and_checkpoints(self):
        sg.state_graph({"action": "step", "graph_id": self.gid,
                        "db_path": self.db})
        res = sg.state_graph({"action": "reset", "graph_id": self.gid,
                              "db_path": self.db})
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["status"], "reset_complete")
        # Graph is gone after reset
        res2 = sg.state_graph({"action": "get_state", "graph_id": self.gid,
                               "db_path": self.db})
        self.assertFalse(res2["ok"])
        self.assertIn("does not exist", res2["error"])
        # list_checkpoints on removed graph also errors
        res3 = sg.state_graph({"action": "list_checkpoints",
                              "graph_id": self.gid, "db_path": self.db})
        self.assertFalse(res3["ok"])

    def test_get_state_requires_existing_graph(self):
        res = sg.state_graph({"action": "get_state",
                              "graph_id": _gid("ghost"),
                              "db_path": self.db})
        self.assertFalse(res["ok"])
        self.assertIn("does not exist", res["error"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
