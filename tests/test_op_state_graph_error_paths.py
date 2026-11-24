"""ERROR-path coverage tests for operator_modules/op_state_graph.py.

Second wave of the sys.settrace audit, module two: 16 raise sites
with half never executed - all in the graph grammar (db_path
hygiene, graph_id and node naming, step state deltas). Every call
pins db_path inside a per-test tmp directory; the /tmp default
location is never allowed to leak between tests.
"""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import operator_modules.op_state_graph as sg


class StateGraphCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.db_path = self.tmp / "graphs.sqlite3"

    def call(self, **kwargs):
        kwargs.setdefault("db_path", str(self.db_path))
        return sg.state_graph(kwargs)

    def bad(self, fragment, **kwargs):
        result = self.call(**kwargs)
        self.assertFalse(result["ok"], msg=str(result.get("error")))
        self.assertIn(fragment, result["error"])
        return result

    def create_graph(self, graph_id="g1", **kwargs):
        result = self.call(action="create_graph", graph_id=graph_id,
                           **kwargs)
        self.assertTrue(result["ok"], msg=str(result.get("error")))
        return result


class DbPathGuardTests(StateGraphCase):
    def test_null_byte_in_db_path(self):
        self.bad("exceeds length limit or contains null bytes",
                 action="list_checkpoints", db_path="store\x00.sqlite3")

    def test_oversized_db_path_string(self):
        self.bad("exceeds length limit or contains null bytes",
                 action="list_checkpoints", db_path="x" * 4097)

    def test_non_string_db_path(self):
        self.bad("Parameter 'db_path' must be a valid string.",
                 action="list_checkpoints", db_path=12345)

    def test_resolution_failure_is_wrapped(self):
        with patch.object(sg.os.path, "realpath",
                          side_effect=OSError("boom")):
            with self.assertRaises(ValueError) as ctx:
                sg._validate_and_resolve_db_path("/tmp/store.sqlite3")
        message = str(ctx.exception)
        self.assertIn("Path resolution error for db_path", message)
        self.assertIn("boom", message)


class GraphGrammarTests(StateGraphCase):
    def test_missing_graph_id(self):
        self.bad("Parameter 'graph_id' must be specified.",
                 action="add_node")

    def test_add_node_requires_non_empty_name(self):
        self.create_graph()
        self.bad("Parameter 'node_name' must be a non-empty string.",
                 action="add_node", graph_id="g1")

    def test_add_edge_requires_non_empty_source(self):
        self.create_graph()
        self.bad("Parameter 'node_name' (source) must be a non-empty "
                 "string.",
                 action="add_edge", graph_id="g1", target_node="end")

    def test_add_edge_requires_non_empty_target(self):
        self.create_graph()
        self.bad("Parameter 'target_node' must be a non-empty string.",
                 action="add_edge", graph_id="g1", node_name="start")

    def test_step_requires_state_delta_dictionary(self):
        self.create_graph()
        self.bad("Parameter 'state_delta' must be a dictionary.",
                 action="step", graph_id="g1", state_delta=[1, 2, 3])

    def test_whitespace_graph_id_on_create_is_tolerated(self):
        # Characterization: the create branch checks truthiness, not
        # stripped content, so a whitespace-only graph_id creates a
        # graph literally named "  ". Documented as-is; harmless but
        # worth knowing before any naming hardening pass.
        result = self.call(action="create_graph", graph_id="  ")
        self.assertTrue(result["ok"], msg=str(result.get("error")))
        self.assertEqual(result["data"]["graph_id"], "  ")

    def test_happy_add_node_and_edge_for_contrast(self):
        self.create_graph()
        node = self.call(action="add_node", graph_id="g1",
                         node_name="decision")
        edge = self.call(action="add_edge", graph_id="g1",
                         node_name="decision", target_node="END")
        self.assertTrue(node["ok"], msg=str(node.get("error")))
        self.assertTrue(edge["ok"], msg=str(edge.get("error")))
        self.assertEqual(node["data"]["status"], "node_added")
        self.assertEqual(edge["data"]["status"], "edge_added")


if __name__ == "__main__":
    unittest.main()
