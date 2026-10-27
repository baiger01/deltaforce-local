"""The updated metadata read waits for the actual control Join, never a timer."""
import ast
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest


class UpdatedMapMetadataGateTests(unittest.TestCase):
    def ready(self, mode, summary, attempted=False, seconds_left=900):
        source = Path(__file__).with_name('verify_local_provider_client.py')
        tree = ast.parse(source.read_text(encoding='utf-8'))
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name == 'updated_map_metadata_ready']
        self.assertEqual(len(nodes), 1, 'The source-qualified Join gate is missing')
        scope = {}
        exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                     str(source), 'exec'), scope)
        probe = summary if hasattr(summary, 'map_join_progress') else SimpleNamespace(map_join_progress=summary)
        return scope['updated_map_metadata_ready'](mode, probe,
            attempted=attempted, seconds_left=seconds_left)

    def test_join_is_required_for_the_new_map_metadata_mode(self):
        self.assertFalse(self.ready('updated_control_metadata_capture', {}))
        self.assertFalse(self.ready('updated_control_metadata_capture',
            {'join_observed_count': 0, 'active_joined_peers': 0}))
        self.assertTrue(self.ready('updated_control_metadata_capture',
            {'join_observed_count': 1, 'active_joined_peers': 1}))
        self.assertFalse(self.ready('updated_control_metadata_capture',
            {'join_observed_count': 1, 'active_joined_peers': 0}))

    def test_no_implicit_lobby_read_repeat_or_overrun(self):
        joined = {'join_observed_count': 1, 'active_joined_peers': 1}
        self.assertFalse(self.ready('updated_transport_capture', joined))
        self.assertFalse(self.ready('updated_control_metadata_capture', joined, attempted=True))
        self.assertFalse(self.ready('updated_control_metadata_capture', joined, seconds_left=299))

    def test_gate_uses_the_real_game_probe_interface_before_any_client_launch(self):
        root = Path(__file__).resolve().parents[1]
        sys.path.insert(0, str(root/'outputs/df-local-server'))
        from dfserver.match.game_server_probe import GameServerProbe
        with tempfile.TemporaryDirectory() as folder:
            probe = GameServerProbe(folder)
            try:
                self.assertFalse(self.ready('updated_control_metadata_capture', probe))
                self.assertFalse(probe.listening)
            finally:
                probe.close()


if __name__ == '__main__':
    unittest.main()
