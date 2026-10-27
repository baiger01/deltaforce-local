"""The UAC child must receive the same explicit current Actor mode."""
import ast
from pathlib import Path
from types import SimpleNamespace
import unittest


class CurrentWrapperForwardingTests(unittest.TestCase):
    def test_current_mode_is_forwarded_to_the_elevated_child(self):
        path = Path(__file__).with_name('run_native_elevated_trial.py')
        tree = ast.parse(path.read_text(encoding='utf-8'))
        blocks = [node for node in tree.body if isinstance(node, ast.If) and
            ast.unparse(node.test) == 'args.updated_minimum_actor_bootstrap']
        self.assertEqual(len(blocks), 1, 'The top-level UAC parameter path must forward current Actor mode')
        code = compile(ast.Module(body=blocks, type_ignores=[]), str(path), 'exec')
        for enabled in (False, True):
            values = dict(args=SimpleNamespace(updated_minimum_actor_bootstrap=enabled), parameters=[])
            exec(code, values)
            self.assertEqual(values['parameters'], ['--updated-minimum-actor-bootstrap'] if enabled else [])

    def test_current_restart_request_waits_for_a_registered_admission(self):
        path = Path(__file__).with_name('verify_local_provider_client.py')
        tree = ast.parse(path.read_text(encoding='utf-8'))
        blocks = [node for node in ast.walk(tree) if isinstance(node, ast.If) and
            ast.unparse(node.test) == 'updated_minimum_source_lease is not None and game_server_probe is not None']
        self.assertEqual(len(blocks), 1)
        code = compile(ast.Module(body=blocks, type_ignores=[]), str(path), 'exec')
        calls = []
        probe = SimpleNamespace(request_pc_restart=lambda map_id: calls.append(map_id) or 'pending')
        values = dict(updated_minimum_source_lease=None, game_server_probe=probe, report={})
        exec(code, values)
        self.assertEqual(calls, [])
        values['updated_minimum_source_lease'] = object()
        exec(code, values)
        self.assertEqual(values['report']['updated_minimum_restart_request'], 'pending')
        probe.request_pc_restart = lambda map_id: calls.append(map_id) or 'queued'
        exec(code, values)
        exec(code, values)
        self.assertEqual(calls, [2201, 2201])


if __name__ == '__main__':
    unittest.main()
