"""Verify post-Join collection gates without starting a native client."""
import ast
import contextlib
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_replication_metadata_trial import Fixture, run_nodes


RUNNER = Path(__file__).resolve().parent / 'verify_local_provider_client.py'


class MapJoinMetadataTrialTests(unittest.TestCase):
    def setUp(self):
        tree = ast.parse(RUNNER.read_text(encoding='utf-8'))
        node = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == 'replication_metadata_join_due')
        scope = {}
        module = ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[]))
        exec(compile(module, str(RUNNER), 'exec'), scope)
        self.due = scope['replication_metadata_join_due']
        self.report = {'replication_metadata_export_identity': {'pid': 42, 'created_at': 123.0}}
        self.progress = {'join_observed_count': 1, 'active_joined_peers': 1}

    def test_actual_join_requires_the_same_unique_owned_process(self):
        self.assertTrue(self.due(self.report, 100, {(42, 123.0)}, self.progress, 1800))
        for candidates in (set(), {(43, 123.0)}, {(42, 123.01)}, {(42, 123.0), (43, 124.0)}):
            with self.subTest(candidates=candidates):
                self.assertFalse(self.due(self.report, 100, candidates, self.progress, 1800))
        self.assertFalse(self.due({}, 100, {(42, 123.0)}, self.progress, 1800))

    def test_lobby_or_stale_join_counter_does_not_trigger(self):
        for progress in ({}, {'join_observed_count': 0, 'active_joined_peers': 1},
                         {'join_observed_count': 1, 'active_joined_peers': 0},
                         {'join_observed_count': True, 'active_joined_peers': 1}):
            with self.subTest(progress=progress):
                self.assertFalse(self.due(self.report, 100, {(42, 123.0)}, progress, 1800))

    def test_once_per_trial_and_within_the_existing_observation_budget(self):
        self.report['replication_metadata_after_join_attempted'] = True
        self.assertFalse(self.due(self.report, 100, {(42, 123.0)}, self.progress, 1800))
        del self.report['replication_metadata_after_join_attempted']
        for elapsed in (1675.001, True, float('nan'), float('inf')):
            with self.subTest(elapsed=elapsed):
                self.assertFalse(self.due(self.report, elapsed, {(42, 123.0)}, self.progress, 1800))
        self.assertTrue(self.due(self.report, 1675, {(42, 123.0)}, self.progress, 1800))

    def fixture(self, root):
        fixture = Fixture(root)
        fixture.run()
        fixture.scope['args'].ds_control_probe = True
        fixture.scope.update(metadata_owned_candidates={(42, 123.0)},
            game_server_probe=SimpleNamespace(map_join_progress=dict(self.progress)),
            replication_metadata_join_due=self.due)
        return fixture

    def run_join_block(self, fixture):
        tree = ast.parse(RUNNER.read_text(encoding='utf-8'))
        block = next(node for node in ast.walk(tree) if isinstance(node, ast.If)
                     and 'replication_metadata_export' in ast.unparse(node.test)
                     and 'map_join_progress' in ast.unparse(node))
        with patch.dict('sys.modules', {'export_native_replication_metadata': fixture.module}), \
                contextlib.redirect_stdout(io.StringIO()):
            run_nodes([block], fixture.scope)

    def test_native_trial_collects_once_and_preserves_the_early_lobby_report(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = self.fixture(Path(folder))
            early = fixture.trial / 'replication-metadata/result.json'
            original = early.read_bytes()
            self.run_join_block(fixture)
            self.run_join_block(fixture)
            self.assertEqual(len(fixture.calls), 2)
            self.assertEqual(fixture.calls[1][2:], (42, 123.0))
            self.assertEqual(fixture.calls[1][1], fixture.trial / 'replication-metadata-after-join')
            self.assertEqual(early.read_bytes(), original)
            progress = fixture.scope['report']['replication_metadata_after_join_progress']
            self.assertEqual(progress['join_at_start']['active_joined_peers'], 1)
            self.assertFalse(progress['snapshot_atomic'])
            self.assertFalse(progress['playable_map_verified'])

    def test_connection_closed_during_collection_is_explicit_in_the_saved_progress(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = self.fixture(Path(folder))
            def collect_then_close(*args, **kwargs):
                result = fixture.collect(*args, **kwargs)
                fixture.scope['game_server_probe'].map_join_progress = {
                    'join_observed_count': 1, 'active_joined_peers': 0}
                return result
            fixture.module.collect = collect_then_close
            self.run_join_block(fixture)
            progress = fixture.scope['report']['replication_metadata_after_join_progress']
            self.assertEqual(progress['join_at_start']['active_joined_peers'], 1)
            self.assertEqual(progress['join_at_finish']['active_joined_peers'], 0)
            self.assertFalse(progress['playable_map_verified'])


if __name__ == '__main__':
    unittest.main()
