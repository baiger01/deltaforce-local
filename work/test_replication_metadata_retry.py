"""Retry guard and real export AST regressions, using only offline fixtures."""
import ast
import contextlib
from copy import deepcopy
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_replication_metadata_trial import (
    Fixture, RUNNER, TREES, export_block, load_function, run_nodes,
)


TRANSIENT_REASONS = (
    'Selected metadata root identity changed after discovery',
    'Class descriptor name changed during discovery',
    'Target class Outer changed between template candidates',
    'Selected object class binding changed after discovery',
    'Selected class metadata path changed after discovery',
    'Class descriptor changed during the complete registry scan',
    'Named template candidate binding changed during discovery',
    'Named template candidate is not bound to a selected UClass',
    'Named template candidate path changed during discovery',
    'Named template candidate Outer path changed during discovery',
    'Selected metadata virtual method binding changed',
    'Selected class key changed during driver table export',
    'Selected NetDriver key changed during table export',
    'Selected object class binding changed during table export',
)
REFUSED = dict(status='metadata_export_refused', error_type='ValueError',
               reason=TRANSIENT_REASONS[0], playable_map_verified=False)
COMPLETE = dict(status='metadata_export_complete', playable_map_verified=False)


def retry_report():
    return dict(replication_metadata_export_attempts=[dict(
        attempt=1, status='metadata_export_refused', error_type='ValueError',
        reason=TRANSIENT_REASONS[0], elapsed_seconds=30,
        directory='work/native-client-tests/fixture/replication-metadata')],
        replication_metadata_export_identity=dict(pid=42, created_at=123.0),
        replication_metadata_lobby_stability=dict(pid=42, created_at=123.0,
                                                  since_elapsed_seconds=30))


class RetryFixture(Fixture):
    """Run only the actual stability/export nodes; collector and factory are mocks."""
    def __init__(self, root, results=(REFUSED, COMPLETE), *, bootstrap=True):
        super().__init__(root)
        self.results = deepcopy(list(results))
        self.now = 25
        self.collect_duration = 5
        self.prepare_calls = []
        self.registered = []
        self.factory_refused = False
        self.mutate_source_on_call = None
        self.scope['args'].ds_initial_actor_bootstrap = bootstrap
        self.scope.update(time=SimpleNamespace(monotonic=lambda:self.now),
            game_server_probe=SimpleNamespace(set_initial_actor_manifests=self.registered.append),
            bootstrap_source_pins={'fixture':'sealed'}, bootstrap_sources={'fixture':'source'},
            control_profile={'maximum_packet_bytes':1024},
            prepare_initial_actor_bootstrap=self.prepare)
        self.stability_block = next(node for node in ast.walk(TREES[RUNNER]) if
            isinstance(node, ast.If) and ast.unparse(node.test) == 'len(metadata_lobby_candidates) == 1')

    def collect(self, game, folder, *, pid, created_at):
        self.calls.append((game, folder, pid, created_at))
        result = deepcopy(self.results.pop(0))
        (folder/'result.json').write_text(json.dumps(result), encoding='utf-8')
        if self.mutate_source_on_call == len(self.calls):
            self.change_source()
        self.now += self.collect_duration
        return result

    def change_source(self):
        (self.root/'work/native_metadata_names.py').write_bytes(b'changed collector fixture')

    def prepare(self, root, folder, probe, pins, sources, maximum_packet_bytes):
        self.prepare_calls.append((root, folder, maximum_packet_bytes))
        if self.factory_refused:
            raise ValueError('Synthetic factory qualification refused')
        # This is only a registration spy, not an Actor factory or native acceptance.
        probe.set_initial_actor_manifests(('offline-fixture-manifest',))
        return dict(stage='ds_initial_actor_bootstrap_prepared', initial_actor_manifest_count=1,
                    native_spawn_verified=False, playable_map_verified=False)

    def step(self, now, candidates=None):
        self.now = now
        self.scope['report']['elapsed_seconds'] = now
        if candidates is not None:
            self.scope['metadata_lobby_candidates'] = candidates
        with patch.dict(sys.modules, {'export_native_replication_metadata':self.module}), \
                contextlib.redirect_stdout(io.StringIO()):
            run_nodes([self.stability_block, export_block()], self.scope)


class ReplicationMetadataRetryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.due = staticmethod(load_function(RUNNER, 'replication_metadata_retry_due'))

    def test_each_exact_transient_value_error_reason_has_one_retry(self):
        for reason in TRANSIENT_REASONS:
            report = retry_report()
            report['replication_metadata_export_attempts'][0]['reason'] = reason
            with self.subTest(reason=reason):
                self.assertTrue(self.due(report, 50, {(42,123.0)}, 900))

    def test_allowlist_is_exact_and_not_arbitrary_error_text(self):
        for reason in ('unknown', '', TRANSIENT_REASONS[0]+' ',
                       'Replication metadata collector source identity changed',
                       'registry_header_or_chunk_parameters_changed'):
            report = retry_report()
            report['replication_metadata_export_attempts'][0]['reason'] = reason
            with self.subTest(reason=reason):
                self.assertFalse(self.due(report, 50, {(42,123.0)}, 900))

    def test_failed_nonvalueerror_complete_and_already_prepared_never_retry(self):
        for status, error in (('replication_metadata_export_failed','ValueError'),
                              ('metadata_export_complete',None),
                              ('metadata_export_refused','PermissionError')):
            report = retry_report()
            report['replication_metadata_export_attempts'][0].update(status=status,error_type=error)
            with self.subTest(status=status,error=error):
                self.assertFalse(self.due(report, 50, {(42,123.0)}, 900))
        report = retry_report()
        report['ds_initial_actor_bootstrap_progress'] = {'stage':'ds_initial_actor_bootstrap_prepared'}
        self.assertFalse(self.due(report, 50, {(42,123.0)}, 900))

    def test_only_exactly_one_completed_attempt_is_eligible(self):
        for attempts in (None, [], [None], retry_report()['replication_metadata_export_attempts']*2):
            report = retry_report()
            report['replication_metadata_export_attempts'] = attempts
            with self.subTest(attempts=attempts):
                self.assertFalse(self.due(report, 50, {(42,123.0)}, 900))

    def test_same_unique_pid_and_creation_time_are_required(self):
        for candidates in (set(), {(43,123.0)}, {(42,123.01)}, {(42,123.0),(43,123.0)}):
            with self.subTest(candidates=candidates):
                self.assertFalse(self.due(retry_report(),50,candidates,900))
        for key, value in (('pid',43),('created_at',123.01)):
            report = retry_report()
            report['replication_metadata_lobby_stability'][key] = value
            with self.subTest(key=key):
                self.assertFalse(self.due(report,50,{(42,123.0)},900))

    def test_twenty_seconds_must_follow_collection_completion_and_stability(self):
        self.assertFalse(self.due(retry_report(),49.999,{(42,123.0)},900))
        self.assertTrue(self.due(retry_report(),50,{(42,123.0)},900))
        report = retry_report()
        report['replication_metadata_lobby_stability']['since_elapsed_seconds'] = 29
        self.assertFalse(self.due(report,60,{(42,123.0)},900))
        report['replication_metadata_lobby_stability']['since_elapsed_seconds'] = 45
        self.assertFalse(self.due(report,64.999,{(42,123.0)},900))
        self.assertTrue(self.due(report,65,{(42,123.0)},900))

    def test_remaining_observation_budget_requires_at_least_125_seconds(self):
        self.assertFalse(self.due(retry_report(),50,{(42,123.0)},174.999))
        self.assertTrue(self.due(retry_report(),50,{(42,123.0)},175))
        for key in ('elapsed_seconds','since_elapsed_seconds'):
            report = retry_report()
            source = report['replication_metadata_export_attempts'][0] if key == 'elapsed_seconds' else report['replication_metadata_lobby_stability']
            source[key] = True
            self.assertFalse(self.due(report,50,{(42,123.0)},900))

    def test_first_refusal_registers_no_actor_then_one_fresh_retry_can_prepare(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = RetryFixture(Path(temp))
            fixture.step(25)
            report = fixture.scope['report']
            first = fixture.trial/'replication-metadata/result.json'
            first_raw = first.read_bytes()
            self.assertEqual(len(fixture.calls),1)
            self.assertEqual(fixture.registered,[])
            self.assertEqual(fixture.prepare_calls,[])
            self.assertEqual(report['ds_initial_actor_bootstrap_progress']['status'],'not_registered')
            self.assertNotIn('replication_metadata_lobby_stability',report)
            self.assertEqual(report['replication_metadata_export_attempts'][0]['elapsed_seconds'],30)
            fixture.step(30)
            fixture.step(49.999)
            self.assertEqual(len(fixture.calls),1)
            fixture.step(50)
            self.assertEqual(len(fixture.calls),2)
            self.assertEqual(fixture.calls[0][2:],fixture.calls[1][2:])
            self.assertNotEqual(fixture.calls[0][1],fixture.calls[1][1])
            self.assertEqual(fixture.calls[1][1],fixture.trial/'replication-metadata-retry-2')
            self.assertEqual(first.read_bytes(),first_raw)
            self.assertEqual(len(fixture.registered),1)
            self.assertEqual(len(fixture.prepare_calls),1)
            fixture.step(100)
            self.assertEqual(len(fixture.calls),2)
            self.assertEqual(len(fixture.registered),1)

    def test_second_transient_refusal_is_terminal_for_retry_without_actor_registration(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = RetryFixture(Path(temp),(REFUSED,REFUSED))
            fixture.step(25)
            fixture.step(30)
            fixture.step(50)
            fixture.step(55)
            fixture.step(100)
            self.assertEqual(len(fixture.calls),2)
            self.assertEqual(len(fixture.scope['report']['replication_metadata_export_attempts']),2)
            self.assertEqual(fixture.registered,[])

    def test_late_template_class_refusal_rescans_then_requires_complete_report(self):
        late_template = dict(REFUSED,
            reason='Named template candidate is not bound to a selected UClass')
        for second, expected_registrations in ((COMPLETE, 1), (late_template, 0)):
            with self.subTest(second_status=second['status']), tempfile.TemporaryDirectory() as temp:
                fixture = RetryFixture(Path(temp), (late_template, second))
                fixture.step(25)
                self.assertEqual(fixture.registered, [])
                first_bytes = (fixture.trial/'replication-metadata/result.json').read_bytes()
                fixture.step(30)
                fixture.step(49.999)
                self.assertEqual(len(fixture.calls), 1)
                fixture.step(50)
                fixture.step(55)
                fixture.step(100)
                self.assertEqual(len(fixture.calls), 2)
                self.assertEqual(len(fixture.registered), expected_registrations)
                self.assertEqual(fixture.calls[0][2:], fixture.calls[1][2:])
                self.assertEqual((fixture.trial/'replication-metadata/result.json').read_bytes(), first_bytes)

    def test_disconnect_clears_stability_and_reconnect_needs_another_twenty_seconds(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = RetryFixture(Path(temp))
            fixture.step(25)
            fixture.step(30)
            fixture.step(45,set())
            self.assertNotIn('replication_metadata_lobby_stability',fixture.scope['report'])
            fixture.step(50,{(42,123.0)})
            fixture.step(69.999)
            self.assertEqual(len(fixture.calls),1)
            fixture.step(70)
            self.assertEqual(len(fixture.calls),2)

    def test_identity_change_or_multiple_candidates_never_retry_existing_process(self):
        for candidates in ({(42,123.01)},{(43,123.0)},{(42,123.0),(43,123.0)}):
            with self.subTest(candidates=candidates), tempfile.TemporaryDirectory() as temp:
                fixture = RetryFixture(Path(temp))
                fixture.step(25)
                fixture.step(30,candidates)
                fixture.step(60)
                self.assertEqual(len(fixture.calls),1)
                self.assertEqual(fixture.registered,[])

    def test_complete_success_is_prepared_only_once_without_retry(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = RetryFixture(Path(temp),(COMPLETE,))
            fixture.step(25)
            fixture.step(30)
            fixture.step(60)
            self.assertEqual(len(fixture.calls),1)
            self.assertEqual(len(fixture.registered),1)
            self.assertEqual(len(fixture.prepare_calls),1)

    def test_complete_report_factory_rejection_is_not_a_collection_retry(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = RetryFixture(Path(temp),(COMPLETE,))
            fixture.factory_refused = True
            fixture.step(25)
            fixture.step(30)
            fixture.step(60)
            self.assertEqual(len(fixture.calls),1)
            self.assertEqual(len(fixture.prepare_calls),1)
            self.assertEqual(fixture.registered,[])
            self.assertEqual(fixture.scope['report']['ds_initial_actor_bootstrap_progress']['status'],'not_registered')

    def test_unknown_refusal_or_failed_collection_never_retry(self):
        for result in (dict(REFUSED,reason='unknown'),
                       dict(REFUSED,error_type='PermissionError'),
                       dict(REFUSED,status='replication_metadata_export_failed')):
            with self.subTest(result=result), tempfile.TemporaryDirectory() as temp:
                fixture = RetryFixture(Path(temp),(result,))
                fixture.step(25)
                fixture.step(30)
                fixture.step(60)
                self.assertEqual(len(fixture.calls),1)
                self.assertEqual(fixture.registered,[])

    def test_insufficient_budget_prevents_actual_retry_ast(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = RetryFixture(Path(temp))
            fixture.scope['args'].observation_seconds = 174.999
            fixture.step(25)
            fixture.step(30)
            fixture.step(50)
            self.assertEqual(len(fixture.calls),1)
            self.assertEqual(fixture.registered,[])

    def test_source_change_before_first_export_does_not_collect_or_register(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = RetryFixture(Path(temp))
            fixture.change_source()
            fixture.step(25)
            fixture.step(30)
            fixture.step(60)
            self.assertEqual(fixture.calls,[])
            self.assertEqual(fixture.registered,[])
            self.assertEqual(fixture.scope['report']['replication_metadata_export']['status'],'replication_metadata_export_failed')

    def test_source_change_during_first_export_overrides_refusal_and_disables_retry(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = RetryFixture(Path(temp))
            fixture.mutate_source_on_call = 1
            fixture.step(25)
            fixture.step(30)
            fixture.step(60)
            self.assertEqual(len(fixture.calls),1)
            self.assertEqual(fixture.registered,[])
            self.assertEqual(fixture.scope['report']['replication_metadata_export']['status'],'replication_metadata_export_failed')

    def test_source_change_before_retry_rejects_without_second_collect_or_actor(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = RetryFixture(Path(temp))
            fixture.step(25)
            fixture.step(30)
            fixture.change_source()
            fixture.step(50)
            self.assertEqual(len(fixture.calls),1)
            self.assertEqual(len(fixture.scope['report']['replication_metadata_export_attempts']),2)
            self.assertEqual(fixture.registered,[])
            self.assertFalse((fixture.trial/'replication-metadata-retry-2').exists())

    def test_source_change_during_retry_complete_report_cannot_prepare_actor(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = RetryFixture(Path(temp))
            fixture.mutate_source_on_call = 2
            fixture.step(25)
            fixture.step(30)
            fixture.step(50)
            self.assertEqual(len(fixture.calls),2)
            self.assertEqual(fixture.registered,[])
            self.assertEqual(fixture.prepare_calls,[])
            self.assertEqual(fixture.scope['report']['replication_metadata_export']['status'],'replication_metadata_export_failed')

    def test_retry_does_not_reuse_existing_retry_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = RetryFixture(Path(temp))
            fixture.step(25)
            fixture.step(30)
            stale = fixture.trial/'replication-metadata-retry-2'
            stale.mkdir()
            (stale/'result.json').write_text('existing fixture result',encoding='utf-8')
            fixture.step(50)
            self.assertEqual(len(fixture.calls),1)
            self.assertEqual(fixture.registered,[])
            self.assertEqual((stale/'result.json').read_text(),'existing fixture result')
            self.assertEqual(fixture.scope['report']['replication_metadata_export']['status'],'replication_metadata_export_failed')


if __name__ == '__main__':
    unittest.main()
