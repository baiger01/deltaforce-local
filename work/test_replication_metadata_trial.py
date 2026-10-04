"""Offline metadata and Actor-bootstrap scenarios; never run either launcher.

Only parsed argument/guard/collection AST blocks run against in-memory mocks and
temporary fixture paths. No process inspection, Windows API, UAC or client starts.
"""
import argparse
import ast
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

WORK = Path(__file__).resolve().parent
RUNNER = WORK / 'verify_local_provider_client.py'
WRAPPER = WORK / 'run_native_elevated_trial.py'
TREES = {path: ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
         for path in (RUNNER, WRAPPER)}
SOURCE_FILES = ('work/native_metadata_objects.py', 'work/native_metadata_names.py', 'work/native_metadata_paths.py',
    'work/native_replication_metadata_core.py', 'work/export_native_replication_metadata.py',
    'outputs/df-local-server/dfserver/legacy_ds_class_net_cache.py')
FIELD = 'replication_metadata_export'
OPTION = '--replication-metadata-export'
SCENARIO_COUNT = 42

def run_nodes(nodes, scope):
    module = ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[]))
    exec(compile(module, '<isolated metadata-trial AST>', 'exec'), scope)

def load_function(path, name):
    node = next(n for n in TREES[path].body if isinstance(n, ast.FunctionDef) and n.name == name)
    scope = dict(Path=Path, hashlib=hashlib, json=json)
    run_nodes([node], scope)
    return scope[name]

def parser_only(path):
    nodes = [n for n in TREES[path].body if
        (isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'parser' for t in n.targets)) or
        (isinstance(n, ast.Expr) and isinstance(n.value, ast.Call) and
         isinstance(n.value.func, ast.Attribute) and isinstance(n.value.func.value, ast.Name) and
         n.value.func.value.id == 'parser' and n.value.func.attr == 'add_argument')]
    scope = dict(argparse=argparse, Path=Path, SOURCE_GAME=Path('fixture-source'))
    run_nodes(nodes, scope)
    return scope['parser']

def export_block():
    return next(n for n in ast.walk(TREES[RUNNER]) if isinstance(n, ast.If) and
        'metadata_lobby_candidates' in ast.unparse(n.test) and
        'replication_metadata_export_attempted' in ast.unparse(n.test))

class Fixture:
    def __init__(self, root):
        self.root = root
        for relative in SOURCE_FILES:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('fixture:' + relative).encode())
        self.pins = load_function(RUNNER, 'replication_metadata_source_pins')(root)
        self.trial = root / 'work/native-client-tests/fixture'
        self.trial.mkdir(parents=True)
        self.calls = []
        self.saved = []
        self.module = ModuleType('export_native_replication_metadata')
        self.module.collect = self.collect
        self.scope = dict(args=SimpleNamespace(replication_metadata_export=True, ds_initial_actor_bootstrap=False,
                                              observation_seconds=900),
            report=dict(elapsed_seconds=25), metadata_lobby_candidates={(42, 123.0)},
            ROOT=root, TEST_ROOT=self.trial, GAME=Path('fixture-shadow'),
            metadata_source_pins=self.pins,
            replication_metadata_source_pins=load_function(RUNNER, 'replication_metadata_source_pins'),
            replication_metadata_retry_due=load_function(RUNNER, 'replication_metadata_retry_due'),
            json=json, time=SimpleNamespace(monotonic=lambda: 25), start=0,
            save=lambda: self.saved.append(dict(self.scope['report'])))

    def collect(self, game, folder, *, pid, created_at):
        self.calls.append((game, folder, pid, created_at))
        result = dict(status='fixture_complete')
        (folder / 'result.json').write_text(json.dumps(result))
        return result

    def fail(self, *args, **kwargs):
        self.calls.append(('failed', args, kwargs))
        raise PermissionError('isolated fixture failure')

    def run(self):
        with patch.dict(sys.modules, {'export_native_replication_metadata': self.module}), \
                contextlib.redirect_stdout(io.StringIO()):
            run_nodes([export_block()], self.scope)

class ReplicationMetadataTrialTests(unittest.TestCase):
    def test_26_flag_profile_and_code_compatibility_scenarios(self):
        old = ('ds_transport_code_probe', 'ds_connection_class_code_probe', 'ds_control_code_probe',
               'ds_control_candidate_interval', 'ds_control_field_helpers', 'ds_control_followup_code',
               'ds_control_sender_body', 'ds_image_code_cache', 'entry_code_probe', 'stop_after_code_collection')
        for path in (RUNNER, WRAPPER):
            parser = parser_only(path)
            args = parser.parse_args([OPTION, '--game-server-probe', '--game-root', 'fixture-shadow'])
            args.shadow_game = Path('fixture-shadow').resolve()
            guards = [n for n in TREES[path].body if isinstance(n, ast.If) and
                      ast.unparse(n.test).startswith('args.replication_metadata_export and')]
            self.assertEqual(len(guards), 2)
            scope = dict(parser=parser, args=args, GAME=args.shadow_game, SHADOW_GAME=args.shadow_game)
            for control in (False, True):
                with self.subTest(path=path.name, control=control):
                    args.ds_control_probe = control
                    run_nodes(guards, scope)
            for attr in old:
                with self.subTest(path=path.name, conflicting_flag=attr):
                    setattr(args, attr, True)
                    with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as stopped:
                        run_nodes(guards, scope)
                    self.assertEqual(stopped.exception.code, 2)
                    setattr(args, attr, False)
            with self.subTest(path=path.name, missing_game_profile=True):
                args.game_server_probe = False
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as stopped:
                    run_nodes(guards, scope)
                self.assertEqual(stopped.exception.code, 2)

    def test_two_argv_hop_scenarios(self):
        hops = [n for n in ast.walk(TREES[WRAPPER]) if isinstance(n, ast.If) and
            ast.unparse(n.test) == 'args.' + FIELD and any(isinstance(c, ast.Call) and
            isinstance(c.func, ast.Attribute) and c.func.attr == 'append' for c in ast.walk(n))]
        self.assertEqual(len(hops), 2)
        for flag in (False, True):
            with self.subTest(flag=flag):
                scope = dict(args=SimpleNamespace(replication_metadata_export=flag),
                             sys=SimpleNamespace(argv=[]), parameters=[])
                run_nodes(hops, scope)
                self.assertEqual(scope['sys'].argv, [OPTION] if flag else [])
                self.assertEqual(scope['parameters'], [OPTION] if flag else [])

    def test_three_worker_bool_rejection_scenarios(self):
        guards = [n for n in ast.walk(TREES[WRAPPER]) if isinstance(n, ast.Assert) and
                  FIELD in ast.unparse(n.test)]
        self.assertEqual(len(guards), 2)
        for requested, actual in ((True, False), (1, True), (0, False)):
            with self.subTest(requested=requested, actual=actual), self.assertRaises(AssertionError):
                run_nodes(guards, dict(request={FIELD: requested}, args=SimpleNamespace(**{FIELD: actual})))

    def test_two_source_pin_scenarios(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(Path(temp))
            wrapper = load_function(WRAPPER, 'replication_metadata_source_pins')
            with self.subTest(unchanged=True):
                self.assertEqual(fixture.pins, wrapper(fixture.root))
                self.assertEqual(set(fixture.pins), set(SOURCE_FILES))
            with self.subTest(changed=True):
                (fixture.root / 'work/native_metadata_names.py').write_bytes(b'changed')
                self.assertNotEqual(fixture.pins, wrapper(fixture.root))

    def test_once_success_and_observation_continues(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(Path(temp))
            fixture.run()
            fixture.run()
            self.assertEqual(len(fixture.calls), 1)
            self.assertEqual(fixture.calls[0][2:], (42, 123.0))
            self.assertEqual(fixture.calls[0][1], fixture.trial / 'replication-metadata')
            self.assertEqual(fixture.scope['report']['replication_metadata_export_progress']['observation_action'], 'continue')

    def test_once_exception_has_failure_result_and_continues(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(Path(temp))
            fixture.module.collect = fixture.fail
            fixture.run()
            fixture.run()
            self.assertEqual(len(fixture.calls), 1)
            self.assertEqual(fixture.scope['report']['replication_metadata_export']['status'], 'replication_metadata_export_failed')
            saved = json.loads((fixture.trial / 'replication-metadata/result.json').read_bytes())
            self.assertEqual(saved['error_type'], 'PermissionError')
            self.assertFalse(saved['playable_map_verified'])

    def test_no_current_lobby_identity_does_not_trigger(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(Path(temp))
            fixture.scope['metadata_lobby_candidates'] = set()
            fixture.run()
            self.assertEqual(fixture.calls, [])
            self.assertNotIn('replication_metadata_export_attempted', fixture.scope['report'])

    def test_non_unique_owned_identity_fails_before_import_or_folder(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(Path(temp))
            fixture.scope['metadata_lobby_candidates'] = {(1, 1.0), (2, 2.0)}
            fixture.run()
            self.assertEqual(fixture.calls, [])
            self.assertEqual(fixture.scope['report']['replication_metadata_export']['status'], 'replication_metadata_export_failed')
            self.assertFalse((fixture.trial / 'replication-metadata').exists())

    def test_grace_period_does_not_trigger(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(Path(temp))
            fixture.scope['report']['elapsed_seconds'] = 19
            fixture.run()
            self.assertEqual(fixture.calls, [])
            self.assertNotIn('replication_metadata_export_attempted', fixture.scope['report'])

    def test_changed_source_fails_before_import_or_folder(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(Path(temp))
            (fixture.root / 'work/native_metadata_names.py').write_bytes(b'changed')
            fixture.run()
            self.assertEqual(fixture.calls, [])
            self.assertEqual(fixture.scope['report']['replication_metadata_export']['status'], 'replication_metadata_export_failed')
            self.assertFalse((fixture.trial / 'replication-metadata').exists())

    def test_two_missing_source_preflight_rejections(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(Path(temp))
            (fixture.root / 'work/native_metadata_names.py').unlink()
            for path in (RUNNER, WRAPPER):
                with self.subTest(path=path.name), self.assertRaisesRegex(ValueError, 'missing or unreadable'):
                    load_function(path, 'replication_metadata_source_pins')(fixture.root)

    def test_worker_source_pin_mismatch_rejected(self):
        guards = [n for n in ast.walk(TREES[WRAPPER]) if isinstance(n, ast.Assert) and
                  'replication_metadata_source_pins' in ast.unparse(n.test)]
        self.assertEqual(len(guards), 1)
        with self.assertRaises(AssertionError):
            run_nodes(guards, dict(request={'replication_metadata_source_pins': {'fixture': 'changed'}},
                                  metadata_source_pins={}))


BOOTSTRAP_FIELD = 'ds_initial_actor_bootstrap'
BOOTSTRAP_OPTION = '--ds-initial-actor-bootstrap'
LEVEL_SOURCE = 'work/evidence/native-player-class-and-iris-level-path-review.json'
VERSION_SOURCE = 'work/evidence/native-engine-network-protocol-version-source-summary.json'
PC_SOURCE = 'work/evidence/native-player-controller-base-tail-profile.json'


class BootstrapFixture(Fixture):
    def __init__(self, root):
        super().__init__(root)
        function = next(n for n in TREES[RUNNER].body if isinstance(n, ast.FunctionDef)
                        and n.name == 'initial_actor_bootstrap_source_pins')
        files = next(n for n in function.body if isinstance(n, ast.Assign)
                     and any(isinstance(t, ast.Name) and t.id == 'files' for t in n.targets))
        self.bootstrap_files = ast.literal_eval(files.value)
        for relative in self.bootstrap_files:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            actual_data = (LEVEL_SOURCE, VERSION_SOURCE, PC_SOURCE,
                'outputs/df-local-server/protocol/local_initial_role_sources.json',
                'work/native-client-tests/1791073668497579200/replication-metadata-after-actor-open/result.json',
                'outputs/df-local-server/protocol/local_pawn_spawn_policy.json',
                'work/official-interface-observations/1791043432995-pid243608/result.json',
                'work/evidence/native-spawn-role-and-connection-semantics.json')
            path.write_bytes((WORK.parent / relative).read_bytes() if relative in actual_data
                             else ('bootstrap-fixture:' + relative).encode())
        self.bootstrap_pin_function = load_function(RUNNER, 'initial_actor_bootstrap_source_pins')
        self.bootstrap_pins = self.bootstrap_pin_function(root)
        self.sources = load_function(RUNNER, 'load_initial_actor_bootstrap_sources')(
            root, self.bootstrap_pins, 2201)
        self.preparer = load_function(RUNNER, 'prepare_initial_actor_bootstrap')
        self.preparer.__globals__['initial_actor_bootstrap_source_pins'] = self.bootstrap_pin_function
        self.profiles = []
        self.probe = SimpleNamespace(set_initial_actor_manifests=lambda map_id, manifests, resolver=None:
                                     self.profiles.append((map_id, manifests)),
                                     actor_transport_progress={'datagrams_sent': 3, 'delivery_acks': 3, 'fully_delivered_sets': 1})
        self.factory_calls = []
        self.optional_factory_calls = []
        self.factory_module = ModuleType('native_actor_bootstrap')
        self.factory_module.build_pawn_actor_bootstrap = self.factory
        self.factory_module.build_initial_actor_bootstrap = self.optional_factory
        self.factory_module.QualifiedPCTailProfile = SimpleNamespace
        self.factory_module.QualifiedGameSpawnProfile = SimpleNamespace
        self.scope.update(bootstrap_source_pins=self.bootstrap_pins, bootstrap_sources=self.sources,
                          game_server_probe=self.probe,
                          initial_actor_bootstrap_source_pins=self.bootstrap_pin_function,
                          prepare_initial_actor_bootstrap=self.preparer,
                          control_profile={'maximum_packet_bytes': 1024})

    def factory(self, raw, **kwargs):
        self.factory_calls.append((raw, kwargs))
        return SimpleNamespace(manifest='explicit-pawn-manifest',
                               preflight=SimpleNamespace(conservative_packet_bytes=200))

    def optional_factory(self, raw, **kwargs):
        self.optional_factory_calls.append((raw, kwargs))
        return SimpleNamespace(manifest='explicit-' + kwargs['role'] + '-manifest')

    def complete(self, game, folder, *, pid, created_at):
        self.calls.append((game, folder, pid, created_at))
        result = {'kind': 'existing_native_replication_metadata_export',
            'status': 'metadata_export_complete',
            'client_sha256': '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0',
            'roots': {'selected_roots_rechecked': True, 'classes': [], 'named_template_candidates': []}}
        self.complete_raw = json.dumps(result).encode()
        (folder / 'result.json').write_bytes(self.complete_raw)
        return result

    def run(self):
        with patch.dict(sys.modules, {'export_native_replication_metadata': self.module,
                                     'native_actor_bootstrap': self.factory_module}), \
                contextlib.redirect_stdout(io.StringIO()):
            run_nodes([export_block()], self.scope)

    def run_after(self):
        block = next(n for n in ast.walk(TREES[RUNNER]) if isinstance(n, ast.If)
                     and 'replication_metadata_after_actor_open_attempted' in ast.unparse(n.test)
                     and 'args.ds_initial_actor_bootstrap' in ast.unparse(n.test))
        self.scope['metadata_owned_candidates'] = {(42, 123.0)}
        with patch.dict(sys.modules, {'export_native_replication_metadata': self.module}), \
                contextlib.redirect_stdout(io.StringIO()):
            run_nodes([block], self.scope)


class InitialActorBootstrapTrialTests(unittest.TestCase):
    def assert_actor_channels_avoid_static_channels(self, manifests):
        # Native trial 1790993562510611400 rejected Actor channel 1 because
        # Voice already owned it. Check the actual serialized bunch headers,
        # for both Pawn-only and optional-role registration paths.
        from dfserver.legacy_ds_actor_manifest import preflight_actor_manifest
        from dfserver.legacy_ds_wire_codec import (WirePacket,
            encode_observed_application, decode_observed_application)
        channels = []
        for manifest in manifests:
            bunch = preflight_actor_manifest(manifest, channel_sequence=1,
                                             max_packet_bytes=1024).bunch
            packet = WirePacket(1, 0, (0,), False, 0, None, (bunch,), 0)
            wire = encode_observed_application(packet, max_packet_bytes=1024,
                                                received_by_server=False)
            decoded = decode_observed_application(wire, max_packet_bytes=1024,
                                                  received_by_server=False)
            actual = decoded.bunches[0]
            self.assertEqual(actual.channel_name.hardcoded_index, 102)
            self.assertNotIn(actual.channel_index, (0, 1),
                             'Actor collides with native Control/Voice channel')
            channels.append(actual.channel_index)
        self.assertEqual(len(channels), len(set(channels)))

    def test_shipping_control_metadata_requirements_and_code_conflicts(self):
        conflicting = ('ds_transport_code_probe', 'ds_connection_class_code_probe', 'ds_control_code_probe',
            'ds_control_candidate_interval', 'ds_control_field_helpers', 'ds_control_followup_code',
            'ds_control_sender_body', 'ds_image_code_cache', 'entry_code_probe', 'stop_after_code_collection')
        for path in (RUNNER, WRAPPER):
            parser = parser_only(path)
            args = parser.parse_args([BOOTSTRAP_OPTION, OPTION, '--ds-control-probe',
                                      '--game-root', 'fixture-shadow'])
            args.shadow_game = Path('fixture-shadow').resolve()
            guards = [n for n in TREES[path].body if isinstance(n, ast.If)
                      and ast.unparse(n.test).startswith('args.ds_initial_actor_bootstrap and')]
            self.assertEqual(len(guards), 2)
            scope = dict(parser=parser, args=args, GAME=args.shadow_game, SHADOW_GAME=args.shadow_game)
            run_nodes(guards, scope)
            for name, value in (('ds_control_probe', False), ('replication_metadata_export', False),
                                ('entry', 'bootstrap'), ('game_root', Path('fixture-source'))):
                with self.subTest(path=path.name, missing=name):
                    before = getattr(args, name)
                    setattr(args, name, value)
                    scope['GAME'] = args.game_root.resolve()
                    with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                        run_nodes(guards, scope)
                    setattr(args, name, before)
                    scope['GAME'] = args.shadow_game
            for name in conflicting:
                with self.subTest(path=path.name, conflict=name):
                    setattr(args, name, True)
                    with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                        run_nodes(guards, scope)
                    setattr(args, name, False)

    def test_two_argument_hops(self):
        hops = [n for n in ast.walk(TREES[WRAPPER]) if isinstance(n, ast.If) and
                ast.unparse(n.test) == 'args.' + BOOTSTRAP_FIELD and any(isinstance(c, ast.Call)
                and isinstance(c.func, ast.Attribute) and c.func.attr == 'append' for c in ast.walk(n))]
        self.assertEqual(len(hops), 2)
        for value in (False, True):
            scope = dict(args=SimpleNamespace(ds_initial_actor_bootstrap=value),
                         sys=SimpleNamespace(argv=[]), parameters=[])
            run_nodes(hops, scope)
            self.assertEqual(scope['sys'].argv, [BOOTSTRAP_OPTION] if value else [])
            self.assertEqual(scope['parameters'], [BOOTSTRAP_OPTION] if value else [])

    def test_worker_bool_and_source_pins_are_strict(self):
        guards = [n for n in ast.walk(TREES[WRAPPER]) if isinstance(n, ast.Assert) and
                  ('ds_initial_actor_bootstrap' in ast.unparse(n.test) or
                   'initial_actor_bootstrap_source' in ast.unparse(n.test))]
        self.assertEqual(len(guards), 4)
        for value in (1, False):
            with self.subTest(value=value), self.assertRaises(AssertionError):
                run_nodes(guards, dict(request={'ds_initial_actor_bootstrap': value},
                                      args=SimpleNamespace(ds_initial_actor_bootstrap=True)))
        scope = dict(request={'ds_initial_actor_bootstrap': True,
                              'initial_actor_bootstrap_source_pins': {'changed': 'source'},
                              'initial_actor_bootstrap_sources': {}},
                     args=SimpleNamespace(ds_initial_actor_bootstrap=True),
                     bootstrap_source_pins={}, bootstrap_sources={})
        with self.assertRaises(AssertionError):
            run_nodes(guards, scope)

    def test_pins_and_constructor_version_preflight_match_both_launchers(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = BootstrapFixture(Path(temp))
            pins = load_function(WRAPPER, 'initial_actor_bootstrap_source_pins')(fixture.root)
            self.assertEqual(pins, fixture.bootstrap_pins)
            self.assertEqual(load_function(WRAPPER, 'load_initial_actor_bootstrap_sources')(
                fixture.root, pins, 2201), fixture.sources)
            self.assertEqual(fixture.sources['connection_network_version'], 13)
            self.assertEqual(fixture.sources['archive_network_version'], 13)
            self.assertFalse(fixture.sources['runtime_connection_version_verified'])
            for wrong_map in (None, True, 2202):
                with self.subTest(map=wrong_map), self.assertRaises(ValueError):
                    load_function(RUNNER, 'load_initial_actor_bootstrap_sources')(
                        fixture.root, fixture.bootstrap_pins, wrong_map)

    def test_level_and_version_evidence_change_rejected(self):
        for relative in (LEVEL_SOURCE, VERSION_SOURCE, PC_SOURCE):
            with self.subTest(source=relative), tempfile.TemporaryDirectory() as temp:
                fixture = BootstrapFixture(Path(temp))
                (fixture.root / relative).write_bytes(b'{"source_backed_build_default":1077088301}')
                for path in (RUNNER, WRAPPER):
                    with self.assertRaisesRegex(ValueError, 'seal does not match'):
                        load_function(path, 'load_initial_actor_bootstrap_sources')(
                            fixture.root, fixture.bootstrap_pins, 2201)

    def test_success_uses_exact_report_bytes_and_registers_once(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = BootstrapFixture(Path(temp))
            fixture.scope['args'].ds_initial_actor_bootstrap = True
            fixture.module.collect = fixture.complete
            fixture.run()
            fixture.run()
            self.assertEqual(len(fixture.factory_calls), 1)
            raw, kwargs = fixture.factory_calls[0]
            self.assertEqual(raw, fixture.complete_raw)
            self.assertEqual(kwargs['source_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(kwargs['source_relative_path'], 'work/native-client-tests/fixture/replication-metadata/result.json')
            self.assertEqual(kwargs['connection_network_version'], 13)
            self.assertEqual(kwargs['archive_network_version'], 13)
            self.assertEqual(kwargs['level_outer_guid'], 9)
            self.assertEqual(fixture.profiles, [(2201, ('explicit-PlayerController-manifest',
                'explicit-GameState-manifest', 'explicit-pawn-manifest'))])
            self.assertEqual([kwargs['role'] for _, kwargs in fixture.optional_factory_calls],
                             ['PlayerController', 'GameState'])
            self.assertFalse(fixture.scope['report']['ds_initial_actor_bootstrap_progress']['native_spawn_verified'])

    def test_failed_metadata_never_builds_or_registers(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = BootstrapFixture(Path(temp))
            fixture.scope['args'].ds_initial_actor_bootstrap = True
            fixture.module.collect = fixture.fail
            fixture.run()
            self.assertEqual(fixture.factory_calls, [])
            self.assertEqual(fixture.profiles, [])
            self.assertEqual(fixture.scope['report']['ds_initial_actor_bootstrap_progress']['stage'],
                             'ds_initial_actor_bootstrap_rejected')

    def test_factory_rejection_preserves_observation_and_no_profile(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = BootstrapFixture(Path(temp))
            fixture.scope['args'].ds_initial_actor_bootstrap = True
            fixture.module.collect = fixture.complete
            fixture.factory_module.build_pawn_actor_bootstrap = lambda *a, **k: (_ for _ in ()).throw(ValueError('no unique candidate'))
            fixture.run()
            self.assertEqual(fixture.profiles, [])
            self.assertEqual(fixture.scope['report']['ds_initial_actor_bootstrap_progress']['error_type'], 'ValueError')
            self.assertEqual(fixture.scope['report']['ds_initial_actor_bootstrap_progress']['reason'], 'no unique candidate')
            self.assertEqual(fixture.scope['report']['replication_metadata_export_progress']['observation_action'], 'continue')

    def test_actual_factory_accepts_only_one_explicit_pawn_candidate(self):
        # Synthetic metadata identities and paths; no captured account, token or live object.
        from native_actor_bootstrap import build_pawn_actor_bootstrap
        klass = {'name': 'BP_DFMCharacter_C', 'address': 0x200000,
                 'object_index': 10, 'serial': 1, 'key': '0a00000001000000',
                 'asset_path': '/Game/TestPawn.BP_DFMCharacter_C'}
        candidate = {'name': 'Default__BP_DFMCharacter_C', 'address': 0x210000,
                     'object_index': 11, 'serial': 1, 'key': '0b00000001000000',
                     'class_name': 'BP_DFMCharacter_C', 'class_address': 0x200000,
                     'class_outer_address': 0x220000, 'outer_address': 0x220000,
                     'class_outer_path': '/Game/TestPawn', 'outer_path': '/Game/TestPawn',
                     'outer_relation': 'same_outer_as_class',
                     'asset_path': '/Game/TestPawn.Default__BP_DFMCharacter_C',
                     'selection_kind': 'name_class_outer_metadata_candidate',
                     'class_default_object_flags_verified': False,
                     'package_map_resolution_verified': False}
        for classes, candidates, accepted in (([klass], [candidate], True),
                ([], [candidate], False), ([klass, klass], [candidate], False),
                ([klass], [], False), ([klass], [candidate, candidate], False)):
            with self.subTest(classes=len(classes), candidates=len(candidates)), tempfile.TemporaryDirectory() as temp:
                fixture = BootstrapFixture(Path(temp))
                fixture.scope['args'].ds_initial_actor_bootstrap = True
                fixture.factory_module.build_pawn_actor_bootstrap = build_pawn_actor_bootstrap
                metadata = {'kind': 'existing_native_replication_metadata_export',
                    'status': 'metadata_export_complete',
                    'client_sha256': '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0',
                    'roots': {'selected_roots_rechecked': True, 'classes': classes,
                              'named_template_candidates': candidates}}
                def collect(game, folder, *, pid, created_at):
                    (folder / 'result.json').write_bytes(json.dumps(metadata).encode())
                    return metadata
                fixture.module.collect = collect
                fixture.run()
                event = fixture.scope['report']['ds_initial_actor_bootstrap_progress']
                if accepted:
                    self.assertEqual(len(fixture.profiles), 1)
                    manifest = fixture.profiles[0][1][-1]
                    self.assertEqual(manifest.class_path, klass['asset_path'])
                    self.assertEqual(manifest.archetype_path, candidate['asset_path'])
                    self.assertEqual(manifest.actor_guid, 2)
                    self.assertIsNone(manifest.local_player_index)
                    self.assert_actor_channels_avoid_static_channels((manifest,))
                else:
                    self.assertEqual(fixture.profiles, [])
                    self.assertIn('Exactly one', event['reason'])
                    fixture.run_after()
                    self.assertNotIn('replication_metadata_after_actor_open_attempted', fixture.scope['report'])

    def test_source_change_before_and_during_factory_blocks_registration(self):
        for during in (False, True):
            with self.subTest(during=during), tempfile.TemporaryDirectory() as temp:
                fixture = BootstrapFixture(Path(temp))
                fixture.scope['args'].ds_initial_actor_bootstrap = True
                fixture.module.collect = fixture.complete
                path = fixture.root / 'work/native_actor_bootstrap.py'
                if during:
                    def changing(raw, **kwargs):
                        path.write_bytes(b'changed')
                        return fixture.factory(raw, **kwargs)
                    fixture.factory_module.build_pawn_actor_bootstrap = changing
                else:
                    path.write_bytes(b'changed')
                fixture.run()
                self.assertEqual(fixture.profiles, [])
                self.assertEqual(fixture.scope['report']['ds_initial_actor_bootstrap_progress']['stage'],
                                 'ds_initial_actor_bootstrap_rejected')

    def test_actual_three_role_factory_registration_and_derived_pc_rejection(self):
        import struct
        from native_actor_bootstrap import (build_pawn_actor_bootstrap, build_initial_actor_bootstrap,
                                            QualifiedPCTailProfile)
        for target_rva, expected_roles in ((0x12d4ddb0, ['PlayerController', 'GameState', 'Pawn']),
                (0x12d4ddc0, None)):
            with self.subTest(target_rva=target_rva), tempfile.TemporaryDirectory() as temp:
                fixture = BootstrapFixture(Path(temp))
                fixture.scope['args'].ds_initial_actor_bootstrap = True
                fixture.factory_module.build_pawn_actor_bootstrap = build_pawn_actor_bootstrap
                fixture.factory_module.build_initial_actor_bootstrap = build_initial_actor_bootstrap
                fixture.factory_module.QualifiedPCTailProfile = QualifiedPCTailProfile
                classes, candidates = [], []
                for ordinal, (name, package) in enumerate((('BP_DFMCharacter_C', '/Game/TestPawn'),
                        ('BP_DFMPlayerController_C', '/Game/TestPC'), ('BP_GameState_PVPVE_C', '/Game/TestGS'))):
                    klass, template, outer = 0x200000 + ordinal * 0x20000, 0x210000 + ordinal * 0x20000, 0x400000 + ordinal * 0x10000
                    classes.append({'name': name, 'address': klass, 'object_index': ordinal * 2 + 10,
                        'serial': 1, 'key': struct.pack('<iI', ordinal * 2 + 10, 1).hex(),
                        'asset_path': package + '.' + name})
                    candidate = {'name': 'Default__' + name, 'address': template,
                        'object_index': ordinal * 2 + 11, 'serial': 1,
                        'key': struct.pack('<iI', ordinal * 2 + 11, 1).hex(),
                        'class_name': name, 'class_address': klass, 'class_outer_address': outer,
                        'outer_address': outer, 'class_outer_path': package, 'outer_path': package,
                        'outer_relation': 'same_outer_as_class', 'asset_path': package + '.Default__' + name,
                        'selection_kind': 'name_class_outer_metadata_candidate',
                        'class_default_object_flags_verified': False, 'package_map_resolution_verified': False}
                    if ordinal == 1:
                        candidate['actor_channel_open_hook'] = {'slot': 0x3d8,
                            'vtable_address': 0x15b221ff0, 'target_address': 0x140000000 + target_rva,
                            'target_rva': target_rva, 'target_module_sha256': fixture.sources['pc_tail_profile']['client_sha256'],
                            'inside_pinned_image': True, 'identity_rechecked': True,
                            'status': 'observed_pinned_image_method'}
                    candidates.append(candidate)
                metadata = {'kind': 'existing_native_replication_metadata_export', 'status': 'metadata_export_complete',
                    'client_sha256': fixture.sources['pc_tail_profile']['client_sha256'],
                    'roots': {'selected_roots_rechecked': True, 'classes': classes, 'named_template_candidates': candidates}}
                def collect(game, folder, *, pid, created_at):
                    (folder / 'result.json').write_bytes(json.dumps(metadata).encode())
                    return metadata
                fixture.module.collect = collect
                fixture.run()
                event = fixture.scope['report']['ds_initial_actor_bootstrap_progress']
                if expected_roles is None:
                    self.assertEqual(event['stage'], 'ds_initial_actor_bootstrap_rejected')
                    self.assertEqual(event['status'], 'not_registered')
                    self.assertEqual(fixture.profiles, [])
                    self.assertEqual(event['reason'], 'Configured initial PlayerController could not be qualified')
                    continue
                self.assertEqual(event['roles'], expected_roles)
                self.assertEqual(event['initial_actor_manifest_count'], len(expected_roles))
                self.assertEqual(len(fixture.profiles), 1)
                actual = fixture.profiles[0][1]
                self.assert_actor_channels_avoid_static_channels(actual)
                self.assertEqual([item.actor_guid for item in actual], [4, 6, 2])
                self.assertEqual(len({item.channel_index for item in actual}), len(actual))
                self.assertEqual([item.local_player_index for item in actual], [0, None, None])
                self.assertFalse(event['send_order_gameplay_verified'])
                self.assertFalse(event['native_spawn_verified'])
                self.assertEqual(event['optional_role_rejections'], {})

    def test_bad_current_pc_hook_blocks_the_whole_configured_archive_set(self):
        # A present-but-invalid Class/template must not be silently replaced by
        # the valid archive or downgraded to a registered GameState/Pawn subset.
        from native_actor_bootstrap import build_initial_actor_bootstrap, QualifiedPCTailProfile
        with tempfile.TemporaryDirectory() as temp:
            fixture = BootstrapFixture(Path(temp))
            fixture.scope['args'].ds_initial_actor_bootstrap = True
            fixture.factory_module.build_initial_actor_bootstrap = build_initial_actor_bootstrap
            fixture.factory_module.QualifiedPCTailProfile = QualifiedPCTailProfile
            archive = WORK.parent / 'work/native-client-tests/1791073668497579200/replication-metadata-after-actor-open/result.json'
            metadata = json.loads(archive.read_bytes())
            candidate = next(row for row in metadata['roots']['named_template_candidates']
                             if row['class_name'] == 'BP_DFMPlayerController_C')
            candidate['actor_channel_open_hook']['target_rva'] = 1
            def collect(game, folder, *, pid, created_at):
                (folder / 'result.json').write_bytes(json.dumps(metadata).encode())
                return metadata
            fixture.module.collect = collect
            fixture.run()
            self.assertEqual(fixture.profiles, [])
            self.assertEqual(fixture.optional_factory_calls, [])
            event = fixture.scope['report']['ds_initial_actor_bootstrap_progress']
            self.assertEqual(event['stage'], 'ds_initial_actor_bootstrap_rejected')
            self.assertEqual(event['status'], 'not_registered')
            self.assertEqual(event['reason'], 'Configured initial PlayerController could not be qualified')
            self.assertEqual(fixture.scope['report']['replication_metadata_export']['status'],
                             'metadata_export_complete')

    def test_post_open_metadata_waits_for_whole_prepared_actor_set(self):
        for sent, ack, whole in ((1, 1, 1), (3, 2, 1), (3, 3, 0), (3, 3, 1)):
            with self.subTest(sent=sent, ack=ack, whole=whole), tempfile.TemporaryDirectory() as temp:
                fixture = BootstrapFixture(Path(temp))
                fixture.scope['args'].ds_initial_actor_bootstrap = True
                fixture.scope['report'].update(ds_initial_actor_bootstrap_progress={
                    'stage': 'ds_initial_actor_bootstrap_prepared', 'initial_actor_manifest_count': 3},
                    replication_metadata_export_identity={'pid': 42, 'created_at': 123.0})
                fixture.probe.actor_transport_progress = {'datagrams_sent': sent, 'delivery_acks': ack, 'fully_delivered_sets': whole}
                fixture.run_after()
                self.assertEqual(len(fixture.calls), 1 if ack == 3 and whole else 0)

    def test_after_actor_export_requires_sent_ack_and_same_identity(self):
        for sent, ack, identity in ((0, 1, (42, 123.0)), (1, 0, (42, 123.0)),
                                    (1, 1, (43, 123.0)), (1, 1, (42, 124.0))):
            with self.subTest(sent=sent, ack=ack, identity=identity), tempfile.TemporaryDirectory() as temp:
                fixture = BootstrapFixture(Path(temp))
                fixture.scope['args'].ds_initial_actor_bootstrap = True
                fixture.scope['report'].update(ds_initial_actor_bootstrap_progress={'stage': 'ds_initial_actor_bootstrap_prepared'},
                    replication_metadata_export_identity={'pid': identity[0], 'created_at': identity[1]})
                fixture.probe.actor_transport_progress = {'datagrams_sent': sent, 'delivery_acks': ack}
                fixture.run_after()
                self.assertEqual(fixture.calls, [])
                self.assertNotIn('replication_metadata_after_actor_open_attempted', fixture.scope['report'])

    def test_after_actor_export_once_without_reinstalling_profile(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = BootstrapFixture(Path(temp))
            fixture.scope['args'].ds_initial_actor_bootstrap = True
            fixture.module.collect = fixture.complete
            fixture.run()
            fixture.run_after()
            fixture.run_after()
            self.assertEqual(len(fixture.calls), 2)
            self.assertEqual(len(fixture.profiles), 1)
            self.assertEqual(fixture.calls[1][1], fixture.trial / 'replication-metadata-after-actor-open')
            event = fixture.scope['report']['replication_metadata_after_actor_open_progress']
            self.assertTrue(event['transport_ack_is_not_spawn_proof'])
            self.assertFalse(event['native_spawn_verified'])

    def test_lobby_missing_roles_use_recorded_load_metadata_and_keep_pawn_resolver(self):
        # Replay the actual failure: lobby metadata had only Pawn. PC/GS were
        # first observed after loading, and previously never entered the queue.
        from dfserver.legacy_ds_actor_manifest import preflight_actor_manifest
        from dfserver.legacy_ds_actor_bunch import build_actor_bunch
        from dfserver.legacy_ds_bit_archive import BitReader
        from dfserver.legacy_ds_guid_exports import read_guid_exports
        from dfserver.legacy_ds_match_admission import LocalMatchTicket
        root = WORK.parent
        pin_function = load_function(RUNNER, 'initial_actor_bootstrap_source_pins')
        pins = pin_function(root)
        sources = load_function(RUNNER, 'load_initial_actor_bootstrap_sources')(root, pins, 2201)
        prepare = load_function(RUNNER, 'prepare_initial_actor_bootstrap')
        prepare.__globals__['initial_actor_bootstrap_source_pins'] = pin_function
        registered = []
        probe = SimpleNamespace(set_initial_actor_manifests=lambda map_id, manifests, resolver=None:
                                registered.append((map_id, manifests, resolver)))
        folder = root / 'work/native-client-tests/1791073668497579200/replication-metadata'
        event = prepare(root, folder, probe, pins, sources, 1024)
        self.assertEqual(event['roles'], ['PlayerController', 'GameState', 'Pawn'])
        self.assertEqual(event['optional_role_rejections'], {})
        self.assertEqual(len(registered), 1)
        for source in event['optional_role_sources'].values():
            self.assertEqual(source['provenance'], 'archive_same_build_not_current_process')
            self.assertEqual(source['sha256'], '0528623c16f1f1d7f2e80047899f34e362ea132763b13a36c6571e5dda7b3e2a')
        map_id, manifests, resolver = registered[0]
        self.assertEqual(map_id, 2201)
        self.assert_actor_channels_avoid_static_channels(manifests)
        self.assertEqual([m.actor_guid for m in manifests], [4, 6, 2])
        self.assertEqual([m.local_player_index for m in manifests], [0, None, None])
        fields = tuple(dict(preflight_actor_manifest(m, channel_sequence=1,
                       max_packet_bytes=1024).actor_fields) for m in manifests)
        ticket = LocalMatchTicket(100, 200, 2201, 142201103, 303, 'a'*32, 10.0, 130.0)
        resolved = resolver(ticket, fields)
        self.assertEqual(resolved[:2], fields[:2])
        self.assertEqual(resolved[2], dict(fields[2], game_replication_flags=0))
        for item, has_tail in zip(resolved, (True, False, True)):
            bunch = build_actor_bunch(channel_sequence=1, max_packet_bytes=1024, **item)
            reader = BitReader(bunch.payload, bit_count=bunch.payload_bits)
            read_guid_exports(reader)
            self.assertEqual(tuple(reader.read_packed_int() for _ in range(3)),
                             (item['actor_guid'], item['archetype_guid'], item['level_guid']))
            self.assertEqual(tuple(reader.read_bool() for _ in range(4)), (False,)*4)
            if has_tail:
                self.assertEqual(reader.read_bytes(1), b'\x00')
            self.assertEqual(reader.remaining, 0)
        self.assertFalse(event['native_spawn_verified'])
        self.assertFalse(event['playable_map_verified'])

    def test_post_actor_changed_sources_reject_without_collecting(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = BootstrapFixture(Path(temp))
            fixture.scope['args'].ds_initial_actor_bootstrap = True
            fixture.module.collect = fixture.complete
            fixture.run()
            (fixture.root / 'work/native_metadata_names.py').write_bytes(b'changed')
            fixture.run_after()
            self.assertEqual(len(fixture.calls), 1)
            self.assertEqual(fixture.scope['report']['replication_metadata_after_actor_open']['error_type'], 'RuntimeError')

    def test_progress_forwarding_is_once_for_both_phases(self):
        function = load_function(WRAPPER, 'forward_initial_actor_bootstrap_progress')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            log, report_path = root / 'fixture.log', root / 'fixture.json'
            log.write_text('not JSON\n' + json.dumps({'stage': 'ds_initial_actor_bootstrap_prepared'}) + '\n' +
                json.dumps({'stage': 'ds_initial_actor_metadata_export_completed', 'native_spawn_verified': False}) + '\n')
            report = {}
            with contextlib.redirect_stdout(io.StringIO()) as stream:
                function(report, log, report_path)
                function(report, log, report_path)
            self.assertEqual(len(stream.getvalue().splitlines()), 2)
            self.assertIn('ds_initial_actor_bootstrap_progress', report)
            self.assertIn('replication_metadata_after_actor_open_progress', report)

if __name__ == '__main__':
    unittest.main(verbosity=2)
