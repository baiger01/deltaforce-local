"""Pure archived PC/GS source selection; no process, UAC or socket access."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from native_actor_bootstrap import (
    CLIENT_SHA256, ROLE_CLASSES, QualifiedPCTailProfile, PC_BASE_OPEN_HOOK_RVA,
)
from native_initial_role_sources import (
    INITIAL_ROLE_CONFIG_RELATIVE_PATH, INITIAL_ROLE_CONFIG_SHA256,
    load_initial_role_sources, select_initial_role_source,
)


ROOT = Path(__file__).resolve().parent.parent
TRIAL = 'work/native-client-tests/1791073668497579200'
ARCHIVE_PATH = TRIAL + '/replication-metadata-after-actor-open/result.json'
ARCHIVE_SHA = '0528623c16f1f1d7f2e80047899f34e362ea132763b13a36c6571e5dda7b3e2a'
LEVEL_SOURCE = 'work/evidence/native-player-class-and-iris-level-path-review.json'
LEVEL_SHA = 'b1a7abc074ccb7f23c1902b74c9246c9f5f69be1cb48244a5c856e7eb265ab1a'
PC_SOURCE = 'work/evidence/native-player-controller-base-tail-profile.json'
PC_SHA = '7941c3a10556a232f20558e0a4b83b78659af902e1878ae5998b6ae3d71dddac'


def encode(document):
    return json.dumps(document, ensure_ascii=False, separators=(',', ':')).encode()


def arguments(role):
    guids, channel = ((13, 15, 17, 4), 2) if role == 'PlayerController' else ((19, 21, 23, 6), 3)
    params = dict(level_path='/Game/Maps/Iris_Entry/Iris_Entry.Iris_Entry:PersistentLevel',
        level_source_relative_path=LEVEL_SOURCE, level_source_sha256=LEVEL_SHA,
        package_guid=guids[0], class_guid=guids[1], archetype_guid=guids[2],
        level_package_guid=25, level_outer_guid=9, level_guid=11, actor_guid=guids[3],
        channel_index=channel, channel_sequence=1023, connection_network_version=13,
        archive_network_version=13, max_packet_bytes=1024, references_resolvable=True)
    if role == 'PlayerController':
        params.update(local_player_index=0,
            pc_tail_profile=QualifiedPCTailProfile(CLIENT_SHA256, PC_SOURCE, PC_SHA,
                                                  PC_BASE_OPEN_HOOK_RVA))
    return params


class InitialRoleSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.archive_raw = (ROOT / ARCHIVE_PATH).read_bytes()
        if hashlib.sha256(cls.archive_raw).hexdigest() != ARCHIVE_SHA:
            raise AssertionError('Archived native report changed')
        cls.archive_document = json.loads(cls.archive_raw)
        cls.first_raw = (ROOT / (TRIAL + '/replication-metadata/result.json')).read_bytes()
        cls.sources = load_initial_role_sources(ROOT,
            config_relative_path=INITIAL_ROLE_CONFIG_RELATIVE_PATH,
            config_sha256=INITIAL_ROLE_CONFIG_SHA256)

    def select(self, raw, role='PlayerController', **changes):
        params = dict(role=role, current_source_relative_path='work/tests/current-report.json',
            current_source_sha256=hashlib.sha256(raw).hexdigest(),
            factory_arguments=arguments(role), archive_sources=self.sources)
        params.update(changes)
        return select_initial_role_source(raw, **params)

    def altered(self, mutate):
        document = deepcopy(self.archive_document)
        mutate(document)
        return encode(document)

    def candidate(self, document, role='PlayerController'):
        return next(row for row in document['roots']['named_template_candidates']
                    if row['class_name'] == ROLE_CLASSES[role])

    def test_fixed_actual_report_preflights_both_missing_initial_roles(self):
        before = bytes(self.first_raw)
        expected_paths = {
            'PlayerController': '/Game/BluePrints/Characters/BP_DFMPlayerController.BP_DFMPlayerController_C',
            'GameState': '/Game/BluePrints/GameModes/TestGame/BP_GameState_PVPVE.BP_GameState_PVPVE_C',
        }
        for role in ('PlayerController', 'GameState'):
            with self.subTest(role=role):
                result = self.select(self.first_raw, role)
                self.assertEqual(result.metadata_report, self.archive_raw)
                self.assertEqual((result.source_relative_path, result.source_sha256),
                                 (ARCHIVE_PATH, ARCHIVE_SHA))
                self.assertEqual(result.provenance, 'archive_same_build_not_current_process')
                self.assertEqual(result.fallback_reason, 'missing_class')
                self.assertEqual(result.bootstrap.manifest.class_path, expected_paths[role])
                self.assertEqual(result.bootstrap.manifest.source_sha256, ARCHIVE_SHA)
                self.assertEqual(result.bootstrap.manifest.local_player_index,
                                 0 if role == 'PlayerController' else None)
                self.assertIsNone(result.bootstrap.manifest.game_replication_flags)
                self.assertFalse(result.bootstrap.native_acceptance)
                self.assertFalse(result.bootstrap.possession_verified)
                self.assertFalse(result.summary()['current_process_identity_claimed'])
                self.assertNotIn('address', json.dumps(result.summary()))
        self.assertEqual(self.first_raw, before)

    def test_complete_current_source_wins_with_different_report_addresses(self):
        def relocate(document):
            name = ROLE_CLASSES['PlayerController']
            klass = next(row for row in document['roots']['classes'] if row['name'] == name)
            candidate = self.candidate(document)
            klass['address'] += 0x20000000
            candidate['address'] += 0x20000000
            candidate['class_address'] = klass['address']
            candidate['class_outer_address'] += 0x20000000
            candidate['outer_address'] += 0x20000000
        raw = self.altered(relocate)
        result = self.select(raw)
        self.assertIs(result.metadata_report, raw)
        self.assertEqual(result.source_relative_path, 'work/tests/current-report.json')
        self.assertEqual(result.source_sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(result.bootstrap.metadata_source.sha256, result.source_sha256)
        self.assertEqual(result.provenance, 'current_process_metadata')
        self.assertIsNone(result.fallback_reason)

    def test_missing_template_uses_whole_archive_only_when_known_class_path_matches(self):
        def remove(document):
            document['roots']['named_template_candidates'] = [row for row in
                document['roots']['named_template_candidates']
                if row['class_name'] != ROLE_CLASSES['PlayerController']]
        raw = self.altered(remove)
        self.assertEqual(self.select(raw).fallback_reason, 'missing_template')
        document = json.loads(raw)
        klass = next(row for row in document['roots']['classes']
                     if row['name'] == ROLE_CLASSES['PlayerController'])
        klass['asset_path'] = '/Game/Other.BP_DFMPlayerController_C'
        with self.assertRaisesRegex(ValueError, 'Class path disagrees'):
            self.select(encode(document))

    def test_absent_role_without_config_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'no sealed source'):
            self.select(self.first_raw, archive_sources=None)

    def test_duplicate_current_class_or_template_cannot_fallback(self):
        for field, name in (('classes', 'name'), ('named_template_candidates', 'class_name')):
            def duplicate(document):
                row = next(row for row in document['roots'][field]
                           if row[name] == ROLE_CLASSES['PlayerController'])
                document['roots'][field].append(deepcopy(row))
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'Ambiguous current'):
                self.select(self.altered(duplicate))

    def test_bad_current_hook_binding_path_and_identity_do_not_fallback(self):
        for mutate in (
            lambda row: row['actor_channel_open_hook'].update(target_rva=0x12d4ddb1),
            lambda row: row['actor_channel_open_hook'].update(identity_rechecked=False),
            lambda row: row.update(class_address=row['class_address'] + 8),
            lambda row: row.update(asset_path='/Game/Other.Default__BP_DFMPlayerController_C'),
            lambda row: row.update(key='00' * 8),
        ):
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.select(self.altered(lambda doc: mutate(self.candidate(doc))))

    def test_current_report_failure_status_sha_build_and_recheck_cannot_fallback(self):
        for key, value in (('status', 'metadata_export_refused'), ('client_sha256', '0'*64),
                           ('kind', 'other_report')):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.select(self.altered(lambda doc: doc.update({key: value})))
        with self.assertRaises(ValueError):
            self.select(self.altered(lambda doc: doc['roots'].update(selected_roots_rechecked=False)))
        with self.assertRaises(ValueError):
            self.select(self.first_raw, current_source_sha256='0'*64)

    def test_invalid_existing_class_cannot_fallback_when_template_missing(self):
        document = deepcopy(self.archive_document)
        name = ROLE_CLASSES['PlayerController']
        document['roots']['named_template_candidates'] = [row for row in
            document['roots']['named_template_candidates'] if row['class_name'] != name]
        klass = next(row for row in document['roots']['classes'] if row['name'] == name)
        klass['key'] = '00'*8
        with self.assertRaisesRegex(ValueError, 'weak-key'):
            self.select(encode(document))

    def test_invalid_factory_arguments_are_not_hidden_by_archive(self):
        params = arguments('PlayerController')
        params['channel_index'] = 0
        with self.assertRaises(ValueError):
            self.select(self.first_raw, factory_arguments=params)
        params = arguments('PlayerController')
        params['source_sha256'] = ARCHIVE_SHA
        with self.assertRaisesRegex(ValueError, 'exclude role'):
            self.select(self.first_raw, factory_arguments=params)
        with self.assertRaises(ValueError):
            self.select(self.first_raw, role='Pawn')

    def test_factory_is_resolved_at_call_time_and_arguments_are_not_mutated(self):
        import native_actor_bootstrap
        params = arguments('PlayerController')
        before = deepcopy(params)
        with patch.object(native_actor_bootstrap, 'build_initial_actor_bootstrap',
                          wraps=native_actor_bootstrap.build_initial_actor_bootstrap) as factory:
            result = self.select(self.first_raw, factory_arguments=params)
            self.assertEqual(factory.call_count, 1)
            self.assertEqual(factory.call_args.args, (self.archive_raw,))
            self.assertEqual(factory.call_args.kwargs['source_sha256'], ARCHIVE_SHA)
            self.assertIsNotNone(result.bootstrap)
        self.assertEqual(params, before)

    def write_config(self, directory, report, **changes):
        raw = report if type(report) is bytes else encode(report)
        (directory/'report.json').write_bytes(raw)
        config = {'kind': 'pinned_initial_role_metadata_sources', 'client_sha256': CLIENT_SHA256,
            'roles': {'PlayerController': {'source_relative_path': 'report.json',
                                           'source_sha256': hashlib.sha256(raw).hexdigest()}}}
        config.update(changes)
        config_raw = encode(config)
        (directory/'config.json').write_bytes(config_raw)
        return config, config_raw

    def test_config_and_referenced_report_pins_are_exact_and_bounded(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            _, config_raw = self.write_config(directory, self.archive_raw)
            sha = hashlib.sha256(config_raw).hexdigest()
            sources = load_initial_role_sources(directory, config_relative_path='config.json',
                                                config_sha256=sha)
            self.assertEqual(sources.roles['PlayerController'].metadata_report, self.archive_raw)
            with self.assertRaises(TypeError):
                sources.roles['PlayerController'] = None
            (directory/'report.json').write_bytes(self.archive_raw + b' ')
            with self.assertRaisesRegex(ValueError, 'sealed SHA256'):
                load_initial_role_sources(directory, config_relative_path='config.json', config_sha256=sha)
            with self.assertRaises(ValueError):
                load_initial_role_sources(directory, config_relative_path='config.json', config_sha256='0'*64)

    def test_archive_incomplete_duplicate_or_wrong_build_is_refused(self):
        mutations = (
            lambda doc: doc.update(status='metadata_export_refused'),
            lambda doc: doc.update(client_sha256='0'*64),
            lambda doc: doc['roots'].update(selected_roots_rechecked=False),
            lambda doc: doc['roots']['named_template_candidates'].append(deepcopy(self.candidate(doc))),
        )
        for mutate in mutations:
            document = deepcopy(self.archive_document)
            mutate(document)
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as temp:
                directory = Path(temp)
                _, config_raw = self.write_config(directory, document)
                with self.assertRaises(ValueError):
                    load_initial_role_sources(directory, config_relative_path='config.json',
                                              config_sha256=hashlib.sha256(config_raw).hexdigest())

    def test_path_traversal_and_duplicate_config_keys_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            config, _ = self.write_config(directory, self.archive_raw)
            for path in ('../report.json', '/report.json', 'C:/report.json', 'work\\report.json'):
                config['roles']['PlayerController']['source_relative_path'] = path
                raw = encode(config)
                (directory/'config.json').write_bytes(raw)
                with self.subTest(path=path), self.assertRaises(ValueError):
                    load_initial_role_sources(directory, config_relative_path='config.json',
                                              config_sha256=hashlib.sha256(raw).hexdigest())
            raw = b'{"kind":"pinned_initial_role_metadata_sources","kind":"other"}'
            (directory/'config.json').write_bytes(raw)
            with self.assertRaisesRegex(ValueError, 'ambiguous'):
                load_initial_role_sources(directory, config_relative_path='config.json',
                                          config_sha256=hashlib.sha256(raw).hexdigest())


if __name__ == '__main__':
    unittest.main()
