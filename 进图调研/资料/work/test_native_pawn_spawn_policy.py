"""Local policy/resolver tests: sealed files and pure factories, no native I/O."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from native_actor_bootstrap import build_pawn_actor_bootstrap
from native_pawn_spawn_policy import (
    INTERFACE_PATH, INTERFACE_SHA256, POLICY_PATH, STATE_SOURCE, STATE_SOURCE_SHA256,
    build_local_pawn_resolver, load_local_pawn_policy,
)
from test_native_actor_game_spawn_profile import ROOT, REPORT_RAW, arguments
from dfserver.legacy_ds_actor_bunch import build_actor_bunch
from dfserver.legacy_ds_bit_archive import BitReader
from dfserver.legacy_ds_game_spawn_flags import GameSpawnFlags
from dfserver.legacy_ds_guid_exports import read_guid_exports
from dfserver.legacy_ds_match_admission import LocalMatchTicket


class LocalPawnSpawnPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='df-pawn-policy-offline-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.pins = {}
        self.write(POLICY_PATH, (ROOT / POLICY_PATH).read_bytes())
        self.write(INTERFACE_PATH, REPORT_RAW)
        self.write(STATE_SOURCE, (ROOT / STATE_SOURCE).read_bytes())
        self.policy = load_local_pawn_policy(self.root, self.pins)
        self.arguments = arguments()
        self.prepared = build_pawn_actor_bootstrap(REPORT_RAW, **self.arguments)
        self.pawn_fields = dict(self.prepared.preflight.actor_fields)
        self.other_fields = dict(self.pawn_fields, actor_guid=4, channel_index=2)
        self.fields = (self.other_fields, self.pawn_fields)
        self.ticket = LocalMatchTicket(100, 200, 2201, 142201103, 303,
                                       'a'*32, 10.0, 130.0)

    def write(self, relative, raw):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        self.pins[relative] = hashlib.sha256(raw).hexdigest()

    def resolver(self, **changes):
        parameters = dict(root=self.root, pins=self.pins, metadata_raw=REPORT_RAW,
                          pawn_arguments=self.arguments, expected_policy=self.policy)
        parameters.update(changes)
        return build_local_pawn_resolver(**parameters)

    def assert_unchanged_rejection(self, resolve, ticket, fields):
        before = deepcopy(fields)
        with self.assertRaises(ValueError):
            resolve(ticket, fields)
        self.assertEqual(fields, before)

    def test_real_source_policy_and_report_compute_zero_without_touching_other_actors(self):
        self.assertEqual(hashlib.sha256(REPORT_RAW).hexdigest(), INTERFACE_SHA256)
        self.assertEqual(self.pins[STATE_SOURCE], STATE_SOURCE_SHA256)
        before = deepcopy(self.fields)
        result = self.resolver()(self.ticket, self.fields)
        self.assertEqual(self.fields, before)
        self.assertEqual(result[0], self.other_fields)
        self.assertIsNot(result[0], self.other_fields)
        self.assertIsNot(result[1], self.pawn_fields)
        expected = dict(self.pawn_fields, game_replication_flags=0)
        self.assertEqual(result[1], expected)
        bunch = build_actor_bunch(channel_sequence=9, max_packet_bytes=1024, **result[1])
        self.assertEqual(bunch.payload_bits, self.prepared.preflight.bunch.payload_bits+8)
        reader = BitReader(bunch.payload, bit_count=bunch.payload_bits)
        read_guid_exports(reader)
        self.assertEqual(tuple(reader.read_packed_int() for _ in range(3)), (2, 7, 11))
        self.assertEqual(tuple(reader.read_bool() for _ in range(4)), (False,)*4)
        self.assertEqual(reader.read_bytes(1), b'\x00')
        self.assertEqual(reader.remaining, 0)
        self.assertIsNone(self.pawn_fields['game_replication_flags'])
        self.assertEqual(self.policy['remote_role'], 2)
        self.assertIs(self.policy['replication_enabled'], True)
        self.assertIsNone(self.policy['connection_actor_guid'])
        self.assertEqual(self.policy['connection_focus_target_guids'], [])

    def test_none_factory_behavior_is_not_changed_by_loading_or_resolving_policy(self):
        original = self.prepared.preflight.bunch
        self.resolver()(self.ticket, self.fields)
        same = build_pawn_actor_bootstrap(REPORT_RAW, **self.arguments, game_spawn_profile=None)
        self.assertEqual(same.preflight.bunch, original)
        self.assertIsNone(same.manifest.game_replication_flags)
        self.assertNotIn('game_spawn_profile', same.summary())
        reader = BitReader(original.payload, bit_count=original.payload_bits)
        read_guid_exports(reader)
        self.assertEqual(reader.remaining, 28)
        self.assertEqual(reader.read_payload(28), bytes.fromhex('040e1600'))

    def test_wrong_map_ticket_type_missing_or_duplicate_pawn_reject_unchanged(self):
        resolve = self.resolver()
        for ticket in (replace(self.ticket, map_id=2202), None, {'map_id': 2201}):
            with self.subTest(ticket_type=type(ticket).__name__):
                self.assert_unchanged_rejection(resolve, ticket, self.fields)
        for fields in (list(self.fields), (self.other_fields,),
                       (self.pawn_fields, dict(self.pawn_fields)), ()):
            with self.subTest(kind=type(fields).__name__, length=len(fields)):
                self.assert_unchanged_rejection(resolve, self.ticket, fields)

    def test_registered_guid_graph_version_and_location_changes_reject_unchanged(self):
        resolve = self.resolver()
        graph = self.pawn_fields['exports']
        cases = (dict(archetype_guid=5), dict(level_guid=9), dict(channel_index=5),
                 dict(archive_network_version=12), dict(force_unicode=True),
                 dict(exports=(replace(graph[0], path='WrongClass'),)+graph[1:]))
        for changes in cases:
            fields = (self.other_fields, dict(self.pawn_fields, **changes))
            with self.subTest(changes=list(changes)):
                self.assert_unchanged_rejection(resolve, self.ticket, fields)
        self.assert_unchanged_rejection(resolve, self.ticket,
                                       (self.other_fields, dict(self.pawn_fields, actor_guid=8)))

    def test_non_dict_missing_bool_or_invalid_actor_guids_reject_consistently(self):
        resolve = self.resolver()
        for other in ('actor', None, {}, {'actor_guid':True}, {'actor_guid':0},
                      {'actor_guid':-1}, {'actor_guid':4.0}):
            fields = (other, self.pawn_fields)
            with self.subTest(other=other):
                self.assert_unchanged_rejection(resolve, self.ticket, fields)

    def test_wrong_allocated_guid_and_metadata_source_hash_reject(self):
        with self.assertRaisesRegex(ValueError, 'actual allocated Actor'):
            self.resolver(pawn_arguments=dict(self.arguments, actor_guid=8))
        wrong_metadata_pin = dict(self.arguments, source_sha256='f'*64)
        self.assert_unchanged_rejection(self.resolver(pawn_arguments=wrong_metadata_pin),
                                       self.ticket, self.fields)
        self.assert_unchanged_rejection(self.resolver(metadata_raw=REPORT_RAW+b' '),
                                       self.ticket, self.fields)

    def test_policy_and_interface_file_pins_cannot_be_substituted(self):
        for relative in (POLICY_PATH, INTERFACE_PATH, STATE_SOURCE):
            pins = dict(self.pins, **{relative:'f'*64})
            with self.subTest(relative=relative), self.assertRaisesRegex(ValueError, 'changed'):
                load_local_pawn_policy(self.root, pins)
        modified = deepcopy(self.policy)
        modified['remote_role'] = 1
        with self.assertRaisesRegex(ValueError, 'between launch and preparation'):
            self.resolver(expected_policy=modified)
        self.write(INTERFACE_PATH, b'{}')
        with self.assertRaisesRegex(ValueError, 'interface observation'):
            load_local_pawn_policy(self.root, self.pins)

    def test_semantics_content_and_local_source_byte_bound_are_checked(self):
        self.write(STATE_SOURCE, b'{}')
        with self.assertRaisesRegex(ValueError, 'role semantics'):
            load_local_pawn_policy(self.root, self.pins)
        self.write(STATE_SOURCE, (ROOT / STATE_SOURCE).read_bytes())
        self.write(INTERFACE_PATH, bytes(1024*1024+1))
        with self.assertRaisesRegex(ValueError, 'bounded project'):
            load_local_pawn_policy(self.root, self.pins)

    def test_policy_loader_refuses_unconfigured_defaults_and_wrong_types(self):
        changes = (dict(map_id=2202), dict(map_id=True), dict(actor_guid=4),
                   dict(remote_role=True), dict(remote_role=1), dict(replication_enabled=1),
                   dict(owner_policy='any_player'), dict(connection_actor_guid=2),
                   dict(connection_focus_target_guids=[2]), dict(native_spawn_verified=True),
                   dict(state_origin='official_packet'), dict(interface_source={}),
                   dict(client_sha256='f'*64))
        for change in changes:
            policy = dict(self.policy, **change)
            self.write(POLICY_PATH, json.dumps(policy).encode('utf-8'))
            with self.subTest(change=list(change)), self.assertRaisesRegex(ValueError, 'Unsupported'):
                load_local_pawn_policy(self.root, self.pins)

    def test_resolver_snapshots_argument_mapping_and_policy_does_not_mutate_inputs(self):
        arguments_before, policy_before = deepcopy(self.arguments), deepcopy(self.policy)
        resolve = self.resolver()
        result = resolve(self.ticket, self.fields)
        self.assertEqual(self.arguments, arguments_before)
        self.assertEqual(self.policy, policy_before)
        self.arguments['archetype_guid'] = 999
        self.policy['remote_role'] = 0
        self.assertEqual(resolve(self.ticket, self.fields), result)

    def test_state_downgrade_requires_persistent_model_and_cannot_silently_commit(self):
        changed = replace(self.prepared, game_spawn_result=GameSpawnFlags(1, 1, True, 'test'))
        with patch('native_actor_bootstrap.build_pawn_actor_bootstrap', return_value=changed):
            self.assert_unchanged_rejection(self.resolver(), self.ticket, self.fields)


if __name__ == '__main__':
    unittest.main()
