"""Offline qualification and pure flag composition, never native execution."""
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
from pathlib import Path
import unittest

from native_actor_bootstrap import (
    QualifiedGameSpawnProfile, build_initial_actor_bootstrap, build_pawn_actor_bootstrap,
)
from dfserver.legacy_ds_bit_archive import BitReader
from dfserver.legacy_ds_guid_exports import read_guid_exports


ROOT = Path(__file__).resolve().parent.parent
REPORT_RELATIVE = 'work/official-interface-observations/1791043432995-pid243608/result.json'
REPORT_SHA256 = 'dd5a951133d77361d2bb791a5aba5fa12d764acff4cef9127f204708b862462d'
REPORT_RAW = (ROOT / REPORT_RELATIVE).read_bytes()
FACTS = dict(original_state_u8=1, actor_byte93_mask20=False,
             owner_connection_match=True, connection_present=True,
             actor_is_connection_actor=False, actor_in_connection_actor_array=False)


def profile(**changes):
    parameters = dict(interface_report=REPORT_RAW, source_relative_path=REPORT_RELATIVE,
                      source_sha256=REPORT_SHA256, **FACTS)
    parameters.update(changes)
    return QualifiedGameSpawnProfile(**parameters)


def mutated_profile(mutator):
    report = json.loads(REPORT_RAW)
    mutator(report)
    raw = json.dumps(report, ensure_ascii=False).encode('utf-8')
    return profile(interface_report=raw, source_sha256=hashlib.sha256(raw).hexdigest())


def arguments(metadata_raw=REPORT_RAW, **changes):
    parameters = dict(source_relative_path=REPORT_RELATIVE,
        source_sha256=hashlib.sha256(metadata_raw).hexdigest(),
        level_path='/Game/Test/Map.Map:PersistentLevel',
        level_source_relative_path='work/evidence/test-game-spawn-level.json',
        level_source_sha256='b'*64, package_guid=3, class_guid=5, archetype_guid=7,
        level_package_guid=25, level_outer_guid=9, level_guid=11, actor_guid=2,
        channel_index=4, channel_sequence=9, connection_network_version=13,
        archive_network_version=13, max_packet_bytes=1024, references_resolvable=True)
    parameters.update(changes)
    return parameters


def build(metadata_raw=REPORT_RAW, **changes):
    return build_pawn_actor_bootstrap(metadata_raw, **arguments(metadata_raw, **changes))


class QualifiedGameSpawnProfileTests(unittest.TestCase):
    def test_exact_saved_official_report_pin_and_literal_byte(self):
        self.assertEqual(hashlib.sha256(REPORT_RAW).hexdigest(), REPORT_SHA256)
        result = build(game_spawn_profile=profile())
        reader = BitReader(result.preflight.bunch.payload,
                           bit_count=result.preflight.bunch.payload_bits)
        read_guid_exports(reader)
        self.assertEqual(tuple(reader.read_packed_int() for _ in range(3)), (2, 7, 11))
        self.assertEqual(tuple(reader.read_bool() for _ in range(4)), (False,)*4)
        self.assertEqual(reader.read_bytes(1), b'\x01')
        self.assertEqual(reader.remaining, 0)
        self.assertEqual(result.manifest.game_replication_flags, 1)
        self.assertTrue(result.game_spawn_source.contents_sha_verified)
        self.assertFalse(result.native_acceptance)
        self.assertFalse(result.player_spawn_verified)
        self.assertFalse(result.possession_verified)

    def test_none_preserves_exact_legacy_output_and_summary(self):
        old = build()
        explicit_none = build(game_spawn_profile=None)
        self.assertEqual(old, explicit_none)
        self.assertEqual(old.summary(), explicit_none.summary())
        self.assertNotIn('game_spawn_profile', old.summary())
        self.assertIsNone(old.manifest.game_replication_flags)
        zero = build(game_spawn_profile=profile(original_state_u8=0,
                                                owner_connection_match=False))
        self.assertEqual(zero.manifest.game_replication_flags, 0)
        self.assertEqual(zero.preflight.bunch.payload_bits, old.preflight.bunch.payload_bits+8)

    def test_literal_two_bit_cases_and_downgrade_use_only_explicit_facts(self):
        cases = ((dict(original_state_u8=0, owner_connection_match=False), 0, 0, False),
                 ({}, 1, 1, False),
                 (dict(original_state_u8=2, actor_byte93_mask20=True,
                       actor_is_connection_actor=True), 2, 2, False),
                 (dict(original_state_u8=2, actor_byte93_mask20=True,
                       owner_connection_match=False, actor_in_connection_actor_array=True), 3, 1, True))
        for changes, flags, effective, downgraded in cases:
            with self.subTest(changes=changes):
                inputs = profile(**changes)
                result = build(game_spawn_profile=inputs)
                summary = result.summary()['game_spawn_profile']
                self.assertEqual(summary['flags_u8'], flags)
                self.assertEqual(summary['effective_state_u8'], effective)
                self.assertIs(summary['state_downgraded'], downgraded)
                self.assertEqual(summary['facts'], {name:getattr(inputs, name) for name in FACTS})
                self.assertEqual(summary['facts_origin'], 'explicit_caller_server_model')
                self.assertFalse(summary['server_owned_facts_verified'])
                self.assertFalse(summary['native_acceptance'])
        with self.assertRaises(FrozenInstanceError):
            inputs.original_state_u8 = 0
        with self.assertRaises(TypeError):
            result.game_spawn_facts['original_state_u8'] = 0

    def test_reports_from_different_process_addresses_bind_by_exact_paths(self):
        # Exact address relationships are verified inside each report. Official
        # and local metadata addresses must never be equated across processes.
        metadata = json.loads(REPORT_RAW)
        klass = metadata['roots']['classes'][0]
        klass['address'] += 0x10000
        candidate = metadata['roots']['named_template_candidates'][0]
        candidate['address'] += 0x20000
        candidate['class_address'] = klass['address']
        raw = json.dumps(metadata).encode('utf-8')
        result = build(raw, game_spawn_profile=profile())
        self.assertEqual(result.manifest.game_replication_flags, 1)

    def test_pc_and_game_state_do_not_inherit_pawn_interface_profile(self):
        for role in ('PlayerController', 'GameState'):
            with self.subTest(role=role), self.assertRaisesRegex(ValueError, 'only for Pawn'):
                build_initial_actor_bootstrap(REPORT_RAW, role=role,
                    **arguments(game_spawn_profile=profile()))

    def test_profile_report_bytes_hash_and_source_path_are_checked(self):
        for changes in (dict(interface_report=bytearray(REPORT_RAW)),
                        dict(interface_report=REPORT_RAW+b' '),
                        dict(source_sha256='a'*64), dict(source_sha256=REPORT_SHA256.upper()),
                        dict(source_relative_path='../result.json'),
                        dict(source_relative_path='C:/result.json')):
            with self.subTest(changes=list(changes)), self.assertRaises(ValueError):
                build(game_spawn_profile=profile(**changes))
        duplicate = REPORT_RAW.rstrip()[:-1]+b',"status":"metadata_export_complete"}'
        with self.assertRaisesRegex(ValueError, 'malformed or ambiguous'):
            build(game_spawn_profile=profile(interface_report=duplicate,
                source_sha256=hashlib.sha256(duplicate).hexdigest()))
        with self.assertRaisesRegex(ValueError, 'exact QualifiedGameSpawnProfile'):
            build(game_spawn_profile=dict(FACTS))

    def test_failed_incomplete_or_wrong_build_reports_cannot_qualify(self):
        mutations = (lambda r:r.update(status='metadata_export_refused'),
                     lambda r:r.update(client_sha256='a'*64),
                     lambda r:r['roots'].update(selected_roots_rechecked=False),
                     lambda r:r['roots']['classes'].append(deepcopy(r['roots']['classes'][0])),
                     lambda r:r['roots']['named_template_candidates'].append(
                         deepcopy(r['roots']['named_template_candidates'][0])),
                     lambda r:r['actor_interface_observations'].append(
                         deepcopy(r['actor_interface_observations'][0])))
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                build(game_spawn_profile=mutated_profile(mutation))

    def test_observation_native_gate_method_identity_and_source_qualification(self):
        mutations = []
        changes = (dict(native_interface_gate_observed=False), dict(identity_rechecked=False),
                   dict(shipping_sha256='a'*64), dict(method_slot=True), dict(method_target_rva=0),
                   dict(main_vtable_rva=0), dict(secondary_vtable_rva=0),
                   dict(candidate_address=0), dict(class_address=0),
                   dict(class_path='/Game/Other.Other_C'), dict(candidate_path='/Game/Other.Default__Other_C'),
                   dict(method_code_prefix_bytes=31), dict(method_code_prefix_hex='00'*32),
                   dict(method_code_prefix_sha256='a'*64))
        for change in changes:
            mutations.append(lambda r, change=change:r['actor_interface_observations'][0].update(**change))
        mutations.extend((
            lambda r:r['actor_interface_observations'][0]['binding'].update(adjustment=0),
            lambda r:r['actor_interface_observations'][0]['binding'].update(interface_address=0),
            lambda r:r['actor_interface_observations'][0]['binding'].update(declaring_class_address=0),
            lambda r:r['actor_interface_observations'][0]['source_pins']['pawn_writer'].update(sha256='a'*64),
            lambda r:r['roots']['named_template_candidates'][0]['actor_channel_open_hook'].update(identity_rechecked=False),
            lambda r:r['roots']['classes'][0]['class_ancestry'].append(
                deepcopy(r['roots']['classes'][0]['class_ancestry'][7])),
        ))
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(ValueError):
                build(game_spawn_profile=mutated_profile(mutation))

    def test_report_cannot_substitute_a_consistent_different_asset_path(self):
        def rename(r):
            klass = r['roots']['classes'][0]
            candidate = r['roots']['named_template_candidates'][0]
            package = '/Game/Test/OtherPawn'
            klass['asset_path'] = package+'.'+klass['name']
            candidate['class_outer_path'] = candidate['outer_path'] = package
            candidate['asset_path'] = package+'.'+candidate['name']
        with self.assertRaisesRegex(ValueError, 'paths disagree'):
            build(game_spawn_profile=mutated_profile(rename))

    def test_missing_invalid_or_contradictory_server_facts_reject(self):
        parameters = dict(interface_report=REPORT_RAW, source_relative_path=REPORT_RELATIVE,
                          source_sha256=REPORT_SHA256, **FACTS)
        for name in FACTS:
            missing = dict(parameters)
            del missing[name]
            with self.subTest(missing=name), self.assertRaises(TypeError):
                QualifiedGameSpawnProfile(**missing)
        for changes in (dict(original_state_u8=True), dict(original_state_u8=-1),
                        dict(original_state_u8=256), dict(actor_byte93_mask20=1),
                        dict(owner_connection_match=0), dict(connection_present=False),
                        dict(actor_in_connection_actor_array='false')):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                build(game_spawn_profile=profile(**changes))
        result = build(game_spawn_profile=profile(connection_present=False,
            owner_connection_match=False, original_state_u8=2, actor_byte93_mask20=True))
        self.assertEqual(result.game_spawn_result.effective_state_u8, 1)
        self.assertEqual(result.manifest.game_replication_flags, 1)


if __name__ == '__main__':
    unittest.main()
