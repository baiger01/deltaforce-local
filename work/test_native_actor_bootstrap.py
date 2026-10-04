"""Synthetic registry-to-manifest tests; no processes, UAC or network sends."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
import json
import unittest

import export_native_replication_metadata as exporter
from native_actor_bootstrap import (build_pawn_actor_bootstrap, build_initial_actor_bootstrap,
    CLIENT_SHA256, PAWN_CLASS, ROLE_CLASSES, QualifiedPCTailProfile,
    PC_OPEN_HOOK_SLOT, PC_BASE_OPEN_HOOK_RVA, PawnActorBootstrap)
from test_export_native_replication_metadata import Fixture
from test_native_metadata_archetypes import add_candidate
from dfserver.legacy_ds_bit_archive import BitReader
from dfserver.legacy_ds_guid_exports import read_guid_exports
from dfserver.legacy_ds_quantized_vector import QuantizedVector10


def report_fixture(*, relation='same_outer_as_class', zero_serial=False):
    fixture = Fixture()
    outer = fixture.pawn if relation == 'class' else fixture.packages['/Game/Test/Pawn']
    candidate = add_candidate(fixture, fixture.pawn, PAWN_CLASS, outer)
    if zero_serial:
        fixture.serial(fixture.pawn, 0)
        fixture.serial(candidate, 0)
    roots = exporter.discover_roots(fixture.session(), fixture.base)
    return {'kind':'existing_native_replication_metadata_export',
        'status':'metadata_export_complete', 'client_sha256':CLIENT_SHA256, 'roots':roots,
        'class_cache_exports':0, 'replication_layout_exports':0,
        'player_spawn_verified':False, 'playable_map_verified':False}


def arguments(report=None, **changes):
    raw = json.dumps(report or report_fixture(), ensure_ascii=False, indent=2).encode('utf-8')
    params = dict(source_relative_path='work/tests/synthetic-metadata-report.json',
        source_sha256=hashlib.sha256(raw).hexdigest(),
        level_path='/Game/Test/Map.TestWorld:PersistentLevel',
        level_source_relative_path='work/evidence/synthetic-level-source.json',
        level_source_sha256='b'*64, package_guid=3, class_guid=5, archetype_guid=7,
        level_package_guid=25, level_outer_guid=9, level_guid=11, actor_guid=2, channel_index=1, channel_sequence=9,
        connection_network_version=13, archive_network_version=13, max_packet_bytes=1024,
        references_resolvable=True)
    params.update(changes)
    return raw, params


def build(report=None, **changes):
    raw, params = arguments(report, **changes)
    return build_pawn_actor_bootstrap(raw, **params)


class PawnBootstrapTests(unittest.TestCase):
    def test_actual_registry_fixture_yields_observed_package_graph_and_empty_body(self):
        result = build()
        manifest = result.manifest
        self.assertEqual(manifest.class_path, '/Game/Test/Pawn.BP_DFMCharacter_C')
        self.assertEqual(manifest.archetype_path, '/Game/Test/Pawn.Default__BP_DFMCharacter_C')
        self.assertEqual(manifest.archetype_qualification, 'named_default_object_candidate')
        cls, template, level = manifest.exports
        self.assertEqual((cls.guid, cls.path, cls.outer.guid, cls.outer.path),
                         (5, PAWN_CLASS, 3, '/Game/Test/Pawn'))
        self.assertEqual((template.guid, template.outer.guid), (7, 3))
        self.assertEqual((level.guid, level.path, level.outer.guid, level.outer.path),
                         (11, 'PersistentLevel', 9, 'TestWorld'))
        self.assertEqual((level.outer.outer.guid, level.outer.outer.path,
                          level.outer.outer.outer), (25, '/Game/Test/Map', None))
        reader = BitReader(result.preflight.bunch.payload, bit_count=result.preflight.bunch.payload_bits)
        self.assertEqual(read_guid_exports(reader), manifest.exports)
        self.assertEqual(reader.remaining, 28)
        self.assertEqual(reader.read_payload(28), bytes.fromhex('040e1600'))
        self.assertEqual(reader.remaining, 0)
        self.assertEqual(result.preflight.actor_fields['content_blocks'], ())
        self.assertIsNone(manifest.local_player_index)
        self.assertTrue(result.preflight.bunch.open)
        self.assertTrue(result.preflight.bunch.reliable)
        self.assertTrue(result.preflight.bunch.package_exports)
        self.assertEqual(result.preflight.bunch.channel_name.hardcoded_index, 102)

    def test_class_outer_uses_observed_colon_without_fabricating_cdo_package(self):
        result = build(report_fixture(relation='class'))
        cls, template, _ = result.manifest.exports
        self.assertEqual(template.outer, cls)
        self.assertEqual(result.manifest.archetype_path,
                         '/Game/Test/Pawn.BP_DFMCharacter_C:Default__BP_DFMCharacter_C')
        binding = next(item for item in result.manifest.path_bindings if item.guid == 7)
        self.assertEqual(binding.separator_from_outer, ':')

    def test_level_chain_preserves_each_observed_package_world_and_level_name(self):
        result = build(level_path='/Game/Test/Arbitrary.ObservedOuter:ObservedLevel')
        self.assertEqual(result.manifest.exports[-1].outer.path, 'ObservedOuter')
        self.assertEqual(result.manifest.exports[-1].outer.outer.path, '/Game/Test/Arbitrary')
        self.assertEqual(result.manifest.exports[-1].path, 'ObservedLevel')
        binding = next(item for item in result.manifest.path_bindings if item.guid == 11)
        self.assertEqual(binding.full_path, '/Game/Test/Arbitrary.ObservedOuter:ObservedLevel')
        self.assertEqual(binding.separator_from_outer, ':')

    def test_source_bytes_verified_but_native_profile_level_contents_and_possession_not_claimed(self):
        result = build()
        summary = result.summary()
        self.assertTrue(summary['metadata_source']['contents_sha_verified'])
        self.assertFalse(summary['level_source']['contents_sha_verified'])
        for field in ('network_profile_verified', 'native_acceptance', 'player_spawn_verified', 'possession_verified'):
            self.assertFalse(summary[field])
            self.assertFalse(getattr(result, field))
        self.assertFalse(result.preflight.native_acceptance)
        with self.assertRaises(FrozenInstanceError):
            result.native_acceptance = True
        self.assertNotIn('roots', summary)
        self.assertNotIn('class_address', summary)

    def test_metadata_status_build_and_selected_root_qualification_are_required(self):
        for key, value in (('status','metadata_export_refused'), ('kind','other_report'),
                           ('client_sha256','c'*64)):
            report = report_fixture()
            report[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                build(report)
        for roots in (None, {}, {'selected_roots_rechecked':False}):
            report = report_fixture()
            report['roots'] = roots
            with self.subTest(roots=roots), self.assertRaises(ValueError):
                build(report)

    def test_missing_or_duplicate_pawn_class_cannot_be_guessed_or_deduplicated(self):
        for duplicate in (False, True):
            report = report_fixture()
            pawn = next(row for row in report['roots']['classes'] if row['name'] == PAWN_CLASS)
            report['roots']['classes'] = [pawn, deepcopy(pawn)] if duplicate else []
            with self.subTest(duplicate=duplicate), self.assertRaisesRegex(ValueError, 'Exactly one selected Pawn'):
                build(report)

    def test_missing_or_duplicate_candidate_cannot_be_guessed_or_deduplicated(self):
        for duplicate in (False, True):
            report = report_fixture()
            candidate = report['roots']['named_template_candidates'][0]
            report['roots']['named_template_candidates'] = [candidate, deepcopy(candidate)] if duplicate else []
            with self.subTest(duplicate=duplicate), self.assertRaisesRegex(ValueError, 'Exactly one named Pawn'):
                build(report)

    def test_candidate_binding_name_paths_and_metadata_only_qualification_are_strict(self):
        changes = {
            'class_address':0x710000000, 'class_name':'BP_Other_C',
            'name':'Default__Other', 'selection_kind':'guessed_template',
            'class_default_object_flags_verified':True, 'package_map_resolution_verified':True,
            'class_outer_address':0, 'outer_address':0x720000000,
            'outer_relation':'unrelated', 'outer_path':'/Game/Other',
            'class_outer_path':'/Game/Other', 'asset_path':'/Game/Other.Default__BP_DFMCharacter_C',
        }
        for key, value in changes.items():
            report = report_fixture()
            report['roots']['named_template_candidates'][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                build(report)
        for key in ('outer_path','class_outer_path','outer_relation','class_outer_address',
                    'selection_kind','class_default_object_flags_verified','package_map_resolution_verified'):
            report = report_fixture()
            del report['roots']['named_template_candidates'][0][key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                build(report)

    def test_unobserved_class_package_or_uclass_used_as_template_is_refused(self):
        for field in ('asset_path','class_outer_path'):
            report = report_fixture()
            if field == 'asset_path':
                cls = next(row for row in report['roots']['classes'] if row['name'] == PAWN_CLASS)
                cls[field] = '/Game/Other.BP_DFMCharacter_C'
            else:
                report['roots']['named_template_candidates'][0][field] = '/Game/Test/Pawn.OtherOuter'
            with self.subTest(field=field), self.assertRaises(ValueError):
                build(report)
        report = report_fixture()
        candidate = report['roots']['named_template_candidates'][0]
        candidate['address'] = candidate['class_address']
        with self.assertRaisesRegex(ValueError, 'binding'):
            build(report)

    def test_registry_identity_bytes_required_and_zero_serial_metadata_still_allowed(self):
        self.assertFalse(build(report_fixture(zero_serial=True)).player_spawn_verified)
        for key, value in (('object_index',True), ('serial',-1), ('key','0000000000000000'), ('address',True)):
            report = report_fixture()
            report['roots']['named_template_candidates'][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                build(report)

    def test_exact_report_bytes_reject_mutation_mapping_and_ambiguous_json(self):
        raw, params = arguments()
        for wrong in (raw+b' ', bytearray(raw), json.loads(raw)):
            with self.subTest(kind=type(wrong).__name__), self.assertRaises(ValueError):
                build_pawn_actor_bootstrap(wrong, **params)
        duplicated = raw.rstrip()[:-1]+b',"status":"metadata_export_complete"}'
        params['source_sha256'] = hashlib.sha256(duplicated).hexdigest()
        with self.assertRaisesRegex(ValueError, 'malformed or ambiguous'):
            build_pawn_actor_bootstrap(duplicated, **params)

    def test_source_pins_require_relative_paths_and_lowercase_sha_for_both_sources(self):
        for prefix in ('source', 'level_source'):
            for path in ('/absolute','C:/file','../file','work/../file','work\\file','work//file',''):
                with self.subTest(prefix=prefix, path=path), self.assertRaises(ValueError):
                    build(**{prefix+'_relative_path':path})
            for sha in ('B'*64, 'b'*63, 'not-a-sha', None):
                with self.subTest(prefix=prefix, sha=sha), self.assertRaises(ValueError):
                    build(**{prefix+'_sha256':sha})

    def test_guids_profile_channel_and_packet_budget_delegate_to_real_preflight(self):
        for changes in (dict(class_guid=True), dict(class_guid=4), dict(class_guid=7),
                dict(package_guid=5), dict(level_package_guid=True), dict(level_package_guid=24),
                dict(level_package_guid=9), dict(level_package_guid=3),
                dict(level_outer_guid=3), dict(level_guid=5),
                dict(actor_guid=3), dict(actor_guid=0), dict(channel_index=0),
                dict(channel_sequence=1024), dict(archive_network_version=12),
                dict(connection_network_version=True), dict(references_resolvable=False),
                dict(max_packet_bytes=True), dict(max_packet_bytes=1493), dict(max_packet_bytes=16)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                build(**changes)

    def test_incomplete_level_path_and_pc_tail_or_content_options_are_not_supported(self):
        for path in ('Iris_Entry','/Game/Test/Map','/Game/Test/Map:',
                     '/Game//Map.Map:PersistentLevel', '/Game/Test/Map.PersistentLevel',
                     '/Game/Test/Map:PersistentLevel', '/Game/Test/Map.World:Inner:PersistentLevel',
                     '/Game/Test/Map.World.Nested:PersistentLevel'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                build(level_path=path)
        for changes in (dict(local_player_index=0), dict(content_blocks=())):
            raw, params = arguments()
            params.update(changes)
            with self.subTest(changes=changes), self.assertRaises(TypeError):
                build_pawn_actor_bootstrap(raw, **params)


def multi_role_report(*, relation='same_outer_as_class'):
    fixture = Fixture()
    roles = ((fixture.pawn, PAWN_CLASS, '/Game/Test/Pawn'),
             (fixture.pc, ROLE_CLASSES['PlayerController'], '/Game/Test/PC'),
             (fixture.gs, ROLE_CLASSES['GameState'], '/Game/Test/GS'))
    for ordinal, (klass, label, package) in enumerate(roles):
        outer = klass if relation == 'class' else fixture.packages[package]
        add_candidate(fixture, klass, label, outer, ordinal)
    roots = exporter.discover_roots(fixture.session(), fixture.base)
    pc = next(row for row in roots['named_template_candidates']
              if row['class_name'] == ROLE_CLASSES['PlayerController'])
    # An independently supplied metadata observation, not an invoked native hook.
    pc['actor_channel_open_hook'] = {
        'slot': 0x3d8, 'vtable_address': fixture.base + 0x1b221ff0,
        'target_address': fixture.base + 0x12d4ddb0, 'target_rva': 0x12d4ddb0,
        'target_module_sha256': CLIENT_SHA256, 'inside_pinned_image': True,
        'identity_rechecked': True, 'status': 'observed_pinned_image_method'}
    return {'kind': 'existing_native_replication_metadata_export',
            'status': 'metadata_export_complete', 'client_sha256': CLIENT_SHA256, 'roots': roots}


def pc_profile(**changes):
    parameters = dict(client_sha256=CLIENT_SHA256,
        source_relative_path='work/evidence/native-post-join-pc-open-rotator-full-roots.json',
        source_sha256='1e87b75e57daf0ef03278df0751a6cb8b71f4e9ae8d2f6608844a6c494c377d7',
        hook_target_rva=0x12d4ddb0)
    parameters.update(changes)
    return QualifiedPCTailProfile(**parameters)


def build_role(role, report=None, **changes):
    raw, params = arguments(report if report is not None else multi_role_report())
    params.update(changes)
    return build_initial_actor_bootstrap(raw, role=role, **params)


class MultiRoleBootstrapTests(unittest.TestCase):
    def test_exact_collector_role_names_and_observed_default_paths(self):
        self.assertEqual(set(ROLE_CLASSES.values()), exporter.TARGET_CLASSES)
        packages = {'Pawn': '/Game/Test/Pawn', 'GameState': '/Game/Test/GS',
                    'PlayerController': '/Game/Test/PC'}
        report = multi_role_report()
        for role, class_name in ROLE_CLASSES.items():
            with self.subTest(role=role):
                extras = dict(local_player_index=0, pc_tail_profile=pc_profile()) if role == 'PlayerController' else {}
                result = build_role(role, report, **extras)
                self.assertEqual(result.manifest.class_path, packages[role] + '.' + class_name)
                self.assertEqual(result.manifest.archetype_path, packages[role] + '.Default__' + class_name)
                self.assertEqual(result.summary()['role'], role)
                self.assertFalse(result.native_acceptance)
                self.assertFalse(result.player_spawn_verified)
                self.assertEqual(result.preflight.actor_fields['content_blocks'], ())
                self.assertEqual(result.manifest.local_player_index, 0 if role == 'PlayerController' else None)

    def test_pawn_api_signature_return_type_and_rejections_are_preserved(self):
        result = build()
        self.assertIs(type(result), PawnActorBootstrap)
        self.assertEqual(result.summary()['kind'], 'pure_metadata_pawn_actor_bootstrap')
        raw, params = arguments()
        with self.assertRaises(TypeError):
            build_pawn_actor_bootstrap(raw, **params, pc_tail_profile=pc_profile())

    def test_game_state_and_pc_class_outer_preserve_actual_colon_path(self):
        report = multi_role_report(relation='class')
        for role in ('GameState', 'PlayerController'):
            with self.subTest(role=role):
                extras = dict(local_player_index=0, pc_tail_profile=pc_profile()) if role == 'PlayerController' else {}
                result = build_role(role, report, **extras)
                self.assertEqual(result.manifest.exports[1].outer, result.manifest.exports[0])
                self.assertEqual(result.manifest.archetype_path,
                    result.manifest.class_path + ':Default__' + ROLE_CLASSES[role])

    def test_each_role_missing_or_duplicate_class_and_template_are_rejected(self):
        for role, class_name in ROLE_CLASSES.items():
            extras = dict(local_player_index=0, pc_tail_profile=pc_profile()) if role == 'PlayerController' else {}
            for key in ('classes', 'named_template_candidates'):
                for duplicate in (False, True):
                    report = multi_role_report()
                    field = 'name' if key == 'classes' else 'class_name'
                    row = next(item for item in report['roots'][key] if item.get(field) == class_name)
                    others = [item for item in report['roots'][key] if item.get(field) != class_name]
                    report['roots'][key] = others + ([row, deepcopy(row)] if duplicate else [])
                    with self.subTest(role=role, key=key, duplicate=duplicate), self.assertRaisesRegex(ValueError, 'Exactly one'):
                        build_role(role, report, **extras)

    def test_cross_role_candidate_does_not_authorize_wrong_class(self):
        for role in ('GameState', 'PlayerController'):
            report = multi_role_report()
            selected = next(row for row in report['roots']['named_template_candidates']
                            if row['class_name'] == ROLE_CLASSES[role])
            selected['class_name'] = PAWN_CLASS
            extras = dict(local_player_index=0, pc_tail_profile=pc_profile()) if role == 'PlayerController' else {}
            with self.subTest(role=role), self.assertRaisesRegex(ValueError, 'binding or qualification'):
                build_role(role, report, **extras)

    def test_pc_needs_explicit_index_and_qualified_profile(self):
        for changes in ({}, {'local_player_index': 0}, {'pc_tail_profile': pc_profile()},
                {'local_player_index': False, 'pc_tail_profile': pc_profile()},
                {'local_player_index': 1, 'pc_tail_profile': pc_profile()},
                {'local_player_index': 0, 'pc_tail_profile': {}},
                {'local_player_index': 0, 'pc_tail_profile': pc_profile(hook_target_rva=0x2d4ddb0)},
                {'local_player_index': 0, 'pc_tail_profile': pc_profile(client_sha256='a'*64)},
                {'local_player_index': 0, 'pc_tail_profile': pc_profile(source_relative_path='../unsealed')},
                {'local_player_index': 0, 'pc_tail_profile': pc_profile(source_sha256='A'*64)}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                build_role('PlayerController', **changes)

    def test_metadata_base_hook_qualification_is_strict_and_derived_target_refused(self):
        alterations = {'slot': True, 'target_rva': 0x2d4ddb0,
            'target_module_sha256': 'd'*64, 'inside_pinned_image': False,
            'identity_rechecked': False, 'status': 'target_outside_pinned_image',
            'vtable_address': 0, 'target_address': None}
        for key, value in alterations.items():
            report = multi_role_report()
            row = next(item for item in report['roots']['named_template_candidates']
                       if item['class_name'] == ROLE_CLASSES['PlayerController'])
            row['actor_channel_open_hook'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                build_role('PlayerController', report, local_player_index=0, pc_tail_profile=pc_profile())
        for missing in (None, 'slot', 'target_rva', 'identity_rechecked', 'inside_pinned_image',
                        'vtable_address', 'target_address', 'target_module_sha256', 'status'):
            report = multi_role_report()
            row = next(item for item in report['roots']['named_template_candidates']
                       if item['class_name'] == ROLE_CLASSES['PlayerController'])
            if missing is None:
                del row['actor_channel_open_hook']
            else:
                del row['actor_channel_open_hook'][missing]
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                build_role('PlayerController', report, local_player_index=0, pc_tail_profile=pc_profile())

    def test_pc_tail_is_last_unaligned_raw_u8_after_nonzero_spawn_location(self):
        result = build_role('PlayerController', local_player_index=0, pc_tail_profile=pc_profile(),
                            location=QuantizedVector10((1, -2, 3)))
        reader = BitReader(result.preflight.bunch.payload, bit_count=result.preflight.bunch.payload_bits)
        read_guid_exports(reader)
        # Independently derived bit fixture: packed GUID bytes 04/0e/16; location
        # present1/compressed1/width1; biased xyz5/2/7; rotation/scale/velocity0;
        # then raw8 index0. Actor section length51 is not byte aligned.
        self.assertEqual(reader.remaining, 51)
        self.assertEqual(reader.read_payload(51), bytes.fromhex('040e1687ea0000'))
        self.assertEqual(reader.remaining, 0)
        self.assertEqual(result.summary()['content_blocks'], 0)
        self.assertFalse(result.summary()['derived_hook_semantics_assumed'])

    def test_other_roles_have_no_pc_tail_and_pc_arguments_are_not_implicit(self):
        for role in ('Pawn', 'GameState'):
            result = build_role(role)
            reader = BitReader(result.preflight.bunch.payload, bit_count=result.preflight.bunch.payload_bits)
            read_guid_exports(reader)
            self.assertEqual(reader.remaining, 28)
            self.assertEqual(reader.read_payload(28), bytes.fromhex('040e1600'))
            for changes in (dict(local_player_index=0), dict(pc_tail_profile=pc_profile())):
                with self.subTest(role=role, changes=changes), self.assertRaises(ValueError):
                    build_role(role, **changes)

    def test_pc_source_summary_does_not_export_observed_pointers_or_claim_native_acceptance(self):
        result = build_role('PlayerController', local_player_index=0, pc_tail_profile=pc_profile())
        summary = result.summary()
        self.assertEqual(summary['pc_tail_hook_target_rva'], 0x12d4ddb0)
        self.assertEqual(summary['local_player_index'], 0)
        self.assertFalse(summary['pc_tail_profile_source']['contents_sha_verified'])
        for name in ('native_acceptance', 'player_spawn_verified', 'possession_verified', 'network_profile_verified'):
            self.assertFalse(summary[name])
        self.assertNotIn('target_address', summary)
        self.assertNotIn('vtable_address', summary)
        self.assertNotIn('actor_channel_open_hook', summary)
        with self.assertRaises(FrozenInstanceError):
            result.pc_tail_hook_target_rva = 0

    def test_unknown_roles_content_and_profile_arguments_are_not_guessed(self):
        for role in ('pawn', PAWN_CLASS, 'Controller', 'GameMode', None):
            with self.subTest(role=role), self.assertRaises(ValueError):
                build_role(role)
        raw, params = arguments(multi_role_report())
        with self.assertRaises(TypeError):
            build_initial_actor_bootstrap(raw, role='GameState', **params, content_blocks=())

if __name__ == '__main__':
    unittest.main()
