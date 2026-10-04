"""Actual-path candidate selection without a CDO getter or guessed package."""
import struct
import unittest
from unittest.mock import patch

import export_native_replication_metadata as exporter
from native_replication_metadata_core import MetadataSession
from test_export_native_replication_metadata import Fixture


# Fixed independently encoded NamePool bytes, not a production name encoder.
DEFAULT_NAMES = {
    'BP_DFMCharacter_C': 'bb9a999e8a938ba0a0bdafa0bbb9b2bc979e8d9e9c8b9a8da0bc',
    'BP_DFMPlayerController_C': '3b1a191e0a130b20203d2f203b39322f131e061a0d3c10110b0d1013131a0d203c',
    'BP_GameState_PVPVE_C': '3b1a191e0a130b20203d2f20381e121a2c0b1e0b1a202f292f293a203c',
}


def add_candidate(fixture, klass, class_name, outer, ordinal=0):
    name = 'Default__' + class_name
    offset = 0x4000 + ordinal * 128
    raw = bytes.fromhex(DEFAULT_NAMES[class_name])
    fixture.memory.write(fixture.block + offset, struct.pack('<H', len(raw) << 6) + raw)
    fixture.tokens[name] = struct.pack('<II', offset // 2, 0)
    address = fixture.allocate()
    fixture.memory.write(address, struct.pack('<Q', 0))
    fixture.describe(address, name, klass, 0, outer=outer)
    fixture.memory.write(fixture.base + 0x1e34ee5c, struct.pack('<i', len(fixture.rows)))
    return address


class NamedArchetypeTests(unittest.TestCase):
    def test_package_outer_candidates_have_observed_paths_for_all_roles(self):
        fixture = Fixture()
        expected = set()
        for ordinal, (klass, label, package) in enumerate((
            (fixture.pc, 'BP_DFMPlayerController_C', '/Game/Test/PC'),
            (fixture.pawn, 'BP_DFMCharacter_C', '/Game/Test/Pawn'),
            (fixture.gs, 'BP_GameState_PVPVE_C', '/Game/Test/GS'),
        )):
            add_candidate(fixture, klass, label, fixture.packages[package], ordinal)
            expected.add(package + '.Default__' + label)
        roots = exporter.discover_roots(fixture.session(), fixture.base)
        self.assertEqual({row['asset_path'] for row in roots['named_template_candidates']}, expected)
        self.assertEqual(roots['missing_named_templates'], [])
        self.assertTrue(all(row['outer_relation'] == 'same_outer_as_class' for row in roots['named_template_candidates']))
        self.assertTrue(all(row['class_default_object_flags_verified'] is False for row in roots['named_template_candidates']))
        self.assertTrue(all(row['package_map_resolution_verified'] is False for row in roots['named_template_candidates']))

    def test_class_outer_preserves_resolved_subobject_separator(self):
        fixture = Fixture()
        address = add_candidate(fixture, fixture.pawn, 'BP_DFMCharacter_C', fixture.pawn)
        roots = exporter.discover_roots(fixture.session(), fixture.base)
        row, = roots['named_template_candidates']
        self.assertEqual(row['address'], address)
        self.assertEqual(row['outer_relation'], 'class')
        self.assertEqual(row['asset_path'], '/Game/Test/Pawn.BP_DFMCharacter_C:Default__BP_DFMCharacter_C')

    def test_name_from_unrelated_outer_is_not_read_or_admitted(self):
        fixture = Fixture()
        address = add_candidate(fixture, fixture.pawn, 'BP_DFMCharacter_C', fixture.packages['/Game/Test/PC'])
        roots = exporter.discover_roots(fixture.session(), fixture.base)
        self.assertEqual(roots['named_template_candidates'], [])
        self.assertNotIn((address + 0x1c, 8), fixture.memory.reads)

    def test_matching_outer_with_non_default_name_is_not_a_candidate(self):
        fixture = Fixture()
        address = add_candidate(fixture, fixture.pawn, 'BP_DFMCharacter_C', fixture.packages['/Game/Test/Pawn'])
        fixture.memory.write(address + 0x1c, fixture.tokens['Health'])
        roots = exporter.discover_roots(fixture.session(), fixture.base)
        self.assertEqual(roots['named_template_candidates'], [])

    def test_zero_native_serial_stays_metadata_only(self):
        fixture = Fixture()
        address = add_candidate(fixture, fixture.pawn, 'BP_DFMCharacter_C', fixture.packages['/Game/Test/Pawn'])
        fixture.serial(address, 0)
        roots = exporter.discover_roots(fixture.session(), fixture.base)
        row, = roots['named_template_candidates']
        self.assertIsNone(row['key'])
        self.assertEqual(row['serial'], 0)

    def test_same_name_in_duplicate_package_keeps_exact_class_binding(self):
        fixture = Fixture(duplicate=True)
        add_candidate(fixture, fixture.pawn, 'BP_DFMCharacter_C', fixture.packages['/Game/Test/Pawn'])
        add_candidate(fixture, fixture.duplicate, 'BP_DFMCharacter_C', fixture.packages['/Game/Test/Pawn2'])
        roots = exporter.discover_roots(fixture.session(), fixture.base)
        self.assertEqual({row['class_address'] for row in roots['named_template_candidates']}, {fixture.pawn, fixture.duplicate})
        self.assertEqual(len({row['asset_path'] for row in roots['named_template_candidates']}), 2)

    def test_changed_candidate_name_refuses_scan_instead_of_retaining_stale_path(self):
        fixture = Fixture()
        address = add_candidate(fixture, fixture.pawn, 'BP_DFMCharacter_C', fixture.packages['/Game/Test/Pawn'])
        original = exporter.object_path

        def change_after_resolving(reader, base, at):
            path = original(reader, base, at)
            if at == address:
                fixture.memory.write(address + 0x1c, fixture.tokens['Health'])
            return path

        with patch.object(exporter, 'object_path', side_effect=change_after_resolving):
            with self.assertRaisesRegex(ValueError, 'template candidate binding changed'):
                exporter.discover_roots(MetadataSession(fixture.memory.read), fixture.base)

    def test_changed_package_name_cannot_retain_old_archetype_path(self):
        fixture = Fixture()
        package = fixture.packages['/Game/Test/Pawn']
        address = add_candidate(fixture, fixture.pawn, 'BP_DFMCharacter_C', package)
        original = exporter.object_path

        def change_outer_name(reader, base, at):
            path = original(reader, base, at)
            if at == address:
                fixture.memory.write(package + 0x1c, fixture.tokens['Health'])
            return path

        with patch.object(exporter, 'object_path', side_effect=change_outer_name):
            with self.assertRaisesRegex(ValueError, 'metadata path changed|candidate path changed'):
                exporter.discover_roots(fixture.session(), fixture.base)

    def test_zero_serial_initialization_commits_current_key_after_semantic_rechecks(self):
        fixture = Fixture()
        fixture.serial(fixture.pawn, 0)
        original = exporter.object_path
        activated = []
        def initialize_when_metadata_path_is_observed(reader, base, at):
            path = original(reader, base, at)
            if at == fixture.pawn and not activated:
                fixture.serial(fixture.pawn, 555)
                activated.append(True)
            return path
        with patch.object(exporter, 'object_path', side_effect=initialize_when_metadata_path_is_observed):
            roots = exporter.discover_roots(fixture.session(), fixture.base)
        pawn, = [item for item in roots['classes'] if item['address'] == fixture.pawn]
        self.assertEqual(pawn['serial'], 555)
        self.assertEqual(pawn['key'], struct.pack('<iI', fixture.rows.index(fixture.pawn), 555).hex())
        self.assertTrue(pawn['native_serial_initialized_during_scan'])
        self.assertFalse(pawn['native_serial_continuity_proved'])
        self.assertEqual(pawn['class_ancestry'][0]['serial'], 555)
        self.assertTrue(roots['selected_roots_rechecked'])

    def test_initialized_serial_changes_are_still_refused(self):
        fixture = Fixture()
        original = exporter.object_path
        changed = []
        def recycle_when_path_is_observed(reader, base, at):
            path = original(reader, base, at)
            if at == fixture.pawn and not changed:
                fixture.serial(fixture.pawn, 777)
                changed.append(True)
            return path
        with patch.object(exporter, 'object_path', side_effect=recycle_when_path_is_observed):
            with self.assertRaisesRegex(ValueError, 'root identity changed') as refused:
                exporter.discover_roots(fixture.session(), fixture.base)
        context = refused.exception.metadata_failure_context
        self.assertEqual(context['address'], fixture.pawn)
        self.assertEqual(context['observed_serial'], 777)
        self.assertNotEqual(context['expected_serial'], 777)

    def test_zero_serial_initialization_cannot_hide_changed_metadata_name(self):
        fixture = Fixture()
        fixture.serial(fixture.pawn, 0)
        original = exporter.object_path
        changed = []
        def mutate_when_path_is_observed(reader, base, at):
            path = original(reader, base, at)
            if at == fixture.pawn and not changed:
                fixture.serial(fixture.pawn, 555)
                fixture.memory.write(fixture.pawn + 0x1c, fixture.tokens['Health'])
                changed.append(True)
            return path
        with patch.object(exporter, 'object_path', side_effect=mutate_when_path_is_observed):
            with self.assertRaisesRegex(ValueError, 'metadata path changed|descriptor changed'):
                exporter.discover_roots(fixture.session(), fixture.base)

    def test_unrelated_classifier_recycling_does_not_invalidate_selected_roots(self):
        fixture = Fixture()
        unrelated = fixture.allocate()
        fixture.describe(unrelated, 'Health', fixture.class_type, fixture.object_type)
        instance = fixture.allocate()
        fixture.describe(instance, 'Pawn', unrelated, 0)
        fixture.memory.write(fixture.base + 0x1e34ee5c, struct.pack('<i', len(fixture.rows)))
        original = exporter.iter_object_records
        def recycle_after_complete_scan(*args, **kwargs):
            yield from original(*args, **kwargs)
            fixture.serial(unrelated, 777)
        with patch.object(exporter, 'iter_object_records', side_effect=recycle_after_complete_scan):
            roots = exporter.discover_roots(fixture.session(), fixture.base)
        self.assertEqual(len(roots['classes']), 3)
        self.assertTrue(roots['selected_roots_rechecked'])
        self.assertFalse(roots['complete_global_inventory'])


if __name__ == '__main__':
    unittest.main()
