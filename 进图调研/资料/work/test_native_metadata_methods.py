"""Independent byte fixtures for source-selected method metadata; no execution."""
import struct
import unittest
from unittest.mock import patch

import export_native_replication_metadata as exporter
from native_replication_metadata_core import MetadataSession
from test_export_native_replication_metadata import Fixture
from test_native_metadata_archetypes import add_candidate


class MethodMetadataTests(unittest.TestCase):
    base = 0x140000000
    object_address = 0x600000000
    vtable = base + 0x1800

    def fixture(self, *, vtable=None, target=None, slot=0x3d8):
        data, reads = {}, []
        def write(address, value):
            data[address] = struct.pack('<Q', value)
        def read(address, count):
            reads.append((address, count))
            self.assertEqual(count, 8)
            return data[address]
        write(self.object_address, self.vtable if vtable is None else vtable)
        write(self.vtable + slot, self.base + 0x12d4ddb0 if target is None else target)
        return MetadataSession(read), write, reads

    def test_observed_rva_preserves_full_module_relative_offset(self):
        session, _, reads = self.fixture()
        row = exporter.observed_virtual_method(session, self.base, self.object_address, 0x3d8)
        self.assertEqual(row['target_rva'], 0x12d4ddb0)
        self.assertEqual(row['vtable_rva'], 0x1800)
        self.assertEqual(row['target_module_sha256'], exporter.SHIPPING_SHA256)
        self.assertTrue(row['inside_pinned_image'])
        self.assertFalse(row['identity_rechecked'])
        exporter.recheck_virtual_method(session, self.base, self.object_address, row)
        self.assertTrue(row['identity_rechecked'])
        self.assertEqual(len(reads), 4)

    def test_missing_and_foreign_tables_are_not_followed(self):
        for vtable, status in ((0, 'missing_vtable'), (self.base - 8, 'vtable_outside_pinned_image'),
                (self.base + exporter.SHIPPING_IMAGE_SIZE - 0x3d8, 'vtable_outside_pinned_image')):
            with self.subTest(vtable=vtable):
                session, _, reads = self.fixture(vtable=vtable)
                row = exporter.observed_virtual_method(session, self.base, self.object_address, 0x3d8)
                self.assertEqual(row['status'], status)
                self.assertIsNone(row['target_rva'])
                self.assertFalse(row['inside_pinned_image'])
                self.assertEqual(reads, [(self.object_address, 8)])

    def test_null_or_foreign_target_never_claims_shipping_binding(self):
        for target, status in ((0, 'null_method'), (self.base - 1, 'target_outside_pinned_image'),
                (self.base + exporter.SHIPPING_IMAGE_SIZE, 'target_outside_pinned_image')):
            with self.subTest(target=target):
                session, _, _ = self.fixture(target=target)
                row = exporter.observed_virtual_method(session, self.base, self.object_address, 0x3d8)
                self.assertEqual(row['status'], status)
                self.assertIsNone(row['target_module_sha256'])

    def test_changed_table_or_target_is_rejected_at_final_recheck(self):
        for address in (self.object_address, self.vtable + 0x3d8):
            session, write, _ = self.fixture()
            row = exporter.observed_virtual_method(session, self.base, self.object_address, 0x3d8)
            write(address, 0)
            with self.assertRaisesRegex(ValueError, 'virtual method binding changed'):
                exporter.recheck_virtual_method(session, self.base, self.object_address, row)
            self.assertFalse(row['identity_rechecked'])

    def test_property_slot_has_no_guessed_type_mapping(self):
        session, _, _ = self.fixture(slot=0x90, target=self.base + 0x123400)
        row = exporter.observed_virtual_method(session, self.base, self.object_address, 0x90)
        exporter.recheck_virtual_method(session, self.base, self.object_address, row)
        self.assertEqual(row['target_rva'], 0x123400)
        self.assertNotIn('property_type', row)
        with self.assertRaisesRegex(ValueError, 'source-selected'):
            exporter.observed_virtual_method(session, self.base, self.object_address, 0x80)

    def test_numeric_leaf_slot_is_observed_independently_from_generic_hook(self):
        session, write, _ = self.fixture(slot=0x88, target=self.base + 0x286bf70)
        write(self.vtable + 0x90, self.base + 0x10e5ce20)
        generic = exporter.observed_virtual_method(session, self.base, self.object_address, 0x90)
        leaf = exporter.observed_virtual_method(session, self.base, self.object_address, 0x88)
        exporter.recheck_virtual_method(session, self.base, self.object_address, generic)
        exporter.recheck_virtual_method(session, self.base, self.object_address, leaf)
        self.assertEqual(generic['target_rva'], 0x10e5ce20)
        self.assertEqual(leaf['target_rva'], 0x286bf70)
        self.assertEqual(generic['vtable_address'], leaf['vtable_address'])

    def test_pc_and_pawn_candidate_hooks_are_independently_observed_and_rechecked(self):
        fixture = Fixture()
        pc = add_candidate(fixture, fixture.pc, 'BP_DFMPlayerController_C', fixture.packages['/Game/Test/PC'])
        pawn = add_candidate(fixture, fixture.pawn, 'BP_DFMCharacter_C', fixture.packages['/Game/Test/Pawn'], 1)
        gs = add_candidate(fixture, fixture.gs, 'BP_GameState_PVPVE_C', fixture.packages['/Game/Test/GS'], 2)
        table = fixture.base + 0x1800
        pawn_table = fixture.base + 0x2400
        fixture.memory.write(pc, struct.pack('<Q', table))
        fixture.memory.write(table + 0x3d8, struct.pack('<Q', fixture.base + 0x12d4ddb0))
        fixture.memory.write(pawn, struct.pack('<Q', pawn_table))
        fixture.memory.write(pawn_table + 0x3d8, struct.pack('<Q', fixture.base + 0x123456))
        roots = exporter.discover_roots(fixture.session(), fixture.base)
        candidates = {item['address']: item for item in roots['named_template_candidates']}
        row = candidates[pc]['actor_channel_open_hook']
        self.assertEqual(row['target_rva'], 0x12d4ddb0)
        self.assertTrue(row['identity_rechecked'])
        pawn_row = candidates[pawn]['actor_channel_open_hook']
        self.assertEqual(pawn_row['target_rva'], 0x123456)
        self.assertTrue(pawn_row['identity_rechecked'])
        for address, observed_table in ((pc, table), (pawn, pawn_table)):
            self.assertEqual(fixture.memory.reads.count((address, 8)), 2)
            self.assertEqual(fixture.memory.reads.count((observed_table + 0x3d8, 8)), 2)
        self.assertNotIn('actor_channel_open_hook', candidates[gs])
        self.assertNotIn((gs, 8), fixture.memory.reads)
        self.assertNotIn('tail_format', pawn_row)

    def test_candidate_hook_change_discards_root_export_for_each_role(self):
        for role, label, package in (('pc', 'BP_DFMPlayerController_C', '/Game/Test/PC'),
                                     ('pawn', 'BP_DFMCharacter_C', '/Game/Test/Pawn')):
            with self.subTest(role=role):
                fixture = Fixture()
                candidate = add_candidate(fixture, getattr(fixture, role), label, fixture.packages[package])
                table = fixture.base + 0x1800
                fixture.memory.write(candidate, struct.pack('<Q', table))
                fixture.memory.write(table + 0x3d8, struct.pack('<Q', fixture.base + 0x12d4ddb0))
                original = exporter.observed_virtual_method
                def change_after_observation(session, base, address, slot):
                    row = original(session, base, address, slot)
                    if address == candidate:
                        fixture.memory.write(table + slot, struct.pack('<Q', fixture.base + 0x12d4dda0))
                    return row
                with patch.object(exporter, 'observed_virtual_method', side_effect=change_after_observation):
                    with self.assertRaisesRegex(ValueError, 'virtual method binding changed'):
                        exporter.discover_roots(fixture.session(), fixture.base)

    def test_candidate_identity_change_still_refuses_each_observed_role(self):
        for role, label, package in (('pc', 'BP_DFMPlayerController_C', '/Game/Test/PC'),
                                     ('pawn', 'BP_DFMCharacter_C', '/Game/Test/Pawn')):
            with self.subTest(role=role):
                fixture = Fixture()
                candidate = add_candidate(fixture, getattr(fixture, role), label, fixture.packages[package])
                original = exporter.observed_virtual_method
                def recycle_after_observation(session, base, address, slot):
                    row = original(session, base, address, slot)
                    if address == candidate:
                        fixture.serial(candidate, 8888)
                    return row
                with patch.object(exporter, 'observed_virtual_method', side_effect=recycle_after_observation):
                    with self.assertRaisesRegex(ValueError, 'root identity changed'):
                        exporter.discover_roots(fixture.session(), fixture.base)

    def test_candidate_hook_uses_existing_read_budget_without_partial_metadata(self):
        fixture = Fixture()
        candidate = add_candidate(fixture, fixture.pawn, 'BP_DFMCharacter_C', fixture.packages['/Game/Test/Pawn'])
        table = fixture.base + 0x1800
        fixture.memory.write(candidate, struct.pack('<Q', table))
        fixture.memory.write(table + 0x3d8, struct.pack('<Q', fixture.base + 0x123456))
        session = fixture.session()
        original = exporter.observed_virtual_method
        def exhaust_before_observation(active_session, base, address, slot):
            if address == candidate:
                active_session.max_calls = active_session.calls + 1
            return original(active_session, base, address, slot)
        with patch.object(exporter, 'observed_virtual_method', side_effect=exhaust_before_observation):
            with self.assertRaisesRegex(ValueError, 'budget'):
                exporter.discover_roots(session, fixture.base)


if __name__ == '__main__':
    unittest.main()
