"""Independent literal registry/name/interface fixtures; no live process API."""
import struct
import unittest
from unittest.mock import patch

import native_actor_interface_metadata as observer
import export_native_replication_metadata as exporter
from native_replication_metadata_core import MetadataSession
from test_export_native_replication_metadata import Fixture
from test_native_metadata_archetypes import add_candidate


class InterfaceFixture:
    def __init__(self):
        self.f = Fixture(driver=False)
        self.actor = add_candidate(self.f, self.f.pawn, 'BP_DFMCharacter_C',
                                   self.f.packages['/Game/Test/Pawn'])
        roots = exporter.discover_roots(self.f.session(), self.f.base)
        self.candidate, = roots['named_template_candidates']
        self.klass = next(row for row in roots['classes'] if row['address'] == self.f.pawn)
        self.memory, self.base = self.f.memory, self.f.base
        # Fixed independent NamePool bytes for the 20-character native label.
        offset = 0x4800
        literal = bytes.fromhex('311a0b2d1a0f3e1c0b100d36110b1a0d191e1c1a')
        self.memory.write(self.f.block + offset, bytes.fromhex('0005') + literal)
        self.f.tokens['NetRepActorInterface'] = struct.pack('<II', offset // 2, 0)
        self.interface = self.f.allocate()
        self.f.describe(self.interface, 'NetRepActorInterface', self.f.class_type, 0)
        self.memory.write(self.base + 0x1e34ee5c, struct.pack('<i', len(self.f.rows)))
        self.memory.write(self.interface + 0xd4, struct.pack('<I', (1 << 14) | (1 << 7)))
        self.chain, self.entries = 0x730000000, 0x730001000
        self.memory.write(self.interface + 0x30, struct.pack('<Qi', self.chain, 1))
        self.memory.write(self.chain, struct.pack('<QQ', 0, self.interface + 0x30))
        for address in (self.f.pawn, self.f.actor_type, self.f.object_type):
            self.memory.write(address + 0x200, struct.pack('<Qi', 0, 0))
        # The interface is inherited from the native Actor fixture, not present
        # in the Blueprint leaf. It uses the source-exact 16-byte item layout.
        self.memory.write(self.f.actor_type + 0x200, struct.pack('<Qi', self.entries, 1))
        self.item = struct.pack('<QiB3x', self.interface, 0xa60, 0)
        self.memory.write(self.entries, self.item)
        self.memory.write(self.base + 0x1de5c898, struct.pack('<Q', self.interface))
        self.memory.write(self.base + 0x1d59de58, struct.pack('<Q', self.base + 0xd968d0))
        self.memory.write(self.base + 0xd968d0, bytes.fromhex('488b01c3'))
        self.memory.write(self.actor, struct.pack('<Q', self.base + 0x1a67a320))
        self.memory.write(self.actor + 0xa60, struct.pack('<Q', self.base + 0x1a67c2e8))
        self.memory.write(self.base + 0x1a67c2f8, struct.pack('<Q', self.base + 0x4e198f0))
        self.code = bytes.fromhex('4d85c00f847001000048897c242041564883ec4048895c2450498bf848897424')
        self.memory.write(self.base + 0x4e198f0, self.code)

    def observe(self, backend=None):
        return observer.observe_actor_interface(MetadataSession(backend or self.memory.read),
                                                self.base, self.candidate, self.klass)


class InterfaceTests(unittest.TestCase):
    def test_actual_inherited_array_cast_and_secondary_binding(self):
        f = InterfaceFixture()
        result = f.observe()
        self.assertEqual(result['binding']['declaring_class'], 'Actor')
        self.assertEqual(result['binding']['adjustment'], 0xa60)
        self.assertEqual(result['method_target_rva'], 0x4e198f0)
        self.assertEqual(result['method_code_prefix_sha256'], observer.WRITER_PREFIX_SHA256)
        self.assertTrue(result['native_interface_gate_observed'])
        self.assertTrue(result['identity_rechecked'])
        self.assertFalse(result['native_method_executed'])
        self.assertFalse(result['replication_flags_value_observed'])
        self.assertFalse(result['spawn_verified'])
        self.assertLess(result['read_bytes'], observer.MAX_READ_BYTES)

    def test_different_interface_can_match_exact_native_base_chain(self):
        f = InterfaceFixture()
        derived = f.f.allocate()
        f.f.describe(derived, 'Actor', f.f.class_type, f.interface)
        f.memory.write(f.base + 0x1e34ee5c, struct.pack('<i', len(f.f.rows)))
        f.memory.write(derived + 0x30, struct.pack('<Qi', f.chain, 2))
        f.memory.write(f.entries, struct.pack('<QiB3x', derived, 0xa60, 0))
        result = f.observe()
        self.assertEqual(result['binding']['interface_address'], derived)

    def test_script_implementation_flag_skipped_not_cast(self):
        f = InterfaceFixture()
        f.memory.write(f.entries + 12, b'\1')
        with self.assertRaisesRegex(ValueError, 'Missing or ambiguous'):
            f.observe()
        self.assertNotIn((f.actor + 0xa60, 8), f.memory.reads)

    def test_duplicate_matches_are_refused(self):
        f = InterfaceFixture()
        f.memory.write(f.entries, f.item + f.item)
        f.memory.write(f.f.actor_type + 0x208, struct.pack('<i', 2))
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            f.observe()

    def test_source_accessor_cell_and_leaf_are_verified(self):
        for address_kind in ('cell', 'leaf'):
            with self.subTest(address_kind=address_kind):
                f = InterfaceFixture()
                if address_kind == 'cell':
                    f.memory.write(f.base + 0x1d59de58, struct.pack('<Q', f.base + 1))
                else:
                    f.memory.write(f.base + 0xd968d0, bytes.fromhex('488b09c3'))
                with self.assertRaisesRegex(ValueError, 'accessor'):
                    f.observe()

    def test_requested_singleton_name_flags_and_initialization(self):
        for kind in ('name', 'native_flag', 'interface_flag', 'null'):
            with self.subTest(kind=kind):
                f = InterfaceFixture()
                if kind == 'name':
                    f.memory.write(f.interface + 0x1c, f.f.tokens['Actor'])
                elif kind == 'null':
                    f.memory.write(f.base + 0x1de5c898, bytes(8))
                else:
                    flags = (1 << 14) if kind == 'native_flag' else (1 << 7)
                    f.memory.write(f.interface + 0xd4, struct.pack('<I', flags))
                with self.assertRaises(ValueError):
                    f.observe()

    def test_source_qualified_main_secondary_method_and_prefix(self):
        for where in ('main', 'adjustment', 'secondary', 'target', 'prefix'):
            with self.subTest(where=where):
                f = InterfaceFixture()
                if where == 'main':
                    f.memory.write(f.actor, struct.pack('<Q', f.base + 0x1a67a328))
                elif where == 'adjustment':
                    f.memory.write(f.entries + 8, struct.pack('<i', -0xa60))
                elif where == 'secondary':
                    f.memory.write(f.actor + 0xa60, struct.pack('<Q', f.base + 0x1a67c2f0))
                elif where == 'target':
                    f.memory.write(f.base + 0x1a67c2f8, struct.pack('<Q', f.base + 0x4e198f1))
                else:
                    f.memory.write(f.base + 0x4e198f0, bytes(32))
                with self.assertRaises(ValueError):
                    f.observe()

    def test_invalid_count_depth_and_class_cycle(self):
        for where in ('negative', 'oversize', 'depth', 'cycle'):
            with self.subTest(where=where):
                f = InterfaceFixture()
                if where in ('negative', 'oversize'):
                    f.memory.write(f.f.actor_type + 0x208, struct.pack('<i', -1 if where == 'negative' else 129))
                elif where == 'depth':
                    f.memory.write(f.interface + 0x38, struct.pack('<i', 32))
                else:
                    f.memory.write(f.f.object_type + 0x48, struct.pack('<Q', f.f.pawn))
                with self.assertRaises(ValueError):
                    f.observe()

    def test_selected_positive_identity_and_path_are_not_rebound(self):
        for where in ('serial', 'name', 'outer', 'path'):
            with self.subTest(where=where):
                f = InterfaceFixture()
                if where == 'serial':
                    f.f.serial(f.actor, 9999)
                elif where == 'name':
                    f.memory.write(f.actor + 0x1c, f.f.tokens['Health'])
                elif where == 'outer':
                    f.memory.write(f.actor + 0x10, struct.pack('<Q', f.f.packages['/Game/Test/GS']))
                else:
                    f.candidate['asset_path'] = '/Game/Guessed.Path'
                with self.assertRaises(ValueError):
                    f.observe()

    def test_mid_observation_registry_or_table_change_rejected(self):
        for where in ('serial', 'parent', 'table', 'slot', 'code'):
            with self.subTest(where=where):
                f = InterfaceFixture()
                changed = False
                def backend(address, size):
                    nonlocal changed
                    raw = f.memory.read(address, size)
                    if address == f.base + 0x4e198f0 and not changed:
                        changed = True
                        if where == 'serial':
                            f.f.serial(f.actor, 9001)
                        elif where == 'parent':
                            f.memory.write(f.f.actor_type + 0x48, bytes(8))
                        elif where == 'table':
                            f.memory.write(f.entries + 8, struct.pack('<i', 1))
                        elif where == 'slot':
                            f.memory.write(f.base + 0x1a67c2f8, struct.pack('<Q', f.base + 1))
                        else:
                            f.memory.write(f.base + 0x4e198f0, bytes(32))
                    return raw
                with self.assertRaises(ValueError):
                    f.observe(backend)

    def test_local_and_parent_session_budgets_remain_bounded(self):
        f = InterfaceFixture()
        with patch.object(observer, 'MAX_READ_BYTES', 32):
            with self.assertRaisesRegex(ValueError, 'budget'):
                f.observe()
        with self.assertRaisesRegex(ValueError, 'budget'):
            observer.observe_actor_interface(MetadataSession(f.memory.read, max_calls=2),
                                              f.base, f.candidate, f.klass)

    def test_wrong_role_or_class_rejected_before_read(self):
        f = InterfaceFixture()
        f.memory.reads.clear()
        f.candidate['class_address'] = f.f.pc
        with self.assertRaises(ValueError):
            f.observe()
        self.assertEqual(f.memory.reads, [])


if __name__ == '__main__':
    unittest.main()
