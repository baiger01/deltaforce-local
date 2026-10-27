"""Independent fixture checks for the updated, read-only metadata relocation."""
import struct
import unittest
from unittest.mock import patch

from test_native_metadata_paths import Memory
import native_metadata_objects as historical
import updated_client_metadata as updated


class UpdatedMetadataTests(unittest.TestCase):
    def memory(self):
        memory = Memory()
        # Move fixture global bytes using independently recorded native RVAs.
        ranges = ((0x1e34ee5c, 4, 0x1e34ee9c), (0x1e34ee68, 8, 0x1e34eea8),
                  (0x1e318784, 4, 0x1e3187c4), (0x1e3267ac, 1, 0x1e3267ec),
                  (0x1e326a88, 8, 0x1e326ac8), (0x1e34ca90, 8, 0x1e34cad0))
        for old, size, new in ranges:
            raw = bytes(memory.data.pop(memory.base + old + i) for i in range(size))
            memory.write(memory.base + new, raw)
        memory.calls.clear()
        return memory

    def test_new_global_cells_resolve_same_registry_name_and_nested_path(self):
        memory = self.memory()
        reader = updated.UpdatedMetadata(memory.read, memory.base)
        self.assertEqual(reader.record(memory.child).index, 3)
        self.assertEqual(str(reader.name(memory.child)), 'Child')
        self.assertEqual(reader.path(memory.child), '/Root.Outer:Child')
        addresses = {at - memory.base for at, size in memory.calls}
        self.assertIn(0x1e34ee9c, addresses)
        self.assertIn(0x1e326ac8, addresses)
        self.assertNotIn(0x1e34ee5c, addresses)
        self.assertEqual(historical.COUNT_RVA, 0x1e34ee5c)

    def test_nonnull_native_decoder_is_still_refused_without_invoking_it(self):
        memory = self.memory()
        memory.write(memory.base + 0x1db3a770, struct.pack('<Q', 1234))
        with self.assertRaisesRegex(ValueError, 'pointer_decoder_required'):
            updated.UpdatedMetadata(memory.read, memory.base).record(memory.child)
        self.assertNotIn((1234, 8), memory.calls)

    def test_changed_qualification_is_rejected_before_memory_access(self):
        memory = self.memory()
        with patch.object(updated, 'QUALIFICATION_SHA256', '0' * 64):
            with self.assertRaisesRegex(ValueError, 'qualification'):
                updated.UpdatedMetadata(memory.read, memory.base)
        self.assertEqual(memory.calls, [])

    def test_unqualified_image_cell_is_not_passed_to_the_backend(self):
        memory = self.memory()
        reader = updated.UpdatedMetadata(memory.read, memory.base)
        with self.assertRaisesRegex(ValueError, 'global'):
            reader._read(memory.base + 0x1000, 8)
        self.assertEqual(memory.calls, [])

    def test_non_ascii_or_question_mark_path_is_not_claimed_exact(self):
        memory = self.memory()
        reader = updated.UpdatedMetadata(memory.read, memory.base)
        with patch.object(updated.paths, 'object_path', return_value='/Root.X?'):
            with self.assertRaisesRegex(ValueError, 'ASCII'):
                reader.path(memory.child)

    def test_current_property_chain_exports_offsets_without_inventing_handles(self):
        memory = self.memory()
        field = 0x610000000
        memory.write(memory.child + 0x70, struct.pack('<Q', field))
        raw = bytearray(0x40)
        raw[0x10:0x18] = memory.tokens['Child']  # FField+0x28
        struct.pack_into('<ii', raw, 0x24, 1, 8)  # FProperty+0x3c/+0x40
        struct.pack_into('<I', raw, 0x30, 0x20)
        struct.pack_into('<H', raw, 0x38, 4)
        struct.pack_into('<i', raw, 0x3c, 0x128)
        memory.write(field + 0x18, raw)
        rows = updated.UpdatedMetadata(memory.read, memory.base).fields(memory.child)
        self.assertEqual(rows[0]['name'], 'Child')
        self.assertEqual(rows[0]['storage_offset'], 0x128)
        self.assertEqual(rows[0]['rep_index'], 4)
        self.assertNotIn('field_handle', rows[0])

    def test_property_chain_cycle_is_refused(self):
        memory = self.memory()
        field = 0x610000000
        memory.write(memory.child + 0x70, struct.pack('<Q', field))
        raw = bytearray(0x40)
        struct.pack_into('<Q', raw, 0, field)
        raw[0x10:0x18] = memory.tokens['Child']
        struct.pack_into('<ii', raw, 0x24, 1, 8)
        memory.write(field + 0x18, raw)
        with self.assertRaisesRegex(ValueError, 'cycle'):
            updated.UpdatedMetadata(memory.read, memory.base).fields(memory.child)

    def test_property_method_targets_are_observed_without_calling_them(self):
        memory = self.memory()
        field, table = 0x610000000, memory.base + 0x15000000
        memory.write(memory.child + 0x70, struct.pack('<Q', field))
        raw = bytearray(0x40)
        raw[0x10:0x18] = memory.tokens['Child']
        struct.pack_into('<ii', raw, 0x24, 1, 8)
        memory.write(field + 0x18, raw)
        memory.write(field, struct.pack('<Q', table))
        for slot, target in ((0x60, 0x1000), (0x88, 0x286bc30), (0x90, 0x10e8e5f0)):
            memory.write(table + slot, struct.pack('<Q', memory.base + target))
        rows = updated.UpdatedMetadata(memory.read, memory.base).fields(memory.child, virtual_methods=True)
        self.assertEqual(rows[0]['virtual_methods']['0x90']['target_rva'], 0x10e8e5f0)
        self.assertNotIn((memory.base + 0x10e8e5f0, 8), memory.calls)

    def test_net_function_flags_use_source_cell_without_reading_parameters(self):
        memory = self.memory()
        function = 0x620000000
        memory.node(5, function, 'Child', memory.child, class_address=memory.owner)
        memory.write(memory.child + 0x58, struct.pack('<Q', function))
        memory.write(function + 0x28, b'\0' * 8)
        memory.write(function + 0x48, b'\0' * 8)
        memory.write(function + 0xc0, struct.pack('<I', 0x40))
        reader = updated.UpdatedMetadata(memory.read, memory.base)
        original_path = reader.path
        with patch.object(reader, 'path', side_effect=lambda address:
                '/Script/CoreUObject.Function' if address == memory.owner else original_path(address)):
            result = reader.functions(memory.child)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['function_flags'], 0x40)
        self.assertFalse(result[0]['parameters_read'])
        self.assertFalse(result[0]['function_called'])
        self.assertNotIn((function + 0x70, 8), memory.calls)


if __name__ == '__main__':
    unittest.main()
