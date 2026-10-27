import struct
import tempfile
import unittest

import read_live_storehot_metadata as tool


class PlainCodec:
    def decode_config_name(self, raw, number):
        return raw[2:].decode('ascii')


class Fixture:
    base = 0x140000000
    manager = 0x200000000
    chunks = 0x210000000
    chunk = 0x220000000
    table = 0x230000000
    outer = 0x240000000
    content = 0x250000000
    slots = 0x260000000
    names = 0x270000000
    array = 0x280000000
    vtable = base + 0x10000

    def __init__(self):
        self.memory, self.reads = {}, []
        self.contract = tool.Contract(((0x1000, b'verified'),), PlainCodec(), ())
        self.put(self.base + 0x1000, b'verified')
        self.put(self.base + tool.manager_source.SELECTOR_RVA, bytes(4))
        self.put(self.base + 0x1db35660, bytes(1))
        self.put(self.base + tool.manager_source.OVERRIDE_RVA, bytes(8))
        self.put(self.base + tool.manager_source.STORAGE_RVA, struct.pack('<iiQ', 0, 17, 0))
        header = bytearray(32)
        struct.pack_into('<i', header, 12, 3)
        struct.pack_into('<Q', header, 24, self.chunks)
        self.put(self.base + tool.manager_source.ARRAY_RVA, bytes(header))
        self.put(self.chunks, struct.pack('<Q', self.chunk))
        for index, obj, serial in ((0, self.manager, 17), (1, self.table, 21), (2, self.outer, 22)):
            self.put(self.chunk + index * 24, struct.pack('<QIIIi', obj, 0, 0, 0, serial))
        self.put(self.manager + 0x30, struct.pack('<Q', self.vtable))
        self.put(self.vtable + 0x68, struct.pack('<Q', self.base + 0xdbf7f0))
        self.put(self.base + tool.map_source.ALLOCATION_ACCESSOR_RVA, struct.pack('<Q', self.base + 14248144))
        header = bytearray(80)
        struct.pack_into('<Qi', header, 0, self.slots, 2)
        struct.pack_into('<i', header, 0x38, 0)
        struct.pack_into('<i', header, 0x48, 1)
        self.put(self.manager + 0x190, bytes(header))
        # First Content pointer is deliberately unusable and must never be followed.
        self.put(self.slots, struct.pack('<QQii', 16, 9, 1, 0))
        self.put(self.slots + 24, struct.pack('<QQii', 64, self.content, -1, 0))
        self.put(self.base + tool.names.POOL_RVA + 8, struct.pack('<Q', self.names))
        self.fname(16, 'OtherConfiguration')
        self.fname(64, tool.TARGET)
        self.fname(128, '/R13N/Game/DataTables/StoreHotRecommendation')
        self.put(self.content + 0x20c, b'\x02')
        self.put(self.content + 0x20e, struct.pack('<H', 1))
        self.put(self.content + 0x1f8, bytes(8))
        self.put(self.content + 0x1d8, struct.pack('<Qii', self.array, 1, 1))
        self.put(self.array, struct.pack('<Q', self.table))
        for obj, index, outer, token in ((self.table, 1, self.outer, 64), (self.outer, 2, 0, 128)):
            self.put(obj + 0x24, struct.pack('<i', index))
            self.put(obj + 8, struct.pack('<Q', self.base + 0x12340))
            self.put(obj + 0x10, struct.pack('<Q', outer))
            self.put(obj + 0x1c, struct.pack('<II', token, 0))

    def put(self, address, raw):
        self.memory[address] = raw

    def fname(self, token, text):
        self.put(self.names + token * 2, struct.pack('<H', len(text) << 6))
        self.put(self.names + token * 2 + 2, text.encode())

    def read(self, address, size):
        self.reads.append((address, size))
        for start, raw in self.memory.items():
            if start <= address and address + size <= start + len(raw):
                return raw[address - start:address - start + size]
        raise AssertionError(f'unplanned fixture read {address:x}/{size}')

    def capture(self, read=None):
        return tool.capture(read or self.read, self.base, self.contract)


class StoreHotMetadataTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()

    def assertSkipped(self, reason):
        report = self.f.capture()
        self.assertEqual(report['status'], 'skipped')
        self.assertEqual(report['reason'], reason)
        self.assertNotIn('selected_table_name', report)
        return report

    def test_exact_fresh_key_and_selected_outer_metadata(self):
        report = self.f.capture()
        self.assertEqual(report['status'], 'captured_metadata')
        self.assertEqual(report['selected_table_name'], tool.TARGET)
        self.assertEqual(report['outer_names'], ['/R13N/Game/DataTables/StoreHotRecommendation'])
        self.assertTrue(report['container_and_serial_rechecked'])
        self.assertFalse(report['row_bytes_read'])
        self.assertTrue(all(size <= 1024 for _, size in self.f.reads))
        self.assertFalse(any(9 <= address < 9 + 0x218 for address, _ in self.f.reads))

    def test_selected_extension_uses_current_table_and_shared_stability(self):
        extra = self.f.table + 0x100
        self.f.put(extra, b'typed')
        def consume(view):
            self.assertEqual(view.table, self.f.table)
            self.assertEqual(view.nodes[0]['name'], tool.TARGET)
            self.assertEqual(view.watch(extra, 5, 'typed_extension'), b'typed')
            return {'typed_value': 'verified'}
        report = tool.capture(self.f.read, self.f.base, self.f.contract,
                              _selected_table_reader=consume)
        self.assertEqual(report['selected_table_extension'], {'typed_value': 'verified'})
        self.assertEqual(self.f.reads.count((extra, 5)), 2)

    def test_selected_extension_failure_discards_all_selected_results(self):
        def consume(view):
            raise tool._Stop('typed_extension_rejected')
        report = tool.capture(self.f.read, self.f.base, self.f.contract,
                              _selected_table_reader=consume)
        self.assertEqual(report['reason'], 'typed_extension_rejected')
        self.assertNotIn('selected_table_name', report)
        self.assertNotIn('selected_table_extension', report)

    def test_selected_extension_change_discards_its_result(self):
        extra = self.f.table + 0x100
        self.f.put(extra, b'typed')
        def consume(view):
            view.watch(extra, 5, 'typed_extension')
            self.f.put(extra, b'newer')
            return {'partial': 'must_discard'}
        report = tool.capture(self.f.read, self.f.base, self.f.contract,
                              _selected_table_reader=consume)
        self.assertEqual(report['reason'], 'metadata_changed_final_results_discarded')
        self.assertNotIn('selected_table_extension', report)

    def test_selected_extension_not_called_after_source_gate_failure(self):
        self.f.put(self.f.base + 0x1000, b'changed!')
        calls = []
        report = tool.capture(self.f.read, self.f.base, self.f.contract,
                              _selected_table_reader=lambda view: calls.append(view))
        self.assertEqual(report['reason'], 'source_code_changed_before_metadata_reads')
        self.assertEqual(calls, [])

    def test_selected_extension_not_called_for_unready_content(self):
        self.f.put(self.f.content + 0x20c, b'\x01')
        calls = []
        report = tool.capture(self.f.read, self.f.base, self.f.contract,
                              _selected_table_reader=lambda view: calls.append(view))
        self.assertEqual(report['reason'], 'selected_content_not_ready')
        self.assertEqual(calls, [])

    def test_original_source_accessor_rva_decimal_14248144(self):
        # The original pinned report stores14248144, i.e. D968D0, not D969D0.
        self.f.put(self.f.base + tool.map_source.ALLOCATION_ACCESSOR_RVA,
                   struct.pack('<Q', self.f.base + 14248144))
        self.assertEqual(self.f.capture()['status'], 'captured_metadata')

    def test_bad_code_no_heap(self):
        self.f.put(self.f.base + 0x1000, b'changed!')
        self.assertSkipped('source_code_changed_before_metadata_reads')
        self.assertEqual(self.f.reads, [(self.f.base + 0x1000, 8)])

    def test_all_code_bounds_prechecked_before_first_read(self):
        self.f.contract = tool.Contract(((0x1000, b'verified'),
                                         (tool.MODULE_SIZE, b'invalid')), PlainCodec(), ())
        self.assertSkipped('module_source_range_out_of_bounds')
        self.assertEqual(self.f.reads, [])

    def test_numbered_selected_name_rejected(self):
        self.f.put(self.f.table + 0x1c, struct.pack('<II', 64, 1))
        self.assertSkipped('unsupported_numbered_metadata_name')

    def test_last_name_header_never_reads_ascii_or_wide_chars_outside_block(self):
        for wide in (False, True):
            with self.subTest(wide=wide):
                self.f = Fixture()
                self.f.put(self.f.slots + 24, struct.pack('<QQii', 0x3ffff, self.f.content, -1, 0))
                self.f.put(self.f.names + 0x7fffe, struct.pack('<H', (1 << 6) | int(wide)))
                self.assertSkipped('metadata_name_payload_outside_native_block')
                self.assertFalse(any(a == self.f.names + 0x80000 for a, _ in self.f.reads))

    def test_selected_table_index_outside_registry(self):
        self.f.put(self.f.table + 0x24, struct.pack('<i', 4))
        self.assertSkipped('selected_object_index_out_of_bounds')

    def test_low_content_base_no_offset_derived_read(self):
        self.f.put(self.f.slots + 24, struct.pack('<QQii', 64, 0xffff, -1, 0))
        self.assertSkipped('invalid_pointer_base_or_range')
        self.assertFalse(any(a == 0xffff + 0x20c for a, _ in self.f.reads))

    def test_nonzero_selector_no_heap(self):
        self.f.put(self.f.base + tool.manager_source.SELECTOR_RVA, struct.pack('<I', 1))
        self.assertSkipped('unsupported_object_registry_selector')
        self.assertTrue(all(a >= self.f.base and a < self.f.base + tool.MODULE_SIZE for a, _ in self.f.reads))

    def test_active_content_override_no_heap(self):
        self.f.put(self.f.base + 0x1db35660, b'\x01')
        self.assertSkipped('content_gettable_override_active')
        self.assertTrue(all(a >= self.f.base and a < self.f.base + tool.MODULE_SIZE for a, _ in self.f.reads))

    def test_null_array_no_chunk_read(self):
        raw = bytearray(self.f.memory[self.f.base + tool.manager_source.ARRAY_RVA])
        struct.pack_into('<Q', raw, 24, 0)
        self.f.put(self.f.base + tool.manager_source.ARRAY_RVA, bytes(raw))
        self.assertSkipped('invalid_pointer_base_or_range')
        self.assertNotIn((self.f.chunks, 8), self.f.reads)

    def test_high_index_null_chunk_no_derived_item_read(self):
        self.f.put(self.f.base + tool.manager_source.STORAGE_RVA, struct.pack('<iiQ', 75536, 17, 0))
        raw = bytearray(self.f.memory[self.f.base + tool.manager_source.ARRAY_RVA])
        struct.pack_into('<i', raw, 12, 80000)
        self.f.put(self.f.base + tool.manager_source.ARRAY_RVA, bytes(raw))
        self.f.put(self.f.chunks + 8, bytes(8))
        self.assertSkipped('invalid_pointer_base_or_range')
        self.assertFalse(any(a == 10000 * 24 for a, _ in self.f.reads))

    def test_low_array_base_rejected_before_addition(self):
        raw = bytearray(self.f.memory[self.f.base + tool.manager_source.ARRAY_RVA])
        struct.pack_into('<Q', raw, 24, 0xffff)
        self.f.put(self.f.base + tool.manager_source.ARRAY_RVA, bytes(raw))
        self.assertSkipped('invalid_pointer_base_or_range')
        self.assertFalse(any(a == 0xffff for a, _ in self.f.reads))

    def test_low_chunk_base_rejected_before_item_offset(self):
        self.f.put(self.f.chunks, struct.pack('<Q', 0xffff))
        self.assertSkipped('invalid_pointer_base_or_range')
        self.assertFalse(any(a == 0xffff for a, _ in self.f.reads))

    def test_stale_manager_serial(self):
        self.f.put(self.f.chunk, struct.pack('<QIIIi', self.f.manager, 0, 0, 0, 18))
        self.assertSkipped('manager_registry_serial_or_flags_invalid')

    def test_target_not_ready_no_table_read(self):
        self.f.put(self.f.content + 0x20c, b'\x01')
        self.assertSkipped('selected_content_not_ready')
        self.assertNotIn((self.f.table + 0x24, 4), self.f.reads)

    def test_duplicate_target_no_content_read(self):
        self.f.put(self.f.slots, struct.pack('<QQii', 64, 9, 1, 0))
        self.assertSkipped('target_configuration_not_uniquely_identified')
        self.assertFalse(any(self.f.content <= a < self.f.content + 0x218 for a, _ in self.f.reads))

    def test_outer_cycle_discards_names(self):
        self.f.put(self.f.outer + 0x10, struct.pack('<Q', self.f.table))
        self.assertSkipped('selected_table_outer_cycle')

    def test_selected_registry_backref_mismatch(self):
        self.f.put(self.f.chunk + 24, struct.pack('<QIIIi', self.f.outer, 0, 0, 0, 21))
        report = self.assertSkipped('selected_object_registry_pointer_mismatch')
        self.assertFalse(report['rejected_selected_identity']['pointer_matches'])

    def test_ordinary_outer_zero_serial_is_stable_metadata_identity(self):
        self.f.put(self.f.chunk + 48, struct.pack('<QIIIi', self.f.outer, 0, 0, 0, 0))
        report = self.f.capture()
        self.assertEqual(report['status'], 'captured_metadata')
        self.assertEqual(report['selected_metadata_nodes'][1]['serial'], 0)
        self.assertTrue(report['container_and_serial_rechecked'])

    def test_ordinary_negative_serial_rejected(self):
        self.f.put(self.f.chunk + 48, struct.pack('<QIIIi', self.f.outer, 0, 0, 0, -1))
        report = self.assertSkipped('selected_object_registry_serial_invalid')
        self.assertEqual(report['rejected_selected_identity']['serial_state'], 'negative')
        self.assertNotIn((self.f.outer + 0x1c, 8), self.f.reads)

    def test_manager_weak_input_zero_serial_remains_rejected(self):
        self.f.put(self.f.base + tool.manager_source.STORAGE_RVA, struct.pack('<iiQ', 0, 0, 0))
        self.assertSkipped('invalid_manager_weak_reference')
        self.assertNotIn((self.f.chunks, 8), self.f.reads)

    def test_ordinary_zero_serial_becomes_allocated_discards_names(self):
        self.f.put(self.f.chunk + 48, struct.pack('<QIIIi', self.f.outer, 0, 0, 0, 0))
        count = 0
        def mutate(address, size):
            nonlocal count
            raw = self.f.read(address, size)
            if address == self.f.chunk + 48:
                count += 1
                if count == 2:
                    return struct.pack('<QIIIi', self.f.outer, 0, 0, 0, 51)
            return raw
        report = self.f.capture(mutate)
        self.assertEqual(report['reason'], 'metadata_changed_final_results_discarded')
        self.assertNotIn('selected_table_name', report)

    def test_selected_excluded_flags_typed_reject(self):
        self.f.put(self.f.chunk + 24, struct.pack('<QIIIi', self.f.table, 0x20000000, 0, 0, 21))
        report = self.assertSkipped('selected_object_registry_flags_excluded')
        self.assertEqual(report['rejected_selected_identity']['excluded_flags'], 0x20000000)

    def test_final_serial_change_discards_names(self):
        count = 0
        def mutate(address, size):
            nonlocal count
            raw = self.f.read(address, size)
            if address == self.f.chunk + 24:
                count += 1
                if count == 2:
                    return struct.pack('<QIIIi', self.f.table, 0, 0, 0, 99)
            return raw
        report = self.f.capture(mutate)
        self.assertEqual(report['reason'], 'metadata_changed_final_results_discarded')
        self.assertNotIn('selected_table_name', report)

    def test_final_name_change_discards_names(self):
        count = 0
        address = self.f.names + 128 * 2 + 2
        def mutate(a, size):
            nonlocal count
            raw = self.f.read(a, size)
            if a == address:
                count += 1
                if count == 2:
                    return b'x' * size
            return raw
        report = self.f.capture(mutate)
        self.assertEqual(report['reason'], 'metadata_changed_final_results_discarded')
        self.assertNotIn('outer_names', report)

    def test_no_source_files_actionable(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError, 'missing_source_evidence: work/'):
                tool.load_contract(folder)


if __name__ == '__main__':
    unittest.main()
