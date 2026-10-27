import struct
import unittest

import read_live_storehot_image_rows as tool
import test_read_live_storehot_metadata as metadata_tests


class PlainCodec:
    def decode_config_name(self, raw, number):
        return raw[2:].decode('ascii')


class Fixture:
    base = 0x140000000
    table = 0x210000000
    slots = 0x220000000
    pool = 0x230000000
    row = 0x240000000
    chars = 0x250000000
    vtable = base + 0x10000

    def __init__(self):
        self.memory, self.reads = {}, []
        self.put(self.table, struct.pack('<Q', self.vtable))
        self.put(self.vtable + 0x270, struct.pack('<Q', self.base + tool.ROWMAP_ACCESSOR_RVA))
        header = bytearray(56)
        struct.pack_into('<Qii', header, 0, self.slots, 4, 4)
        header[16] = 15
        struct.pack_into('<Qii', header, 32, 0, 4, 32)
        self.put(self.table + 0x30, bytes(header))
        self.put(self.base + tool.metadata.names.POOL_RVA + 8, struct.pack('<Q', self.pool))
        for index, (key, tabid) in enumerate(tool.TARGET_ROWS.items()):
            token, row = 32 + index * 32, self.row + index * 0x1000
            self.put(self.slots + index * 24, struct.pack('<IIQ', token, 0, row))
            self.put(self.pool + token * 2, struct.pack('<H', len(key) << 6))
            self.put(self.pool + token * 2 + 2, key.encode('ascii'))
            self.put(row + 16, struct.pack('<Q', tabid))
            for offset in tool.STRING_FIELDS.values():
                self.put(row + offset, bytes(16))

    def put(self, address, raw):
        self.memory[address] = raw

    def read(self, address, size):
        self.reads.append((address, size))
        for start, raw in self.memory.items():
            if start <= address and address + size <= start + len(raw):
                return raw[address - start:address - start + size]
        raise AssertionError('unplanned sparse fixture read')

    def session(self):
        return tool.Session(self.read, self.base, PlainCodec())

    def text(self, field, text):
        data = text.encode('utf-16le') + bytes(2)
        self.put(self.row + tool.STRING_FIELDS[field], struct.pack('<Qii', self.chars, len(data) // 2, len(data) // 2))
        self.put(self.chars, data)


class StoreHotSparseTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()

    def test_public_mode_disabled_without_any_read(self):
        report = tool.capture(self.f.read, self.f.base, tool.Contract(None, (), 'synthetic'))
        self.assertEqual(report['status'], 'disabled')
        self.assertEqual(self.f.reads, [])

    def test_sparse_rows_only_known_fields(self):
        self.f.text('IamgeSourceSmall', "Texture2D'/Game/Resources/Store/A.A'")
        session = self.f.session()
        result = tool._sparse_rows(session, self.f.table)
        session.finish()
        self.assertEqual(result['rows'][0]['fields']['IamgeSourceSmall']['status'], 'captured')
        self.assertFalse(any(a == self.f.row for a, _ in self.f.reads))
        self.assertTrue(all(size <= 1024 for _, size in self.f.reads))

    def test_tabid_mismatch_precedes_all_image_fields(self):
        self.f.put(self.f.row + 16, bytes(8))
        result = tool._sparse_rows(self.f.session(), self.f.table)
        self.assertEqual(result['status'], 'typed_target_selection_rejected')
        self.assertEqual(result['target_TabId_observations'][0], {'row_name': '3', 'observed_TabId': 0})
        self.assertFalse(any(a == self.f.row + offset for a, _ in self.f.reads for offset in tool.STRING_FIELDS.values()))

    def test_later_target_mismatch_prevents_earlier_valid_target_strings(self):
        row2 = self.f.row + 0x1000
        header = bytearray(self.f.memory[self.f.table + 0x30])
        struct.pack_into('<ii', header, 8, 2, 2)
        header[16] = 3
        struct.pack_into('<i', header, 40, 2)
        self.f.put(self.f.table + 0x30, bytes(header))
        self.f.put(self.f.slots + 24, struct.pack('<IIQ', 64, 0, row2))
        self.f.put(self.f.pool + 128, struct.pack('<H', 1 << 6))
        self.f.put(self.f.pool + 130, b'7')
        self.f.put(row2 + 16, struct.pack('<Q', 10101099))
        result = tool._sparse_rows(self.f.session(), self.f.table)
        self.assertEqual(result['status'], 'typed_target_selection_rejected')
        self.assertEqual(len(result['target_TabId_observations']), 2)
        self.assertFalse(any(a in (self.f.row + offset, row2 + offset)
                             for a, _ in self.f.reads for offset in tool.STRING_FIELDS.values()))

    def test_native_key_is_not_an_export_ordinal_selector(self):
        self.f.put(self.f.pool + 66, b'4')
        result = tool._sparse_rows(self.f.session(), self.f.table)
        self.assertEqual(result['status'], 'captured_image_fields')
        self.assertEqual(result['rows'][0]['row_name'], '4')
        self.assertEqual(result['rows'][0]['TabId'], 10101004)

    def test_duplicate_source_target_scalar_rejects_before_any_strings(self):
        self.f.put(self.f.row + 0x1000 + 16, struct.pack('<Q', 10101004))
        result = tool._sparse_rows(self.f.session(), self.f.table)
        self.assertEqual(result['status'], 'typed_target_selection_rejected')
        self.assertEqual(result['duplicate_target_TabIds'], [10101004])
        self.assertEqual(result['missing_target_TabIds'], [10101008])
        self.assertFalse(any(self.f.row <= a < self.f.row + 0x4000 and size == 16
                             for a, size in self.f.reads))

    def test_non_target_row_reads_scalar_without_image_headers(self):
        row5 = self.f.row + 0x4000
        header = bytearray(self.f.memory[self.f.table + 0x30])
        struct.pack_into('<ii', header, 8, 5, 5)
        header[16] = 31
        struct.pack_into('<i', header, 40, 5)
        self.f.put(self.f.table + 0x30, bytes(header))
        self.f.put(self.f.slots + 4 * 24, struct.pack('<IIQ', 160, 0, row5))
        self.f.put(self.f.pool + 320, struct.pack('<H', 2 << 6))
        self.f.put(self.f.pool + 322, b'50')
        self.f.put(row5 + 16, struct.pack('<Q', 10101999))
        result = tool._sparse_rows(self.f.session(), self.f.table)
        self.assertEqual(result['status'], 'captured_image_fields')
        self.assertEqual(len(result['rows']), 4)
        self.assertIn((row5 + 16, 8), self.f.reads)
        self.assertFalse(any(a == row5 + offset for a, _ in self.f.reads
                             for offset in tool.STRING_FIELDS.values()))

    def test_invalid_row_pointer_rejected_before_scalar_offset(self):
        self.f.put(self.f.pool + 66, b'4')
        self.f.put(self.f.slots, struct.pack('<IIQ', 32, 0, 1))
        with self.assertRaisesRegex(ValueError, 'invalid_pointer_base'):
            tool._sparse_rows(self.f.session(), self.f.table)
        self.assertFalse(any(a < 0x10000 for a, _ in self.f.reads))

    def test_null_slots_rejected(self):
        header = bytearray(self.f.memory[self.f.table + 0x30])
        struct.pack_into('<Q', header, 0, 0)
        self.f.put(self.f.table + 0x30, bytes(header))
        with self.assertRaisesRegex(ValueError, 'invalid_pointer_base'):
            tool._sparse_rows(self.f.session(), self.f.table)

    def test_accessor_identity_mismatch_rejected(self):
        self.f.put(self.f.vtable + 0x270, struct.pack('<Q', self.f.base + 0x1000))
        with self.assertRaisesRegex(ValueError, 'accessor_identity_changed'):
            tool._sparse_rows(self.f.session(), self.f.table)
        self.assertNotIn((self.f.table + 0x30, 56), self.f.reads)

    def test_invalid_string_length_never_reads_body(self):
        self.f.put(self.f.row + 160, struct.pack('<Qii', self.f.chars, 1025, 1025))
        result = tool._sparse_rows(self.f.session(), self.f.table)
        self.assertEqual(result['rows'][0]['fields']['IamgeSourceSmall']['status'], 'invalid_FString_count_or_capacity')
        self.assertFalse(any(a == self.f.chars for a, _ in self.f.reads))

    def test_private_text_not_output(self):
        self.f.text('IamgeSourceSmall', 'https://example.invalid/?token=private')
        result = tool._sparse_rows(self.f.session(), self.f.table)
        field = result['rows'][0]['fields']['IamgeSourceSmall']
        self.assertEqual(field, {'status': 'FString_not_public_asset_syntax'})

    def test_header_change_discarded(self):
        session = self.f.session()
        tool._sparse_rows(session, self.f.table)
        self.f.put(self.f.row + 160, struct.pack('<Qii', self.f.chars, 1, 1))
        with self.assertRaisesRegex(ValueError, 'final_results_discarded'):
            session.finish()


class TypedFixture(metadata_tests.Fixture):
    rowstruct = 0x290000000
    class_type = 0x2a0000000
    row_slots = 0x2b0000000
    row = 0x2c0000000

    def __init__(self):
        super().__init__()
        header = bytearray(self.memory[self.base + tool.metadata.manager_source.ARRAY_RVA])
        struct.pack_into('<i', header, 12, 5)
        self.put(self.base + tool.metadata.manager_source.ARRAY_RVA, bytes(header))
        for index, obj, serial in ((3, self.rowstruct, 31), (4, self.class_type, 32)):
            self.put(self.chunk + index * 24, struct.pack('<QIIIi', obj, 0, 0, 0, serial))
            self.put(obj + 0x24, struct.pack('<i', index))
        self.put(self.base + 0x1e340a98, struct.pack('<Q', self.class_type))
        self.put(self.table + 40, struct.pack('<Q', self.rowstruct))
        self.put(self.rowstruct + 8, struct.pack('<Q', self.class_type))
        self.put(self.rowstruct + 0x10, bytes(8))
        self.put(self.rowstruct + 0x1c, struct.pack('<II', 256, 0))
        self.put(self.class_type + 0x1c, struct.pack('<II', 384, 0))
        self.fname(256, tool.metadata.TARGET)
        self.fname(384, 'ScriptStruct')
        self.put(self.table, struct.pack('<Q', self.vtable))
        self.put(self.vtable + 0x270, struct.pack('<Q', self.base + tool.ROWMAP_ACCESSOR_RVA))
        header = bytearray(56)
        struct.pack_into('<Qii', header, 0, self.row_slots, 4, 4)
        header[16] = 15
        struct.pack_into('<Qii', header, 32, 0, 4, 32)
        self.put(self.table + 0x30, bytes(header))
        for index, (key, tabid) in enumerate(tool.TARGET_ROWS.items()):
            token, row = 512 + index * 32, self.row + index * 0x1000
            self.fname(token, key)
            self.put(self.row_slots + index * 24, struct.pack('<IIQ', token, 0, row))
            self.put(row + 16, struct.pack('<Q', tabid))
            for offset in tool.STRING_FIELDS.values():
                self.put(row + offset, bytes(16))
        self.image_contract = tool.Contract(self.contract, (), 'synthetic', {
            'rowstruct_member_offset': 40, 'rowstruct_class_global_rva': 0x1e340a98,
            'source_rowstruct_owner_verified': True})

    def capture_typed(self, read=None):
        return tool.metadata.capture(read or self.read, self.base, self.contract,
                                     _selected_table_reader=lambda view: tool._selected_rows(view, self.image_contract))


class StoreHotTypedRowsTests(unittest.TestCase):
    def setUp(self):
        self.f = TypedFixture()

    def assert_no_rowmap_or_fields(self):
        self.assertNotIn((self.f.table + 0x30, 56), self.f.reads)
        self.assertFalse(any(a == self.f.row + offset for a, _ in self.f.reads
                             for offset in (16, *tool.STRING_FIELDS.values())))

    def test_fresh_typed_identity_and_rows_share_final_stability(self):
        report = self.f.capture_typed()
        self.assertEqual(report['status'], 'captured_metadata')
        typed = report['selected_table_extension']
        self.assertTrue(typed['runtime_RowStruct_identity_verified'])
        self.assertEqual(typed['runtime_RowStruct_metadata_nodes'][0]['name'], tool.metadata.TARGET)
        self.assertEqual(typed['rows'][0]['TabId'], tool.TARGET_ROWS['3'])

    def test_public_capture_publishes_verified_sparse_fields(self):
        report = tool.capture(self.f.read, self.f.base, self.f.image_contract)
        self.assertEqual(report['status'], 'captured_image_fields')
        self.assertTrue(report['runtime_RowStruct_identity_verified'])
        self.assertTrue(report['runtime_rows_read'])
        self.assertTrue(report['image_fields_read'])
        self.assertFalse(report['whole_row_bytes_read'])
        self.assertNotIn('selected_table_extension', report)

    def test_public_capture_bad_code_does_not_follow_any_heap(self):
        self.f.put(self.f.base + 0x1000, b'changed!')
        report = tool.capture(self.f.read, self.f.base, self.f.image_contract)
        self.assertEqual(report['reason'], 'source_code_changed_before_metadata_reads')
        self.assertFalse(report['runtime_rows_read'])
        self.assertEqual(self.f.reads, [(self.f.base + 0x1000, 8)])

    def test_public_capture_typed_mismatch_keeps_diag_without_strings(self):
        self.f.put(self.f.row + 16, struct.pack('<Q', 10101099))
        report = tool.capture(self.f.read, self.f.base, self.f.image_contract)
        self.assertEqual(report['status'], 'captured_typed_diagnostic')
        self.assertTrue(report['runtime_rows_read'])
        self.assertFalse(report['image_fields_read'])
        self.assertEqual(report['target_TabId_observations'][0]['observed_TabId'], 10101099)

    def test_public_capture_final_change_drops_rows_and_verified_type_flag(self):
        count = 0
        def changing(address, size):
            nonlocal count
            raw = self.f.read(address, size)
            if address == self.f.table + 40 and size == 8:
                count += 1
                if count == 2:
                    return struct.pack('<Q', self.f.outer)
            return raw
        report = tool.capture(changing, self.f.base, self.f.image_contract)
        self.assertEqual(report['reason'], 'metadata_changed_final_results_discarded')
        self.assertNotIn('rows', report)
        self.assertNotIn('target_TabId_observations', report)
        self.assertFalse(report['runtime_RowStruct_identity_verified'])

    def test_unclosed_owner_never_reads_rowstruct_field(self):
        self.f.image_contract = tool.Contract(self.f.contract, (), 'synthetic')
        report = self.f.capture_typed()
        self.assertEqual(report['reason'], 'runtime_RowStruct_owner_contract_not_closed')
        self.assertNotIn((self.f.table + 40, 8), self.f.reads)

    def test_wrong_rowstruct_name_rejects_before_rowmap(self):
        self.f.fname(256, 'KeyBox')
        report = self.f.capture_typed()
        self.assertEqual(report['reason'], 'selected_RowStruct_name_differs_no_rows_read')
        self.assert_no_rowmap_or_fields()

    def test_wrong_class_pointer_rejects_before_rowmap(self):
        self.f.put(self.f.rowstruct + 8, struct.pack('<Q', self.f.outer))
        report = self.f.capture_typed()
        self.assertEqual(report['reason'], 'selected_RowStruct_Class_differs_no_rows_read')
        self.assert_no_rowmap_or_fields()

    def test_null_source_class_singleton_never_follows_rowstruct(self):
        self.f.put(self.f.base + 0x1e340a98, bytes(8))
        report = self.f.capture_typed()
        self.assertEqual(report['reason'], 'invalid_pointer_base_or_range')
        self.assertNotIn((self.f.table + 40, 8), self.f.reads)
        self.assert_no_rowmap_or_fields()

    def test_stale_rowstruct_registry_backref_rejects_before_name(self):
        self.f.put(self.f.chunk + 3 * 24, struct.pack('<QIIIi', self.f.outer, 0, 0, 0, 31))
        report = self.f.capture_typed()
        self.assertEqual(report['reason'], 'selected_object_registry_pointer_mismatch')
        self.assertNotIn((self.f.rowstruct + 0x1c, 8), self.f.reads)
        self.assert_no_rowmap_or_fields()

    def test_changed_rowstruct_pointer_discards_captured_rows(self):
        count = 0
        def changing(address, size):
            nonlocal count
            raw = self.f.read(address, size)
            if address == self.f.table + 40 and size == 8:
                count += 1
                if count == 2:
                    return struct.pack('<Q', self.f.outer)
            return raw
        report = self.f.capture_typed(changing)
        self.assertEqual(report['reason'], 'metadata_changed_final_results_discarded')
        self.assertNotIn('selected_table_extension', report)

    def test_changed_tabid_discards_captured_rows(self):
        count = 0
        def changing(address, size):
            nonlocal count
            raw = self.f.read(address, size)
            if address == self.f.row + 16 and size == 8:
                count += 1
                if count == 2:
                    return bytes(8)
            return raw
        report = self.f.capture_typed(changing)
        self.assertEqual(report['reason'], 'metadata_changed_final_results_discarded')
        self.assertNotIn('selected_table_extension', report)

    def test_typed_scalar_mismatch_keeps_stable_public_observation_only(self):
        self.f.put(self.f.row + 16, struct.pack('<Q', 10101099))
        report = self.f.capture_typed()
        typed = report['selected_table_extension']
        self.assertEqual(typed['status'], 'typed_target_selection_rejected')
        self.assertEqual(typed['rows'], [])
        self.assertEqual(typed['target_TabId_observations'][0]['observed_TabId'], 10101099)
        self.assertFalse(any(a == self.f.row + offset for a, _ in self.f.reads
                             for offset in tool.STRING_FIELDS.values()))

class StoreHotSparseBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()

    def test_name_block_bound_precedes_chars(self):
        self.f.put(self.f.slots, struct.pack('<IIQ', 0x3ffff, 0, self.f.row))
        self.f.put(self.f.pool + 0x7fffe, struct.pack('<H', 1 << 6))
        with self.assertRaisesRegex(ValueError, 'outside|out_of_native_block'):
            tool._sparse_rows(self.f.session(), self.f.table)
        self.assertFalse(any(a == self.f.pool + 0x80000 for a, _ in self.f.reads))

    def test_name_block_wide_bound_precedes_chars(self):
        self.f.put(self.f.slots, struct.pack('<IIQ', 0x3fffe, 0, self.f.row))
        self.f.put(self.f.pool + 0x7fffc, struct.pack('<H', (2 << 6) | 1))
        with self.assertRaisesRegex(ValueError, 'out_of_native_block'):
            tool._sparse_rows(self.f.session(), self.f.table)
        self.assertFalse(any(a == self.f.pool + 0x7fffe for a, _ in self.f.reads))

    def test_allocated_count_mismatch_precedes_row_slots(self):
        header = bytearray(self.f.memory[self.f.table + 0x30])
        header[16] = 0
        self.f.put(self.f.table + 0x30, bytes(header))
        with self.assertRaisesRegex(ValueError, 'allocated_count_mismatch'):
            tool._sparse_rows(self.f.session(), self.f.table)
        self.assertNotIn((self.f.slots, 16), self.f.reads)

    def test_string_capacity_bound_precedes_body(self):
        self.f.put(self.f.row + 160, struct.pack('<Qii', self.f.chars, 1, 16385))
        result = tool._sparse_rows(self.f.session(), self.f.table)
        self.assertEqual(result['rows'][0]['fields']['IamgeSourceSmall']['status'], 'invalid_FString_count_or_capacity')
        self.assertFalse(any(a == self.f.chars for a, _ in self.f.reads))

    def test_missing_terminal_nul_no_raw_text(self):
        self.f.put(self.f.row + 160, struct.pack('<Qii', self.f.chars, 1, 1))
        self.f.put(self.f.chars, b'A\0')
        result = tool._sparse_rows(self.f.session(), self.f.table)
        self.assertEqual(result['rows'][0]['fields']['IamgeSourceSmall'], {'status': 'FString_missing_terminal_NUL'})

    def test_body_change_discarded(self):
        self.f.text('IamgeSourceSmall', '/Game/A.A')
        session = self.f.session()
        tool._sparse_rows(session, self.f.table)
        self.f.put(self.f.chars, '/Game/B.B'.encode('utf-16le') + bytes(2))
        with self.assertRaisesRegex(ValueError, 'final_results_discarded'):
            session.finish()


if __name__ == '__main__':
    unittest.main()
