"""Synthetic gates for the typed CDN settings observer; never access a process."""

import json
import struct
import unittest
from unittest.mock import patch

import read_live_cdn_settings as probe


class CdnSettingReadTests(unittest.TestCase):
    BASE = 0x140000000
    ARRAY = 0x20000000000
    CHUNK = 0x22000000000
    OBJECT = 0x23000000000
    ITEM = CHUNK + 2 * 24

    def fixture(self, values=None):
        data, reads = {}, []
        for rva, expected in probe.CODE_WITNESSES:
            data[(self.BASE + rva, len(expected))] = expected
        data[(self.BASE + probe.weak_source.SELECTOR_RVA, 4)] = bytes(4)
        data[(self.BASE + probe.STORAGE_RVA, 8)] = struct.pack('<ii', 65538, 7)
        header = bytearray(32)
        struct.pack_into('<i', header, 12, 100000)
        struct.pack_into('<Q', header, 24, self.ARRAY)
        data[(self.BASE + probe.weak_source.ARRAY_RVA, 32)] = bytes(header)
        data[(self.BASE + probe.weak_source.OVERRIDE_RVA, 8)] = bytes(8)
        data[(self.ARRAY + 8, 8)] = struct.pack('<Q', self.CHUNK)
        item = bytearray(24)
        struct.pack_into('<Q', item, 0, self.OBJECT)
        struct.pack_into('<i', item, 20, 7)
        data[(self.ITEM, 24)] = bytes(item)
        values = values or ('https://cdn.example.com', 'https://cdn.df.qq.com', 'G/CN/Resource')
        for index, ((_, offset, _), value) in enumerate(zip(probe.FIELDS, values)):
            pointer = 0x24000000000 + index * 0x1000
            encoded = value.encode('utf-16-le') + b'\0\0'
            n = len(encoded) // 2
            data[(self.OBJECT + offset, 16)] = struct.pack('<Qii', pointer, n, n)
            data[(pointer, len(encoded))] = encoded
        schema = {'status': 'verified_source_types', 'source_pe_sha256': probe.identity.EXPECTED_PE,
                  'setting_cache_type': 'TWeakObjectPtr<UAppSetting>', 'storage_rva': probe.STORAGE_RVA,
                  'setting_type': 'FAppSettingRow', 'setting_member_offset': 0x38,
                  'uappsetting_size': 0x7c8}

        def read(address, size, module_only=True):
            reads.append((address, size, module_only))
            return data[(address, size)]

        return data, reads, read, schema

    def capture(self, read, schema):
        return probe.capture(read, self.BASE, probe.weak_source.MODULE_SIZE, schema)

    def test_exact_typed_fields_only_and_rechecked(self):
        _, reads, read, schema = self.fixture()
        report = self.capture(read, schema)
        self.assertEqual(report['status'], 'captured_configuration_fields')
        self.assertEqual([f['value'] for f in report['fields']],
                         ['https://cdn.example.com', 'https://cdn.df.qq.com', 'G/CN/Resource'])
        allowed_heap = {(self.ARRAY + 8, 8), (self.ITEM, 24)}
        for index, (_, offset, _) in enumerate(probe.FIELDS):
            allowed_heap.add((self.OBJECT + offset, 16))
            value = report['fields'][index]['value']
            allowed_heap.add((0x24000000000 + index * 0x1000, (len(value) + 1) * 2))
        self.assertEqual({(a, n) for a, n, module in reads if not module}, allowed_heap)
        self.assertTrue(report['weak_reference_and_headers_rechecked'])
        self.assertTrue(all(n <= 1024 for _, n, _ in reads))
        self.assertFalse(report['native_current_getcdnurl_result_verified'])

    def test_missing_type_proof_rejects_before_any_read(self):
        _, reads, read, schema = self.fixture()
        schema['setting_cache_type'] = 'TWeakObjectPtr<UAccountObject>'
        report = self.capture(read, schema)
        self.assertEqual(report['reason'], 'unverified_configuration_source_schema')
        self.assertEqual(reads, [])

    def test_wrong_source_pe_rejects_before_schema_reads(self):
        with patch.object(probe, 'digest_file', return_value='0' * 64):
            with self.assertRaisesRegex(ValueError, 'source PE differs'):
                probe.verify_source_schema('missing-source.exe')

    def test_bad_module_identity_rejects_before_any_read(self):
        _, reads, read, schema = self.fixture()
        report = probe.capture(read, self.BASE, 1, schema)
        self.assertEqual(report['reason'], 'invalid_native_module_identity')
        self.assertEqual(reads, [])

    def test_changed_accessor_rejects_before_any_heap_read(self):
        data, reads, read, schema = self.fixture()
        rva, expected = probe.CODE_WITNESSES[-1]
        data[(self.BASE + rva, len(expected))] = bytes(len(expected))
        self.assertEqual(self.capture(read, schema)['reason'], 'configuration_accessor_code_changed')
        self.assertTrue(all(module for _, _, module in reads))

    def test_selector_rejects_before_any_heap_read(self):
        data, reads, read, schema = self.fixture()
        data[(self.BASE + probe.weak_source.SELECTOR_RVA, 4)] = struct.pack('<I', 1)
        self.assertEqual(self.capture(read, schema)['reason'], 'unsupported_object_index_selector')
        self.assertTrue(all(module for _, _, module in reads))

    def test_override_rejects_before_any_heap_read(self):
        data, reads, read, schema = self.fixture()
        data[(self.BASE + probe.weak_source.OVERRIDE_RVA, 8)] = struct.pack('<Q', self.BASE + 0x1000)
        self.assertEqual(self.capture(read, schema)['reason'], 'unsupported_object_accessor_override')
        self.assertTrue(all(module for _, _, module in reads))

    def test_stale_serial_rejects_before_object_field_read(self):
        data, reads, read, schema = self.fixture()
        item = bytearray(data[(self.ITEM, 24)])
        struct.pack_into('<i', item, 20, 8)
        data[(self.ITEM, 24)] = bytes(item)
        self.assertEqual(self.capture(read, schema)['reason'], 'stale_SettingCache_serial')
        self.assertFalse(any(a == self.OBJECT + probe.FIELDS[0][1] for a, _, _ in reads))

    def test_invalid_object_flags_reject_before_object_fields(self):
        data, reads, read, schema = self.fixture()
        item = bytearray(data[(self.ITEM, 24)])
        struct.pack_into('<I', item, 8, 0x30000000)
        data[(self.ITEM, 24)] = bytes(item)
        self.assertEqual(self.capture(read, schema)['reason'], 'invalid_SettingCache_object_flags')
        self.assertFalse(any(a == self.OBJECT + probe.FIELDS[0][1] for a, _, _ in reads))

    def test_null_chunk_pointer_cannot_derive_a_low_heap_read(self):
        data, reads, read, schema = self.fixture()
        data[(self.ARRAY + 8, 8)] = bytes(8)
        self.assertEqual(self.capture(read, schema)['reason'], 'null_object_chunk')
        self.assertNotIn((48, 24, False), reads)

    def test_null_chunk_large_item_index_does_not_read_an_item(self):
        data, reads, read, schema = self.fixture()
        data[(self.BASE + probe.STORAGE_RVA, 8)] = struct.pack('<ii', 65536 + 10000, 7)
        data[(self.ARRAY + 8, 8)] = bytes(8)
        self.assertEqual(self.capture(read, schema)['reason'], 'null_object_chunk')
        self.assertEqual([(a, n) for a, n, module in reads if not module], [(self.ARRAY + 8, 8)])

    def test_null_chunk_array_does_not_read_a_chunk(self):
        data, reads, read, schema = self.fixture()
        header = bytearray(data[(self.BASE + probe.weak_source.ARRAY_RVA, 32)])
        struct.pack_into('<Q', header, 24, 0)
        data[(self.BASE + probe.weak_source.ARRAY_RVA, 32)] = bytes(header)
        self.assertEqual(self.capture(read, schema)['reason'], 'null_object_chunk_array')
        self.assertTrue(all(module for _, _, module in reads))

    def test_low_chunk_array_base_is_rejected_before_offset_arithmetic(self):
        data, reads, read, schema = self.fixture()
        header = bytearray(data[(self.BASE + probe.weak_source.ARRAY_RVA, 32)])
        struct.pack_into('<Q', header, 24, 0xffff)
        data[(self.BASE + probe.weak_source.ARRAY_RVA, 32)] = bytes(header)
        self.assertEqual(self.capture(read, schema)['reason'], 'invalid_object_chunk_array_pointer')
        self.assertTrue(all(module for _, _, module in reads))

    def test_low_chunk_base_with_large_item_index_does_not_read_an_item(self):
        data, reads, read, schema = self.fixture()
        data[(self.BASE + probe.STORAGE_RVA, 8)] = struct.pack('<ii', 65536 + 10000, 7)
        data[(self.ARRAY + 8, 8)] = struct.pack('<Q', 0xffff)
        self.assertEqual(self.capture(read, schema)['reason'], 'invalid_object_chunk_pointer')
        self.assertEqual([(a, n) for a, n, module in reads if not module], [(self.ARRAY + 8, 8)])

    def test_low_object_base_is_rejected_before_field_offset_arithmetic(self):
        data, reads, read, schema = self.fixture()
        item = bytearray(data[(self.ITEM, 24)])
        struct.pack_into('<Q', item, 0, 0xffff)
        data[(self.ITEM, 24)] = bytes(item)
        self.assertEqual(self.capture(read, schema)['reason'], 'invalid_SettingCache_object_pointer')
        self.assertFalse(any(a == 0xffff + offset for a, _, _ in reads for _, offset, _ in probe.FIELDS))

    def test_long_field_is_reported_without_string_read(self):
        data, reads, read, schema = self.fixture()
        data[(self.OBJECT + probe.FIELDS[0][1], 16)] = struct.pack('<Qii', 0x24000000000, 513, 513)
        report = self.capture(read, schema)
        self.assertEqual(report['fields'][0]['status'], 'unsupported_FString_length')
        self.assertNotIn('value', report['fields'][0])
        self.assertFalse(any(a == 0x24000000000 for a, _, _ in reads))

    def test_empty_header_needs_no_string_pointer_read(self):
        data, reads, read, schema = self.fixture()
        data[(self.OBJECT + probe.FIELDS[0][1], 16)] = bytes(16)
        report = self.capture(read, schema)
        self.assertEqual(report['fields'][0]['value'], '')
        self.assertFalse(any(a == 0x24000000000 for a, _, _ in reads))

    def test_invalid_capacity_is_not_followed(self):
        data, reads, read, schema = self.fixture()
        data[(self.OBJECT + probe.FIELDS[0][1], 16)] = struct.pack('<Qii', 0x24000000000, 20, 19)
        report = self.capture(read, schema)
        self.assertEqual(report['fields'][0]['status'], 'invalid_FString_header')
        self.assertFalse(any(a == 0x24000000000 for a, _, _ in reads))

    def test_invalid_string_pointer_is_not_followed(self):
        data, reads, read, schema = self.fixture()
        data[(self.OBJECT + probe.FIELDS[0][1], 16)] = struct.pack('<Qii', 0x800000000000 - 4, 20, 20)
        report = self.capture(read, schema)
        self.assertEqual(report['fields'][0]['status'], 'invalid_FString_pointer')
        self.assertTrue(all(a < 0x800000000000 - 4 for a, _, _ in reads))

    def test_bad_url_ports_are_not_public_values(self):
        self.assertFalse(probe.public_value('https://cdn.df.qq.com:secret/', 'url'))
        self.assertFalse(probe.public_value('https://cdn.df.qq.com:65536/', 'url'))

    def test_empty_query_fragment_and_userinfo_delimiters_are_not_public_values(self):
        for value in ('https://cdn.df.qq.com/?', 'https://cdn.df.qq.com/#',
                      'https://@cdn.df.qq.com/', 'https://:@cdn.df.qq.com/'):
            self.assertFalse(probe.public_value(value, 'url'), value)

    def test_invalid_or_private_text_is_not_output(self):
        _, _, read, schema = self.fixture(('https://user:secret@example.com',
                                          'https://cdn.df.qq.com/?token=secret', '../private'))
        report = self.capture(read, schema)
        self.assertTrue(all(f['status'] == 'filtered_nonpublic_or_invalid_string' for f in report['fields']))
        self.assertNotIn('secret', json.dumps(report))
        self.assertTrue(all('value' not in f for f in report['fields']))

    def test_reference_changes_after_string_read_discard_all_values(self):
        data, _, read, schema = self.fixture()

        def changing(address, size, module_only=True):
            value = read(address, size, module_only)
            if address == 0x24000000000:
                data[(self.BASE + probe.STORAGE_RVA, 8)] = struct.pack('<ii', 65538, 8)
            return value

        report = self.capture(changing, schema)
        self.assertEqual(report['reason'], 'configuration_reference_changed')
        self.assertEqual(report['fields'], [])

    def test_string_header_changes_after_read_discard_all_values(self):
        data, _, read, schema = self.fixture()

        def changing(address, size, module_only=True):
            value = read(address, size, module_only)
            if address == 0x24000000000:
                data[(self.OBJECT + probe.FIELDS[0][1], 16)] = bytes(16)
            return value

        report = self.capture(changing, schema)
        self.assertEqual(report['reason'], 'configuration_string_header_changed')
        self.assertEqual(report['fields'], [])


if __name__ == '__main__':
    unittest.main()
