import json
import struct
import unittest

import probe_live_fileexists_pak_headers as tool
import test_probe_live_fileexists_directory_state as fixtures


class PakHeaderTests(fixtures.DirectoryStateTests):
    def setUp(self):
        super().setUp()
        source = json.loads(tool.SOURCE_CAPTURE.read_text(encoding='utf-8'))
        blocks = list(source['pak_lookup_code'].values()) + [source['candidate_tail_code']]
        for block in blocks:
            self.memory[(self.BASE + block['rva'], block['size'])] = bytes.fromhex(block['bytes'])
        keys, records, links = self.RECEIVER + 0x1100, self.RECEIVER + 0x1200, self.RECEIVER + 0x1300
        for off, value in ((0x28, keys), (0x38, records), (0x18, links)):
            self.memory[(self.index + off, 8)] = struct.pack('<Q', value)
        for off in (0x30, 0x40):
            self.memory[(self.index + off, 4)] = struct.pack('<I', 1)
        self.pak = self.RECEIVER + 0x1500
        self.memory[(self.buckets, 4)] = struct.pack('<i', 0)
        self.memory[(keys, 4)] = struct.pack('<I', 1)
        self.memory[(records, 16)] = struct.pack('<IIQ', 3, 0, self.pak)
        self.memory[(links, 4)] = struct.pack('<i', -1)
        self.put_string(self.pak + 0x18, self.RECEIVER + 0x1900, '../../../DeltaForce/Content/Paks/example.pak')
        self.put_string(self.pak + 0x100, self.RECEIVER + 0x1a00, '../../../DeltaForce/Content/')
        self.memory[(self.pak + 0x24a, 1)] = b'\x01'

    def put_string(self, address, pointer, value):
        raw = (value + '\0').encode('utf-16le')
        self.memory[(address, 16)] = struct.pack('<Qii', pointer, len(raw)//2, len(raw)//2)
        self.memory[(pointer, len(raw))] = raw

    def header_capture(self):
        return tool.capture(self.read, self.new_query, self.BASE, self.SIZE,
                            source_digest=tool.SOURCE_CAPTURE_SHA,
                            actual_created=self.CREATED, expected_created=self.CREATED)

    def test_selected_package_name_mount_and_cache_flag(self):
        result = self.header_capture()
        self.assertEqual(len(result['selected_pak_headers']), 1)
        row = result['selected_pak_headers'][0]
        self.assertEqual(row['native_filename'], '../../../DeltaForce/Content/Paks/example.pak')
        self.assertEqual(row['native_mount_prefix'], '../../../DeltaForce/Content/')
        self.assertTrue(row['filename_cache_enabled'])
        self.assertFalse(result['actual_archive_entry_resolved'])
        self.assertFalse(result['actual_render_proven'])

    def test_changed_package_lookup_blocks_first_index_read(self):
        rva, (size, _) = next(iter(tool.PINS.items()))
        self.memory[(self.BASE+rva, size)] = b'\x90'*size
        with self.assertRaisesRegex(ValueError, 'fresh_lookup_code_changed'):
            self.header_capture()
        self.assertNotIn((self.RECEIVER + 8, 8), self.reads)

    def test_unterminated_package_filename_is_rejected(self):
        address = self.pak + 0x18
        pointer, count, _ = struct.unpack('<Qii', self.memory[(address, 16)])
        self.memory[(pointer, count*2)] = self.memory[(pointer, count*2)][:-2] + b'xx'
        with self.assertRaisesRegex(ValueError, 'unterminated'):
            self.header_capture()

    def test_string_capacity_and_module_read_are_bounded(self):
        self.memory[(self.pak + 0x18, 16)] = struct.pack('<Qii', self.RECEIVER, 513, 513)
        with self.assertRaisesRegex(ValueError, 'length_outside_bound'):
            self.header_capture()
        for address, size, used in ((self.BASE+10, 16, 0), (self.pak, 1025, 0), (self.pak, 1, 49152)):
            with self.assertRaises(ValueError):
                tool.check_data_read(address, size, self.BASE, self.SIZE, used)

    def test_source_digest_and_field_instructions_are_pinned(self):
        self.assertEqual(tool.load_source(tool.SOURCE_CAPTURE), tool.SOURCE_CAPTURE_SHA)


if __name__ == '__main__':
    unittest.main()
