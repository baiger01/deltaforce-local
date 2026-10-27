import json
import struct
import unittest

import probe_live_fileexists_directory_state as tool
import test_probe_live_fileexists_hash_leaf as fixtures


class DirectoryStateTests(fixtures.HashLeafScopeTests):
    def setUp(self):
        super().setUp()
        d = json.loads(tool.SOURCE_CAPTURE.read_text(encoding='utf-8'))
        for b in d['hash_leaf_code'].values():
            self.memory[(self.BASE + b['rva'], b['size'])] = bytes.fromhex(b['bytes'])
        self.memory[(self.BASE + tool.ACCESSOR_SLOT, 8)] = struct.pack('<Q', self.BASE + tool.ACCESSOR_RVA)
        self.memory[(self.BASE + tool.ACCESSOR_RVA, 4)] = bytes.fromhex('488b01c3')
        self.index = self.RECEIVER + 0x100
        self.buckets = self.RECEIVER + 0x1000
        self.memory[(self.RECEIVER + 8, 8)] = struct.pack('<Q', self.index)
        for off, size, name in tool.FIELDS:
            self.memory[(self.index + off, size)] = (self.buckets if name == 'buckets' else 0).to_bytes(size, 'little')
        self.memory[(self.buckets, 4)] = struct.pack('<i', -1)

    def new_query(self, address):
        if self.RECEIVER < address < self.RECEIVER + 0x2000:
            return {'base': self.RECEIVER, 'size': 0x2000, 'state': 0x1000, 'protect': 4}
        return self.query(address)

    def directory_capture(self):
        return tool.capture(self.read, self.new_query, self.BASE, self.SIZE,
                            source_digest=tool.SOURCE_CAPTURE_SHA,
                            actual_created=self.CREATED, expected_created=self.CREATED)

    def test_four_exact_directories_empty_buckets_not_claimed_missing(self):
        d = self.directory_capture()
        self.assertEqual(len(d['directory_queries']), 4)
        self.assertEqual(sum(len(x['source_images']) for x in d['directory_queries']), 12)
        self.assertFalse(d['native_FileExists_result_observed'])
        self.assertFalse(d['actual_archive_entry_resolved'])
        self.assertFalse(d['actual_render_proven'])

    def test_busy_index_stops_before_bucket_reads(self):
        self.memory[(self.index + 0x58, 4)] = struct.pack('<I', 1)
        d = self.directory_capture()
        self.assertEqual(d['directory_status'], 'index_requires_native_initialization_or_is_busy')
        self.assertEqual(d['directory_queries'], [])
        self.assertNotIn((self.buckets, 4), self.reads)

    def test_only_bucket_selected_record_is_read_and_receiver_is_rechecked(self):
        keys, records, links = self.RECEIVER + 0x1100, self.RECEIVER + 0x1200, self.RECEIVER + 0x1300
        for off, value in ((0x28, keys), (0x38, records), (0x18, links)):
            self.memory[(self.index + off, 8)] = struct.pack('<Q', value)
        for off in (0x30, 0x40):
            self.memory[(self.index + off, 4)] = struct.pack('<I', 2)
        self.memory[(self.buckets, 4)] = struct.pack('<i', 20)
        self.memory[(keys, 4)] = struct.pack('<I', 10)
        self.memory[(keys + 4, 4)] = struct.pack('<I', 65536)
        self.memory[(records + 16, 16)] = struct.pack('<IIQ', 3, 0, self.RECEIVER + 0x1500)
        self.memory[(links + 20 * 4, 4)] = struct.pack('<i', -1)
        d = self.directory_capture()
        self.assertEqual([x['bucket_candidate_records'][0]['record_index'] for x in d['directory_queries']], [1]*4)
        self.assertNotIn((records, 16), self.reads)
        self.assertEqual(self.reads[-1], (self.RECEIVER + 8, 8))

    def test_unreadable_typed_header_refused(self):
        original = self.new_query
        self.new_query = lambda address: {'base':address, 'size':16, 'state':0x1000, 'protect':1} if address==self.index+4 else original(address)
        with self.assertRaisesRegex(ValueError, 'unreadable'):
            self.directory_capture()

    def test_changed_accessor_blocks_first_new_heap_field(self):
        self.memory[(self.BASE + tool.ACCESSOR_RVA, 4)] = b'\x90'*4
        with self.assertRaisesRegex(ValueError, 'accessor'):
            self.directory_capture()
        self.assertNotIn((self.RECEIVER + 8, 8), self.reads)

    def test_bad_bucket_and_module_or_oversize_reads_refused(self):
        self.memory[(self.buckets, 4)] = struct.pack('<i', -2)
        with self.assertRaisesRegex(ValueError, 'chain'):
            self.directory_capture()
        for address,size,used in ((self.BASE+10,8,0), (self.RECEIVER,32,0), (self.RECEIVER,8,tool.MAX_DATA_BYTES)):
            with self.assertRaises(ValueError):
                tool.check_data_read(address,size,self.BASE,self.SIZE,used)

    def test_source_and_ascii_only_lowering(self):
        self.assertEqual(tool.load_source(tool.SOURCE_CAPTURE), tool.SOURCE_CAPTURE_SHA)
        self.assertEqual(tool.native_directory_hash('ABc'), tool.native_directory_hash('abc'))
        self.assertNotEqual(tool.native_directory_hash('\u00c4'), tool.native_directory_hash('\u00e4'))
        self.assertEqual(tool.native_directory_hash(''), 0x100000001b3)


if __name__ == '__main__':
    unittest.main()
