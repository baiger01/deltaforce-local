import hashlib
import unittest
from unittest.mock import patch

import test_probe_live_fileexists_receiver as fixtures

import probe_live_fileexists_target as tool


class FileExistsTargetScopeTests(fixtures.FileExistsReceiverScopeTests):
    def setUp(self):
        super().setUp()

    def prepare_target(self):
        self.memory[(self.virtual_slot, 8)] = tool.struct.pack('<Q', self.BASE + tool.TARGET_RVA)
        self.memory[(self.BASE + tool.TARGET_RVA, tool.TARGET_SIZE)] = b'\x90' * tool.TARGET_SIZE

    def target_capture(self, **options):
        options.setdefault('source_digest', tool.SOURCE_CAPTURE_SHA)
        options.setdefault('actual_created', self.CREATED)
        options.setdefault('expected_created', self.CREATED)
        return tool.capture(self.read, self.query, self.BASE, self.SIZE, **options)

    def test_target_read_is_exact_and_after_stable_chain(self):
        self.prepare_target()
        d = self.target_capture()
        self.assertEqual(len(self.reads), 10)
        self.assertEqual(self.reads[-1], (self.BASE + tool.TARGET_RVA, 46))
        self.assertEqual(d['captured_bytes'], 1165)
        self.assertEqual(d['data_qword_reads'], 6)
        self.assertEqual(d['target_code']['end_exclusive_rva'], 0x1246780e)
        self.assertFalse(d['target_code']['function_complete'])
        self.assertTrue(d['target_code']['pdata_segment_complete'])
        self.assertEqual(len(self.queries), 6)
        self.assertFalse(d['native_called'])

    def test_changed_target_or_chain_blocks_target_code(self):
        self.prepare_target()
        self.memory[(self.virtual_slot, 8)] = tool.struct.pack('<Q', self.BASE + tool.TARGET_RVA + 1)
        with self.assertRaises(ValueError):
            self.target_capture()
        self.assertNotIn((self.BASE + tool.TARGET_RVA, 46), self.reads)
        self.setUp()
        self.prepare_target()
        original = self.read
        count = 0
        def changing(address, size):
            nonlocal count
            count += 1
            if count == 8:
                return tool.struct.pack('<Q', self.VTABLE + 8)
            return original(address, size)
        with self.assertRaises(ValueError):
            tool.capture(changing, self.query, self.BASE, self.SIZE,
                         source_digest=tool.SOURCE_CAPTURE_SHA,
                         actual_created=self.CREATED, expected_created=self.CREATED)
        self.assertNotIn((self.BASE + tool.TARGET_RVA, 46), self.reads)

    def test_wrong_source_or_target_bounds_block_first_read(self):
        self.prepare_target()
        for options in ({'source_digest': '0' * 64}, {'expected_created': self.CREATED + 1}):
            with self.assertRaises(ValueError):
                self.target_capture(**options)
            self.assertEqual(self.reads, [])
        with self.assertRaises(ValueError):
            tool.capture(self.read, self.query, self.BASE, tool.TARGET_RVA + 45,
                         source_digest=tool.SOURCE_CAPTURE_SHA,
                         actual_created=self.CREATED, expected_created=self.CREATED)
        self.assertEqual(self.reads, [])

    def test_target_short_or_nonbyte_read_rejected(self):
        self.prepare_target()
        for value in (b'\x90' * 45, bytearray(46)):
            self.memory[(self.BASE + tool.TARGET_RVA, 46)] = value
            with self.assertRaises(ValueError):
                self.target_capture()

    def test_preserved_source_target_and_metadata(self):
        self.assertEqual(tool.load_source(tool.SOURCE_CAPTURE), tool.SOURCE_CAPTURE_SHA)
        values = {offset: bytes.fromhex(raw) for _, offset, raw, _ in tool.TARGET_METADATA}
        disk = b'\x90' * 46
        values[tool.TARGET_DISK_OFFSET] = disk
        def read_at(offset, size):
            return values[offset]
        with patch.object(tool, 'TARGET_DISK_SHA', hashlib.sha256(disk).hexdigest()):
            d = tool.verify_target_metadata(read_at)
            self.assertEqual(d['function_bytes'], 46)
            for _, offset, _, _ in tool.TARGET_METADATA:
                old = values[offset]
                values[offset] = old[:-1] + bytes([old[-1] ^ 1])
                with self.assertRaises(ValueError):
                    tool.verify_target_metadata(read_at)
                values[offset] = old
            values[tool.TARGET_DISK_OFFSET] = disk[:-1] + b'\xcc'
            with self.assertRaises(ValueError):
                tool.verify_target_metadata(read_at)


if __name__ == '__main__':
    unittest.main()
