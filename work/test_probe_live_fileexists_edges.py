import hashlib
import unittest
from unittest.mock import patch

import test_probe_live_fileexists_receiver as fixtures
import probe_live_fileexists_target as target

import probe_live_fileexists_edges as tool


class FileExistsCodeEdgeTests(fixtures.FileExistsReceiverScopeTests):
    TARGET = fixtures.FileExistsReceiverScopeTests.BASE + target.TARGET_RVA
    def setUp(self):
        super().setUp()
        self.memory[(self.virtual_slot, 8)] = target.struct.pack('<Q', self.BASE + target.TARGET_RVA)
        self.memory[(self.BASE + target.TARGET_RVA, 46)] = tool.TARGET_BYTES
        for rva, size in tool.EXTRA_SPANS:
            self.memory[(self.BASE + rva, size)] = b'\x90' * size

    def edges(self, **options):
        options.setdefault('source_digest', tool.SOURCE_CAPTURE_SHA)
        options.setdefault('actual_created', self.CREATED)
        options.setdefault('expected_created', self.CREATED)
        return tool.capture(self.read, self.query, self.BASE, self.SIZE, **options)

    def test_only_two_exact_source_edges_after_target(self):
        d = self.edges()
        self.assertEqual(self.reads[-3:], [(self.BASE + target.TARGET_RVA, 46),
                                          *((self.BASE + rva, size) for rva, size in tool.EXTRA_SPANS)])
        self.assertEqual(len(self.reads), 12)
        self.assertEqual(len(self.queries), 6)
        self.assertEqual(d['captured_bytes'], 1352)
        self.assertEqual(d['data_qword_reads'], 6)
        self.assertFalse(d['native_called'])
        for b in d['code_edges'].values():
            self.assertTrue(b['pdata_segment_complete'])
            self.assertFalse(b['function_complete'])

    def test_fresh_target_full_hash_and_exact_witnesses_gate_edges(self):
        original = tool.TARGET_BYTES
        for at in (0, 0x16, 0x17, 0x1d, 0x1e, 0x2c):
            raw = bytearray(original)
            raw[at] ^= 1
            self.memory[(self.BASE + target.TARGET_RVA, 46)] = bytes(raw)
            self.reads.clear()
            with self.assertRaises(ValueError):
                self.edges()
            self.assertNotIn((self.BASE + tool.EXTRA_SPANS[0][0], tool.EXTRA_SPANS[0][1]), self.reads)
        for at in (0x16, 0x1d, 0x2c):
            raw = bytearray(original)
            raw[at] ^= 1
            raw = bytes(raw)
            with patch.object(tool, 'TARGET_SHA', hashlib.sha256(raw).hexdigest()):
                with self.assertRaises(ValueError):
                    tool.verify_target(raw)

    def test_all_extra_bounds_and_new_source_gate_before_reads(self):
        with self.assertRaises(ValueError):
            self.edges(source_digest='0' * 64)
        self.assertEqual(self.reads, [])
        with self.assertRaises(ValueError):
            tool.capture(self.read, self.query, self.BASE, tool.EXTRA_SPANS[1][0] + 17,
                         source_digest=tool.SOURCE_CAPTURE_SHA,
                         actual_created=self.CREATED, expected_created=self.CREATED)
        self.assertEqual(self.reads, [])

    def test_preserved_source_and_each_original_metadata_record(self):
        self.assertEqual(tool.load_source(tool.SOURCE_CAPTURE), tool.SOURCE_CAPTURE_SHA)
        values = {offset: bytes.fromhex(raw) for _, offset, raw, _ in tool.EDGE_METADATA}
        disk = {offset: b'\x90' * size for _, offset, size, _ in tool.EDGE_DISK}
        values.update(disk)
        replacement = tuple((name, off, size, hashlib.sha256(disk[off]).hexdigest())
                            for name, off, size, _ in tool.EDGE_DISK)
        with patch.object(tool, 'EDGE_DISK', replacement):
            rows = tool.verify_edge_metadata(lambda off, size: values[off])
            self.assertEqual(rows['fallthrough']['begin_rva'], 0x1246780e)
            self.assertEqual(rows['direct_callee']['selected_rva'], 0x12467ca0)
            for _, offset, _, _ in tool.EDGE_METADATA:
                original = values[offset]
                values[offset] = original[:-1] + bytes([original[-1] ^ 1])
                with self.assertRaises(ValueError):
                    tool.verify_edge_metadata(lambda off, size: values[off])
                values[offset] = original

    def test_short_or_nonbyte_extra_code_rejected(self):
        key = (self.BASE + tool.EXTRA_SPANS[0][0], tool.EXTRA_SPANS[0][1])
        for raw in (b'\x90' * (key[1] - 1), bytearray(key[1])):
            self.memory[key] = raw
            with self.assertRaises(ValueError):
                self.edges()

    def test_short_or_nonbyte_reads_are_rejected(self):
        for rva, size in ((target.TARGET_RVA, 46), *tool.EXTRA_SPANS):
            self.memory.pop((self.BASE + rva, size))
        super().test_short_or_nonbyte_reads_are_rejected()


if __name__ == '__main__':
    unittest.main()
