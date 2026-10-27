import hashlib
import unittest
from unittest.mock import patch

import test_probe_live_fileexists_receiver as fixtures
import probe_live_fileexists_edges as edges

import probe_live_fileexists_continuations as tool


class FileExistsContinuationTests(unittest.TestCase):
    BASE = fixtures.FileExistsReceiverScopeTests.BASE
    SIZE = fixtures.FileExistsReceiverScopeTests.SIZE
    CREATED = fixtures.FileExistsReceiverScopeTests.CREATED
    RECEIVER = fixtures.FileExistsReceiverScopeTests.RECEIVER
    VTABLE = fixtures.FileExistsReceiverScopeTests.VTABLE
    TARGET = BASE + edges.prior.TARGET_RVA
    read = fixtures.FileExistsReceiverScopeTests.read
    query = fixtures.FileExistsReceiverScopeTests.query

    def setUp(self):
        fixtures.FileExistsReceiverScopeTests.setUp(self)
        self.memory[(self.BASE + edges.prior.TARGET_RVA, 46)] = edges.TARGET_BYTES
        for rva, raw in tool.PREVIOUS_BYTES.items():
            self.memory[(self.BASE + rva, len(raw))] = raw
        for rva, size in tool.EXTRA_SPANS:
            self.memory[(self.BASE + rva, size)] = b'\x90' * size

    def capture(self, **options):
        options.setdefault('source_digest', tool.SOURCE_CAPTURE_SHA)
        options.setdefault('actual_created', self.CREATED)
        options.setdefault('expected_created', self.CREATED)
        return tool.capture(self.read, self.query, self.BASE, self.SIZE, **options)

    def test_exact_two_continuations_after_prior_scope(self):
        d = self.capture()
        self.assertEqual(len(self.reads), 14)
        self.assertEqual(self.reads[-2:], [(self.BASE + rva, size) for rva, size in tool.EXTRA_SPANS])
        self.assertEqual(len(self.queries), 6)
        self.assertEqual(d['captured_bytes'], 1591)
        self.assertEqual(d['data_qword_reads'], 6)
        self.assertFalse(d['native_called'])
        self.assertFalse(d['actual_render_proven'])
        self.assertFalse(d['fileexists_outcome_proven'])
        self.assertTrue(d['fresh_previous_segments_full_hash_verified'])

    def test_previous_full_hashes_gate_new_code(self):
        for rva, original in tool.PREVIOUS_BYTES.items():
            for at in (0, len(original) - 1):
                raw = bytearray(original)
                raw[at] ^= 1
                self.memory[(self.BASE + rva, len(original))] = bytes(raw)
                self.reads.clear()
                with self.assertRaises(ValueError):
                    self.capture()
                self.assertNotIn((self.BASE + tool.EXTRA_SPANS[0][0], 36), self.reads)
            self.memory[(self.BASE + rva, len(original))] = original

    def test_exact_branch_and_prologue_gates_even_with_hash_override(self):
        for rva, at in ((0x1246780e, 167), (0x12467ca0, 14)):
            blocks = dict(tool.PREVIOUS_BYTES)
            raw = bytearray(blocks[rva])
            raw[at] ^= 1
            blocks[rva] = bytes(raw)
            hashes = dict(tool.PREVIOUS_HASHES)
            hashes[rva] = hashlib.sha256(blocks[rva]).hexdigest()
            with patch.object(tool, 'PREVIOUS_HASHES', hashes):
                with self.assertRaises(ValueError):
                    tool.verify_previous_edges(blocks)

    def test_new_source_time_and_all_bounds_gate_first_read(self):
        for options in ({'source_digest': '0' * 64}, {'expected_created': self.CREATED + 1}):
            with self.assertRaises(ValueError):
                self.capture(**options)
            self.assertEqual(self.reads, [])
        with self.assertRaises(ValueError):
            tool.capture(self.read, self.query, self.BASE, 0x12467d7c,
                         source_digest=tool.SOURCE_CAPTURE_SHA,
                         actual_created=self.CREATED, expected_created=self.CREATED)
        self.assertEqual(self.reads, [])

    def test_preserved_source_and_each_original_metadata_disk_gate(self):
        self.assertEqual(tool.load_source(tool.SOURCE_CAPTURE), tool.SOURCE_CAPTURE_SHA)
        values = {offset: bytes.fromhex(raw) for _, offset, raw, _ in tool.SEGMENT_METADATA}
        disk = {offset: b'\x90' * size for _, offset, size, _ in tool.SEGMENT_DISK}
        values.update(disk)
        replacement = tuple((name, off, size, hashlib.sha256(disk[off]).hexdigest())
                            for name, off, size, _ in tool.SEGMENT_DISK)
        with patch.object(tool, 'SEGMENT_DISK', replacement):
            d = tool.verify_segment_metadata(lambda off, size: values[off])
            self.assertEqual(d['false_tail']['selected_rvas'], [0x124678b7, 0x124678c7])
            for offset in values:
                original = values[offset]
                values[offset] = original[:-1] + bytes([original[-1] ^ 1])
                with self.assertRaises(ValueError):
                    tool.verify_segment_metadata(lambda off, size: values[off])
                values[offset] = original

    def test_short_or_nonbyte_new_segments_rejected(self):
        for rva, size in tool.EXTRA_SPANS:
            key = (self.BASE + rva, size)
            original = self.memory[key]
            for raw in (original[:-1], bytearray(original)):
                self.memory[key] = raw
                with self.assertRaises(ValueError):
                    self.capture()
            self.memory[key] = original


if __name__ == '__main__':
    unittest.main()
