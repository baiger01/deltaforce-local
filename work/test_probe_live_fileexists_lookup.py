import hashlib
import json
import unittest
from unittest.mock import patch

import test_probe_live_fileexists_continuations as fixtures
import probe_live_fileexists_lookup as tool


class LookupScopeTests(unittest.TestCase):
    BASE = fixtures.FileExistsContinuationTests.BASE
    SIZE = fixtures.FileExistsContinuationTests.SIZE
    CREATED = fixtures.FileExistsContinuationTests.CREATED
    RECEIVER = fixtures.FileExistsContinuationTests.RECEIVER
    VTABLE = fixtures.FileExistsContinuationTests.VTABLE
    TARGET = fixtures.FileExistsContinuationTests.TARGET
    read = fixtures.FileExistsContinuationTests.read
    query = fixtures.FileExistsContinuationTests.query

    def setUp(self):
        fixtures.FileExistsContinuationTests.setUp(self)
        saved = json.loads(tool.SOURCE_CAPTURE.read_text(encoding='utf-8'))
        for block in saved['code_continuations'].values():
            self.memory[(self.BASE + block['rva'], block['size'])] = bytes.fromhex(block['bytes'])
        self.memory[(self.BASE + tool.LOOKUP_RVA, tool.LOOKUP_SIZE)] = b'\x90' * tool.LOOKUP_SIZE

    def capture(self, **options):
        options.setdefault('source_digest', tool.SOURCE_CAPTURE_SHA)
        options.setdefault('actual_created', self.CREATED)
        options.setdefault('expected_created', self.CREATED)
        return tool.capture(self.read, self.query, self.BASE, self.SIZE, **options)

    def test_only37_code_bytes_added_no_more_data(self):
        d = self.capture()
        self.assertEqual(len(self.reads), 15)
        self.assertEqual(self.reads[-1], (self.BASE + tool.LOOKUP_RVA, 37))
        self.assertEqual(len(self.queries), 6)
        self.assertEqual(d['captured_bytes'], 1628)
        self.assertEqual(d['data_qword_reads'], 6)
        for flag in ('native_called', 'actual_render_proven', 'fileexists_outcome_proven'):
            self.assertFalse(d[flag])
        self.assertFalse(d['lookup_code']['function_complete'])

    def test_each_fresh_prior_hash_gates_lookup_read(self):
        for rva, size in tool.prior.EXTRA_SPANS:
            key = self.BASE + rva, size
            original = self.memory[key]
            self.memory[key] = original[:-1] + bytes([original[-1] ^ 1])
            with self.assertRaises(ValueError):
                self.capture()
            self.assertNotIn((self.BASE + tool.LOOKUP_RVA, 37), self.reads)
            self.memory[key] = original
            self.reads.clear()

    def test_argument_edge_required_even_with_hash_override(self):
        blocks = {rva: self.memory[(self.BASE + rva, size)] for rva, size in tool.prior.EXTRA_SPANS}
        raw = bytearray(blocks[0x12467cb2])
        raw[0x12467d5f - 0x12467cb2 + 3] ^= 1
        blocks[0x12467cb2] = bytes(raw)
        hashes = dict(tool.CONTINUATION_HASHES)
        hashes[0x12467cb2] = hashlib.sha256(raw).hexdigest()
        with patch.object(tool, 'CONTINUATION_HASHES', hashes), self.assertRaisesRegex(ValueError, 'arguments'):
            tool.verify_previous_continuations(blocks)

    def test_source_identity_and_bounds_gate_all_reads(self):
        for options in ({'source_digest': '0' * 64}, {'expected_created': self.CREATED + 1}):
            with self.assertRaises(ValueError):
                self.capture(**options)
            self.assertEqual(self.reads, [])
        with self.assertRaises(ValueError):
            tool.capture(self.read, self.query, self.BASE, tool.LOOKUP_RVA + 36,
                         source_digest=tool.SOURCE_CAPTURE_SHA,
                         actual_created=self.CREATED, expected_created=self.CREATED)
        self.assertEqual(self.reads, [])

    def test_pinned_source_and_metadata_reject_one_byte_changes(self):
        self.assertEqual(tool.load_source(tool.SOURCE_CAPTURE), tool.SOURCE_CAPTURE_SHA)
        values = {off: bytes.fromhex(raw) for _, off, raw, _ in tool.METADATA}
        values[tool.DISK_OFFSET] = b'\x90' * tool.LOOKUP_SIZE
        with patch.object(tool, 'DISK_SHA', hashlib.sha256(values[tool.DISK_OFFSET]).hexdigest()):
            self.assertEqual(tool.verify_segment_metadata(lambda off, size: values[off])['segment_bytes'], 37)
            for off, original in list(values.items()):
                values[off] = original[:-1] + bytes([original[-1] ^ 1])
                with self.assertRaises(ValueError):
                    tool.verify_segment_metadata(lambda off, size: values[off])
                values[off] = original


if __name__ == '__main__':
    unittest.main()
