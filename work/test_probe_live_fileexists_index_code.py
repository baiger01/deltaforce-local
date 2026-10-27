import hashlib
import json
import unittest
from unittest.mock import patch

import test_probe_live_fileexists_lookup_body as fixtures
import probe_live_fileexists_index_code as tool


class IndexCodeScopeTests(unittest.TestCase):
    BASE, SIZE, CREATED = fixtures.LookupBodyScopeTests.BASE, fixtures.LookupBodyScopeTests.SIZE, fixtures.LookupBodyScopeTests.CREATED
    RECEIVER, VTABLE, TARGET = fixtures.LookupBodyScopeTests.RECEIVER, fixtures.LookupBodyScopeTests.VTABLE, fixtures.LookupBodyScopeTests.TARGET
    read, query = fixtures.LookupBodyScopeTests.read, fixtures.LookupBodyScopeTests.query

    def setUp(self):
        fixtures.LookupBodyScopeTests.setUp(self)
        d = json.loads(tool.SOURCE_CAPTURE.read_text(encoding='utf-8'))
        for b in d['lookup_body_code'].values():
            self.memory[(self.BASE + b['rva'], b['size'])] = bytes.fromhex(b['bytes'])
        for rva, size in tool.EXTRA_SPANS:
            self.memory[(self.BASE + rva, size)] = b'\x90' * size

    def capture(self, **options):
        options.setdefault('source_digest', tool.SOURCE_CAPTURE_SHA)
        options.setdefault('actual_created', self.CREATED)
        options.setdefault('expected_created', self.CREATED)
        return tool.capture(self.read, self.query, self.BASE, self.SIZE, **options)

    def test_four_fixed_code_extents_no_new_data(self):
        d = self.capture()
        self.assertEqual(len(self.reads), 21)
        self.assertEqual(self.reads[-4:], [(self.BASE + rva, size) for rva, size in tool.EXTRA_SPANS])
        self.assertEqual(d['captured_bytes'], 2954)
        self.assertEqual(d['data_qword_reads'], 6)
        self.assertEqual(len(self.queries), 6)
        self.assertFalse(d['native_called'])
        self.assertFalse(d['actual_render_proven'])

    def test_each_source_body_hash_gates_all_four_extents(self):
        for rva, size in tool.prior.EXTRA_SPANS:
            key = self.BASE + rva, size
            original = self.memory[key]
            self.memory[key] = original[:-1] + bytes([original[-1] ^ 1])
            with self.assertRaises(ValueError):
                self.capture()
            self.assertNotIn((self.BASE + tool.EXTRA_SPANS[0][0], 183), self.reads)
            self.memory[key] = original
            self.reads.clear()

    def test_exact_helper_edge_required_after_hash_override(self):
        blocks = {rva: self.memory[(self.BASE + rva, size)] for rva, size in tool.prior.EXTRA_SPANS}
        raw = bytearray(blocks[0x12468d65])
        raw[0x12468d91 - 0x12468d65 + 1] ^= 1
        blocks[0x12468d65] = bytes(raw)
        hashes = dict(tool.BODY_HASHES)
        hashes[0x12468d65] = hashlib.sha256(raw).hexdigest()
        with patch.object(tool, 'BODY_HASHES', hashes), self.assertRaisesRegex(ValueError, 'helper_call'):
            tool.verify_previous_lookup_body(blocks)

    def test_creation_source_and_bounds_gate_first_read(self):
        for options in ({'source_digest': '0' * 64}, {'expected_created': self.CREATED + 1}):
            with self.assertRaises(ValueError):
                self.capture(**options)
            self.assertEqual(self.reads, [])
        with self.assertRaises(ValueError):
            tool.capture(self.read, self.query, self.BASE, 0x1246d97c,
                         source_digest=tool.SOURCE_CAPTURE_SHA, actual_created=self.CREATED,
                         expected_created=self.CREATED)
        self.assertEqual(self.reads, [])

    def test_pinned_source_and_all_metadata_disk_bytes(self):
        self.assertEqual(tool.load_source(tool.SOURCE_CAPTURE), tool.SOURCE_CAPTURE_SHA)
        values = {off: bytes.fromhex(raw) for _, off, raw, _ in tool.METADATA}
        disks = {off: b'\x90' * size for _, off, size, _ in tool.DISK}
        values.update(disks)
        replacements = tuple((name, off, size, hashlib.sha256(disks[off]).hexdigest())
                             for name, off, size, _ in tool.DISK)
        with patch.object(tool, 'DISK', replacements):
            self.assertEqual(tool.verify_segment_metadata(lambda off, size: values[off])['hash']['segment_bytes'], 269)
            for off, original in list(values.items()):
                values[off] = original[:-1] + bytes([original[-1] ^ 1])
                with self.assertRaises(ValueError):
                    tool.verify_segment_metadata(lambda off, size: values[off])
                values[off] = original


if __name__ == '__main__':
    unittest.main()
