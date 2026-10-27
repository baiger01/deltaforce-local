import hashlib
import unittest
from unittest.mock import patch

import test_probe_live_fileexists_lookup as fixtures
import probe_live_fileexists_lookup_body as tool


class LookupBodyScopeTests(unittest.TestCase):
    BASE, SIZE, CREATED = fixtures.LookupScopeTests.BASE, fixtures.LookupScopeTests.SIZE, fixtures.LookupScopeTests.CREATED
    RECEIVER, VTABLE, TARGET = fixtures.LookupScopeTests.RECEIVER, fixtures.LookupScopeTests.VTABLE, fixtures.LookupScopeTests.TARGET
    read, query = fixtures.LookupScopeTests.read, fixtures.LookupScopeTests.query

    def setUp(self):
        fixtures.LookupScopeTests.setUp(self)
        self.memory[(self.BASE + tool.prior.LOOKUP_RVA, 37)] = tool.LOOKUP_BYTES
        for rva, size in tool.EXTRA_SPANS:
            self.memory[(self.BASE + rva, size)] = b'\x90' * size

    def capture(self, **options):
        options.setdefault('source_digest', tool.SOURCE_CAPTURE_SHA)
        options.setdefault('actual_created', self.CREATED)
        options.setdefault('expected_created', self.CREATED)
        return tool.capture(self.read, self.query, self.BASE, self.SIZE, **options)

    def test_fixed_two_code_extents_and_same_data_scope(self):
        d = self.capture()
        self.assertEqual(len(self.reads), 17)
        self.assertEqual(self.reads[-2:], [(self.BASE + rva, size) for rva, size in tool.EXTRA_SPANS])
        self.assertEqual(d['captured_bytes'], 2012)
        self.assertEqual(d['data_qword_reads'], 6)
        self.assertEqual(len(self.queries), 6)
        self.assertFalse(d['actual_render_proven'])
        self.assertFalse(d['native_called'])

    def test_entry_change_rejects_before_either_new_extent(self):
        key = self.BASE + tool.prior.LOOKUP_RVA, 37
        raw = bytearray(tool.LOOKUP_BYTES)
        raw[18] ^= 1
        self.memory[key] = bytes(raw)
        with self.assertRaises(ValueError):
            self.capture()
        self.assertNotIn((self.BASE + tool.EXTRA_SPANS[0][0], 87), self.reads)

    def test_all_new_bounds_and_creation_gate_first_read(self):
        for options in ({'source_digest': '0' * 64}, {'expected_created': self.CREATED + 1}):
            with self.assertRaises(ValueError):
                self.capture(**options)
            self.assertEqual(self.reads, [])
        with self.assertRaises(ValueError):
            tool.capture(self.read, self.query, self.BASE, tool.EXTRA_SPANS[-1][0] + 296,
                         source_digest=tool.SOURCE_CAPTURE_SHA, actual_created=self.CREATED,
                         expected_created=self.CREATED)
        self.assertEqual(self.reads, [])

    def test_original_metadata_and_source_are_pinned(self):
        self.assertEqual(tool.load_source(tool.SOURCE_CAPTURE), tool.SOURCE_CAPTURE_SHA)
        values = {off: bytes.fromhex(raw) for _, off, raw, _ in tool.METADATA}
        disks = {off: b'\x90' * size for _, off, size, _ in tool.DISK}
        values.update(disks)
        replacements = tuple((name, off, size, hashlib.sha256(disks[off]).hexdigest())
                             for name, off, size, _ in tool.DISK)
        with patch.object(tool, 'DISK', replacements):
            self.assertEqual(tool.verify_segment_metadata(lambda off, size: values[off])['body']['segment_bytes'], 87)
            for off, original in list(values.items()):
                values[off] = original[:-1] + bytes([original[-1] ^ 1])
                with self.assertRaises(ValueError):
                    tool.verify_segment_metadata(lambda off, size: values[off])
                values[off] = original


if __name__ == '__main__':
    unittest.main()
