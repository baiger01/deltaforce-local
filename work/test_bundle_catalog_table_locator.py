import struct
import unittest
import zlib
import io
import hashlib
from types import SimpleNamespace

from bundle_catalog_table_locator import CountingReader, chunk, first_block, scan


def wrapped(data):
    pieces = [data[i:i + 131072] for i in range(0, len(data), 131072)]
    compressed = [zlib.compress(piece) for piece in pieces]
    return (struct.pack('<4Q', 0x9e2a83c1, 131072, sum(map(len, compressed)), len(data))
            + b''.join(struct.pack('<2Q', len(encoded), len(piece))
                       for piece, encoded in zip(pieces, compressed)) + b''.join(compressed))


class ChunkTests(unittest.TestCase):
    def test_single_block(self):
        data = b'StoreHotRecommendation' * 40
        self.assertEqual(chunk(wrapped(data)), data)

    def test_multiple_blocks(self):
        data = b'DataTableAssetInfo' * 16000
        self.assertEqual(chunk(wrapped(data)), data)

    def test_output_over_limit_is_unknown(self):
        raw = bytearray(wrapped(b'x'))
        struct.pack_into('<Q', raw, 24, 2 * 1024 * 1024 + 1)
        self.assertIsNone(chunk(raw))

    def test_unknown_block_size_is_unknown(self):
        raw = bytearray(wrapped(b'x'))
        struct.pack_into('<Q', raw, 8, 65536)
        self.assertIsNone(chunk(raw))

    def test_declared_output_mismatch_is_rejected(self):
        raw = bytearray(wrapped(b'abc'))
        struct.pack_into('<Q', raw, 40, 4)
        with self.assertRaises(ValueError):
            chunk(raw)

    def test_compressed_stream_trailer_is_rejected(self):
        raw = bytearray(wrapped(b'abc'))
        stored = struct.unpack_from('<Q', raw, 16)[0]
        struct.pack_into('<Q', raw, 16, stored + 1)
        struct.pack_into('<Q', raw, 32, stored + 1)
        raw.extend(b'x')
        with self.assertRaises(ValueError):
            chunk(raw)

    def test_truncated_input_is_unknown(self):
        self.assertIsNone(chunk(wrapped(b'abc')[:-1]))

    def test_overfull_output_is_rejected(self):
        raw = bytearray(wrapped(b'abc'))
        struct.pack_into('<Q', raw, 24, 2)
        struct.pack_into('<Q', raw, 40, 2)
        with self.assertRaises(ValueError):
            chunk(raw)

    def test_incomplete_zlib_eof_is_rejected(self):
        raw = bytearray(wrapped(b'header'))
        stored = struct.unpack_from('<Q', raw, 16)[0]
        struct.pack_into('<Q', raw, 16, stored - 1)
        struct.pack_into('<Q', raw, 32, stored - 1)
        with self.assertRaises(ValueError):
            chunk(raw[:-1])

    def test_stored_input_over_limit_is_unknown(self):
        raw = bytearray(wrapped(b'header'))
        struct.pack_into('<Q', raw, 16, 256 * 1024 + 1)
        self.assertIsNone(chunk(raw))


class PrefixTests(unittest.TestCase):
    def entry(self, encoded, expected, **extra):
        return dict(flags=0, method=1, blocks=[(0, len(encoded))], block_size=expected,
                    uncompressed=expected * 100, compressed=len(encoded), header_size=0, **extra)

    def test_zlib_reads_only_first_block(self):
        raw = zlib.compress(b'header')
        reader = CountingReader(io.BytesIO(raw + b'unread resource body'))
        self.assertEqual(first_block(reader, 0, self.entry(raw, 6), ['Zlib']), b'header')
        self.assertEqual(reader.count, len(raw))

    def test_encrypted_does_not_read(self):
        reader = CountingReader(io.BytesIO(b'private'))
        entry = self.entry(b'private', 7)
        entry['flags'] = 1
        self.assertIsNone(first_block(reader, 0, entry, ['Zlib']))
        self.assertEqual(reader.count, 0)

    def test_oversized_first_block_does_not_read(self):
        reader = CountingReader(io.BytesIO(b'x'))
        self.assertIsNone(first_block(reader, 0, self.entry(b'x', 131073), ['Zlib']))
        self.assertEqual(reader.count, 0)

    def test_output_mismatch_is_rejected(self):
        raw = zlib.compress(b'header')
        reader = CountingReader(io.BytesIO(raw))
        with self.assertRaises(ValueError):
            first_block(reader, 0, self.entry(raw, 5), ['Zlib'])


class FakeArchive:
    name = 'synthetic.pak'

    def __init__(self, raw):
        self.raw = raw

    def open(self, mode):
        if mode != 'rb':
            raise AssertionError('Source archive must remain read-only')
        return io.BytesIO(self.raw)

    def stat(self):
        return SimpleNamespace(st_size=len(self.raw))


def raw_entry(body, declared_size=None):
    size = len(body) if declared_size is None else declared_size
    return (struct.pack('<qqqI', 0, size, size, 0) + hashlib.sha1(body).digest()
            + struct.pack('<BI', 0, 0) + body)


def archive_footer(data_limit):
    return struct.pack('<IIQ', 0x5a6f12e1, 11, data_limit) + bytes(496)


class ArchiveGuardsTests(unittest.TestCase):
    def test_data_limit_past_file_is_rejected(self):
        data = raw_entry(b'Z', declared_size=1000000)
        source = FakeArchive(data + archive_footer(1000053))
        with self.assertRaisesRegex(ValueError, 'data limit'):
            scan(source, large_only=False, probe_large=False)

    def test_data_limit_inside_footer_is_rejected(self):
        data = raw_entry(b'Z', declared_size=47)
        source = FakeArchive(data + archive_footer(100))
        with self.assertRaisesRegex(ValueError, 'data limit'):
            scan(source, large_only=False, probe_large=False)

    def test_short_archive_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'short'):
            scan(FakeArchive(bytes(100)), large_only=False, probe_large=False)

    def test_bad_wrapper_stays_unknown_and_next_entry_is_scanned(self):
        malformed = struct.pack('<6Q', 0x9e2a83c1, 131072, 3, 3, 3, 3) + b'bad'
        invalid_layout = bytearray(wrapped(b'header'))
        struct.pack_into('<Q', invalid_layout, 40, 7)
        for payload in (malformed, invalid_layout):
            with self.subTest(payload_kind='zlib' if payload is malformed else 'layout'):
                data = raw_entry(payload) + raw_entry(wrapped(b'StoreHotRecommendation'))
                result = scan(FakeArchive(data + archive_footer(len(data))),
                              large_only=False, probe_large=False)
                self.assertTrue(result['scan_complete'])
                self.assertEqual(result['stats']['headers'], 2)
                self.assertEqual(result['stats']['nested_wrapper_decode_unknown'], 1)
                self.assertEqual(result['stats']['nested_zlib_chunks'], 1)
                self.assertEqual(result['target_or_fixed_neighbor_hits'][0]['entry'], 2)
                self.assertEqual(result['unknown_wrapper_entries'], [{
                    'entry': 1, 'offset': 0, 'status': 'unknown_invalid_or_unsupported_compressed_chunk'}])


if __name__ == '__main__':
    unittest.main()
