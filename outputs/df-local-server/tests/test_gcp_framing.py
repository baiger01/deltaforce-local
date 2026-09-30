import struct
import unittest
from dfserver.gcp_framing import BASE, Frame, MAX_BODY, StreamDecoder, decode_prefix


class GcpFramingTests(unittest.TestCase):
    def setUp(self):
        self.data = Frame(11, 13, 0x4013, 1, 123, b'\x00' * 4, b'A' * 32)
        self.control = Frame(11, 13, 0x9001, 1, 124, b'\x00' * 24, b'')

    def test_independent_known_layout(self):
        wire = bytes.fromhex('3366 000b 000d 4013 01 0000007b 00000019 00000020') + b'\x00' * 4 + b'A' * 32
        frame, size = decode_prefix(wire)
        self.assertEqual(frame, self.data)
        self.assertEqual(size, 57)
        self.assertEqual(frame.encode(), wire)

    def test_every_tcp_split_boundary_and_coalesced_frames(self):
        wire = self.data.encode() + self.control.encode()
        for split in range(len(wire) + 1):
            decoder = StreamDecoder()
            self.assertEqual(decoder.feed(wire[:split]) + decoder.feed(wire[split:]), [self.data, self.control])
            decoder.finish()

    def test_bytewise_reads_preserve_opaque_header(self):
        decoder = StreamDecoder();frames = []
        for value in self.control.encode():
            frames.extend(decoder.feed(bytes([value])))
        self.assertEqual(frames, [self.control])
        self.assertEqual(decoder.pending_bytes, 0)

    def test_invalid_header_is_rejected_before_body_allocation(self):
        for magic, version, hlen, blen in [(0x4366, 11, 25, 32), (0x3366, 12, 25, 32),
                                            (0x3366, 11, 20, 32), (0x3366, 11, 65537, 32),
                                            (0x3366, 11, 25, MAX_BODY + 1)]:
            with self.assertRaises(ValueError):
                decode_prefix(BASE.pack(magic, version, 13, 0x4013, 1, 123, hlen, blen))

    def test_truncation_is_distinct_from_valid_empty_body(self):
        decoder = StreamDecoder();decoder.feed(self.data.encode()[:-1])
        with self.assertRaisesRegex(ValueError, 'Truncated'):
            decoder.finish()
        self.assertEqual(decode_prefix(self.control.encode())[0].body, b'')

    def test_corruption_does_not_resynchronize_to_later_magic(self):
        decoder = StreamDecoder()
        with self.assertRaises(ValueError):
            decoder.feed(b'X' * BASE.size + self.data.encode())
        self.assertEqual(decoder.pending_bytes, 0)
        with self.assertRaisesRegex(ValueError, 'closed'):
            decoder.feed(self.data.encode())


if __name__ == '__main__':
    unittest.main()
