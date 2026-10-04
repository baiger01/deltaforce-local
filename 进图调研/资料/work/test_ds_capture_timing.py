import struct
import unittest

from ds_capture_timing import packet_unix_times


def block(kind, body, endian='<'):
    size = len(body) + 12
    return struct.pack(endian + 'II', kind, size) + body + struct.pack(endian + 'I', size)


def section(endian='<'):
    return block(0x0a0d0d0a, struct.pack(endian + 'IHHq', 0x1a2b3c4d, 1, 0, -1), endian)


def packet(ticks, endian='<'):
    return block(6, struct.pack(endian + '5I', 0, ticks >> 32, ticks & 0xffffffff, 0, 0), endian)


class DSCaptureTimingTests(unittest.TestCase):
    def test_decimal_and_binary_resolution_offsets_and_section_reset(self):
        for endian in ('<', '>'):
            options = (struct.pack(endian + 'HHB3x', 9, 1, 0x8a) +
                       struct.pack(endian + 'HHq', 14, 8, -2) + struct.pack(endian + 'HH', 0, 0))
            descriptor = struct.pack(endian + 'HHI', 1, 0, 65535)
            binary = section(endian) + block(1, descriptor + options, endian) + packet(2560, endian)
            default = section(endian) + block(1, descriptor, endian) + packet(1234567, endian)
            self.assertEqual(list(packet_unix_times(binary + default)), [0.5, 1.234567])

    def test_pcap_microseconds_and_nanoseconds(self):
        for magic, scale, endian in ((b'\xd4\xc3\xb2\xa1', 10**6, '<'),
                                     (b'\xa1\xb2\x3c\x4d', 10**9, '>')):
            raw = magic + bytes(20) + struct.pack(endian + '4I', 2, scale // 4, 0, 0)
            self.assertEqual(list(packet_unix_times(raw)), [2.25])
            invalid = magic + bytes(20) + struct.pack(endian + '4I', 2, scale, 0, 0)
            with self.assertRaises(ValueError):
                list(packet_unix_times(invalid))

    def test_truncation_unknown_interface_and_duplicate_options_fail(self):
        descriptor = struct.pack('<HHI', 1, 0, 65535)
        option = struct.pack('<HHB3x', 9, 1, 6)
        invalid = [section() + packet(1),
                   section() + block(1, descriptor + option * 2) + packet(1),
                   section() + block(1, descriptor) + packet(1)[:-1]]
        for raw in invalid:
            with self.assertRaises(ValueError):
                list(packet_unix_times(raw))
