import unittest

from dfserver.legacy_ds_bit_archive import BitReader, BitWriter


class NativeBitArchiveTests(unittest.TestCase):
    def test_pinned_lsb_mask_order_and_unaligned_byte_groups(self):
        writer = BitWriter()
        writer.write_bool(True)
        writer.write_bytes(b'\x01\x80')
        self.assertEqual(writer.to_bytes(), b'\x03\x00\x01')
        reader = BitReader(writer.to_bytes(), bit_count=17)
        self.assertTrue(reader.read_bool())
        self.assertEqual(reader.read_bytes(2), b'\x01\x80')
        self.assertEqual(reader.remaining, 0)

    def test_non_power_of_two_maximum_uses_value_dependent_length(self):
        # Native max=15 loop stops after three bits for value 7; value 6
        # still needs the fourth zero bit. Fixed ceil(log2(max)) is wrong.
        for value, expected, count in ((7, b'\x07', 3), (6, b'\x06', 4),
                                       (14, b'\x0e', 4), (0, b'\x00', 4)):
            writer = BitWriter()
            writer.write_bounded_int(value, 15)
            self.assertEqual((writer.to_bytes(), writer.bit_count), (expected, count))
            reader = BitReader(expected, bit_count=count)
            self.assertEqual(reader.read_bounded_int(15), value)
            self.assertEqual(reader.remaining, 0)
        writer = BitWriter()
        writer.write_bounded_int(0, 1)
        self.assertEqual(writer.bit_count, 0)

    def test_bounded_values_survive_sequential_fields_and_all_small_maxima(self):
        for maximum in range(1, 100):
            writer = BitWriter()
            for value in range(maximum):
                writer.write_bounded_int(value, maximum)
            reader = BitReader(writer.to_bytes(), bit_count=writer.bit_count)
            self.assertEqual([reader.read_bounded_int(maximum) for _ in range(maximum)],
                             list(range(maximum)))
            self.assertEqual(reader.remaining, 0)

    def test_native_packed_uint32_golden_groups_and_unaligned_cursor(self):
        cases = ((0, '00'), (127, 'fe'), (128, '0102'),
                 (255, 'ff02'), (256, '0104'), (0xffffffff, 'ffffffff1e'))
        for value, expected_hex in cases:
            expected = bytes.fromhex(expected_hex)
            writer = BitWriter()
            writer.write_packed_int(value)
            self.assertEqual(writer.to_bytes(), expected)
            writer = BitWriter()
            writer.write_bits(5, 3)
            writer.write_packed_int(value)
            reader = BitReader(writer.to_bytes(), bit_count=writer.bit_count)
            self.assertEqual(reader.read_bits(3), 5)
            self.assertEqual(reader.read_packed_int(), value)
            self.assertEqual(reader.remaining, 0)

    def test_truncation_overflow_and_local_noncanonical_rejection(self):
        for raw in (b'\x01', b'\x01\x00', b'\xff'*5, b'\xff'*4+b'\x20'):
            with self.assertRaises(ValueError):
                BitReader(raw).read_packed_int()
        with self.assertRaises(ValueError):
            BitReader(b'\x06', bit_count=3).read_bounded_int(15)
        for value, maximum in ((15, 15), (-1, 15), (True, 2), (0, 0)):
            with self.assertRaises(ValueError):
                BitWriter().write_bounded_int(value, maximum)
        with self.assertRaises(ValueError):
            BitWriter(maximum_bits=7).write_packed_int(1)

    def test_partial_bit_payload_cannot_hide_padding_or_truncation(self):
        writer = BitWriter()
        writer.write_bits(3, 2)
        writer.write_payload(b'\x15', 5)
        reader = BitReader(writer.to_bytes(), bit_count=7)
        self.assertEqual(reader.read_bits(2), 3)
        self.assertEqual(reader.read_payload(5), b'\x15')
        with self.assertRaises(ValueError):
            reader.read_bits(1)
        with self.assertRaises(ValueError):
            BitWriter().write_payload(b'\xf5', 5)


if __name__ == '__main__':
    unittest.main()
