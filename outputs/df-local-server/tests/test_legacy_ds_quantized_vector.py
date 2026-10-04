import struct
import unittest

from dfserver.legacy_ds_bit_archive import BitReader, BitWriter
from dfserver.legacy_ds_quantized_vector import (
    MAX_STEP, MIN_STEP, NATIVE_SCALE, QuantizedVector10,
    read_compressed_vector10, write_compressed_vector10,
)


class NativeCompressedVectorTests(unittest.TestCase):
    def decode(self, data, bits, version):
        reader = BitReader(data, bit_count=bits)
        result = read_compressed_vector10(reader, archive_network_version=version)
        self.assertEqual(reader.remaining, 0)
        return result

    def encode(self, steps, version):
        writer = BitWriter()
        write_compressed_vector10(writer, QuantizedVector10(steps),
                                  archive_network_version=version)
        return writer.to_bytes(), writer.bit_count

    def test_fixed_native_field_fixture_zero_positive_negative_without_selector(self):
        # B=0 => bias2, two bits per component; biased axes are2,3,1.
        vector = self.decode(bytes.fromhex('c003'), 11, 12)
        self.assertEqual(vector.steps, (0, 1, -1))
        self.assertEqual(self.encode((0, 1, -1), 12), (bytes.fromhex('c003'), 11))

    def test_version13_compression_selector_is_a_bit_not_a_byte(self):
        self.assertEqual(self.decode(bytes.fromhex('8107'), 12, 13).steps, (0, 1, -1))
        self.assertEqual(self.encode((0, 1, -1), 13), (bytes.fromhex('8107'), 12))

    def test_fixed_wider_fixture_has_three_biased_components(self):
        # B=1 => bias4; axes6,1,7 occupy three bits each after width.
        self.assertEqual(self.decode(bytes.fromhex('c139'), 14, 12).steps, (2, -3, 3))
        self.assertEqual(self.encode((2, -3, 3), 12), (bytes.fromhex('c139'), 14))

    def test_maximum_native_components_fixture(self):
        data = bytes.fromhex('170000000000c0ffffff')
        vector = self.decode(data, 80, 12)
        self.assertEqual(vector.steps, (MIN_STEP, 0, MAX_STEP))
        self.assertEqual(self.encode(vector.steps, 12), (data, 80))

    def test_non_byte_aligned_caller_and_following_field_are_preserved(self):
        writer = BitWriter()
        writer.write_bits(5, 3)
        write_compressed_vector10(writer, QuantizedVector10((2, -3, 3)),
                                  archive_network_version=13)
        writer.write_bits(0xa5, 8)
        reader = BitReader(writer.to_bytes(), bit_count=writer.bit_count)
        self.assertEqual(reader.read_bits(3), 5)
        self.assertEqual(read_compressed_vector10(reader,
            archive_network_version=13).steps, (2, -3, 3))
        self.assertEqual(reader.read_bits(8), 0xa5)
        self.assertEqual(reader.remaining, 0)

    def test_native_float32_scale_and_multiplication(self):
        self.assertEqual(struct.pack('<f', NATIVE_SCALE), bytes.fromhex('cdcccc3d'))
        values = QuantizedVector10((10, 1, -3)).native_float_components()
        self.assertEqual(struct.pack('<3f', *values).hex(), '0000803fcdcccc3d9a9999be')

    def test_unknown_raw_branch_and_every_truncation_leave_cursor_unchanged(self):
        reader = BitReader(b'\x00', bit_count=1)
        with self.assertRaisesRegex(ValueError, 'Raw spawn-vector'):
            read_compressed_vector10(reader, archive_network_version=13)
        self.assertEqual(reader.position, 0)
        for bits in range(12):
            with self.subTest(bits=bits):
                reader = BitReader(bytes.fromhex('8107'), bit_count=bits)
                with self.assertRaises(ValueError):
                    read_compressed_vector10(reader, archive_network_version=13)
                self.assertEqual(reader.position, 0)

    def test_invalid_inputs_and_too_small_output_archive_are_atomic(self):
        for steps in ((True, 0, 0), (MAX_STEP+1, 0, 0), (MIN_STEP-1, 0, 0),
                      (0, 0), [0, 0, 0], (0.0, 0, 0)):
            with self.subTest(steps=steps), self.assertRaises(ValueError):
                QuantizedVector10(steps)
        for version in (True, -1, 1 << 32, '13', None):
            with self.subTest(version=version), self.assertRaises(ValueError):
                self.encode((0, 0, 0), version)
        writer = BitWriter(maximum_bits=10)
        writer.write_bool(True)
        before = writer.to_bytes(), writer.bit_count
        with self.assertRaises(ValueError):
            write_compressed_vector10(writer, QuantizedVector10((0, 1, -1)),
                                      archive_network_version=13)
        self.assertEqual((writer.to_bytes(), writer.bit_count), before)


if __name__ == '__main__':
    unittest.main()
