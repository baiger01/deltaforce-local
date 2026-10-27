import unittest
from dataclasses import replace

from dfserver.legacy_ds_bit_archive import BitWriter, BitReader
from dfserver.legacy_ds_scalar_serializers import NativeScalarBinding, SHIPPING_SHA256
from dfserver.legacy_ds_int64_value import write_int64_value

BINDING = NativeScalarBinding(SHIPPING_SHA256, 0x10e5ce20, 0x286c000, 0x15a86560)


class Int64ValueTests(unittest.TestCase):
    def test_signed_extremes_and_asset_sized_value_at_unaligned_cursor(self):
        for value in (-(1 << 63), -1, 0, 1, 88000000025, (1 << 63) - 1):
            with self.subTest(value=value):
                writer = BitWriter(maximum_bits=70)
                writer.write_bool(True)
                self.assertEqual(write_int64_value(writer, value, binding=BINDING, no_byteswap=True), 64)
                writer.write_bool(False)
                reader = BitReader(writer.to_bytes(), bit_count=writer.bit_count)
                self.assertTrue(reader.read_bool())
                self.assertEqual(int.from_bytes(reader.read_bytes(8), 'little', signed=True), value)
                self.assertFalse(reader.read_bool())
                self.assertEqual(reader.remaining, 0)

    def test_wrong_numeric_table_or_leaf_cannot_be_substituted(self):
        for binding in (None, replace(BINDING, property_vtable_rva=0x1ab60db0),
                replace(BINDING, property_vtable_rva=0x15a863c0),
                replace(BINDING, scalar_leaf_target_rva=0x286bf70),
                replace(BINDING, serializer_target_rva=0),
                replace(BINDING, client_sha256='0' * 64)):
            writer = BitWriter(maximum_bits=100)
            writer.write_bool(True)
            before = (writer.to_bytes(), writer.bit_count)
            with self.subTest(binding=binding), self.assertRaises(ValueError):
                write_int64_value(writer, 1, binding=binding, no_byteswap=True)
            self.assertEqual((writer.to_bytes(), writer.bit_count), before)

    def test_invalid_values_and_archive_profile_leave_writer_untouched(self):
        for value in (True, 1.0, '1', -(1 << 63) - 1, 1 << 63):
            writer = BitWriter(maximum_bits=100)
            with self.subTest(value=value), self.assertRaises(ValueError):
                write_int64_value(writer, value, binding=BINDING, no_byteswap=True)
            self.assertEqual(writer.bit_count, 0)
        for choice in (False, None, 1):
            writer = BitWriter(maximum_bits=100)
            with self.subTest(choice=choice), self.assertRaises(ValueError):
                write_int64_value(writer, 1, binding=BINDING, no_byteswap=choice)
            self.assertEqual(writer.bit_count, 0)

    def test_capacity_rejection_is_atomic(self):
        writer = BitWriter(maximum_bits=63)
        before = (writer.to_bytes(), writer.bit_count)
        with self.assertRaises(ValueError):
            write_int64_value(writer, 1, binding=BINDING, no_byteswap=True)
        self.assertEqual((writer.to_bytes(), writer.bit_count), before)


if __name__ == '__main__':
    unittest.main()
