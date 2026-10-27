import unittest
from dfserver.legacy_ds_bit_archive import BitWriter
from dfserver.legacy_ds_scalar_serializers import (NativeScalarBinding, SHIPPING_SHA256,
    INT32_SERIALIZER_RVA, UINT64_SCALAR_LEAF_RVA, UINT64_PROPERTY_VTABLE_RVA, write_uint64_value)


class Unsigned64Tests(unittest.TestCase):
    def binding(self):
        return NativeScalarBinding(SHIPPING_SHA256, INT32_SERIALIZER_RVA,
                                   UINT64_SCALAR_LEAF_RVA, UINT64_PROPERTY_VTABLE_RVA)

    def test_eight_bytes_are_written_at_the_current_unaligned_bit_cursor(self):
        for value in (0, 2201, (1 << 64) - 1):
            writer = BitWriter(maximum_bits=72);writer.write_bool(True)
            write_uint64_value(writer, value, binding=self.binding(), no_byteswap=True)
            self.assertEqual(writer.bit_count, 65)
            self.assertEqual(writer.to_bytes(), ((value << 1) | 1).to_bytes(9, 'little'))

    def test_generic_hook_alone_wrong_width_and_capacity_never_change_the_cursor(self):
        for value, binding, swap, size in (
                (1, NativeScalarBinding(SHIPPING_SHA256, INT32_SERIALIZER_RVA), True, 72),
                (-1, self.binding(), True, 72), (1 << 64, self.binding(), True, 72),
                (True, self.binding(), True, 72), (1, self.binding(), False, 72),
                (1, self.binding(), True, 64)):
            writer = BitWriter(maximum_bits=size);writer.write_bool(True)
            with self.assertRaises(ValueError):write_uint64_value(writer, value, binding=binding, no_byteswap=swap)
            self.assertEqual((writer.bit_count, writer.to_bytes()), (1, b'\1'))
