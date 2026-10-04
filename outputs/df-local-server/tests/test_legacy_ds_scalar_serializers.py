import unittest

from dfserver.legacy_ds_bit_archive import BitReader, BitWriter, UINT32_MAX
from dfserver.legacy_ds_scalar_serializers import (
    BOOL_SERIALIZER_RVA, INT32_SERIALIZER_RVA, OBJECT_SERIALIZER_RVA,
    INT32_SCALAR_LEAF_RVA, INT32_PROPERTY_VTABLE_RVA,
    SHIPPING_SHA256, NativeScalarBinding, write_bool_value,
    write_int32_value, write_resolved_object_reference,
)


class SourceQualifiedScalarTests(unittest.TestCase):
    def binding(self, rva):
        if rva == INT32_SERIALIZER_RVA:
            return NativeScalarBinding(SHIPPING_SHA256, rva,
                scalar_leaf_target_rva=INT32_SCALAR_LEAF_RVA,
                property_vtable_rva=INT32_PROPERTY_VTABLE_RVA)
        return NativeScalarBinding(SHIPPING_SHA256, rva)

    def write_bool(self, writer, value, **changes):
        options = dict(binding=self.binding(BOOL_SERIALIZER_RVA))
        options.update(changes)
        return write_bool_value(writer, value, **options)

    def write_int(self, writer, value, **changes):
        options = dict(binding=self.binding(INT32_SERIALIZER_RVA), no_byteswap=True)
        options.update(changes)
        return write_int32_value(writer, value, **options)

    def write_object(self, writer, value, **changes):
        options = dict(binding=self.binding(OBJECT_SERIALIZER_RVA), export_mode=False,
                       reference_resolved=True, exports_acknowledged=True)
        options.update(changes)
        return write_resolved_object_reference(writer, value, **options)

    def assert_rejected(self, function, value, **changes):
        writer = BitWriter()
        writer.write_bits(5, 3)
        before = writer.to_bytes(), writer.bit_count
        with self.assertRaises(ValueError):
            function(writer, value, **changes)
        self.assertEqual((writer.to_bytes(), writer.bit_count), before)

    def test_boolean_literals_are_one_bit(self):
        for value, expected in ((False, b'\x00'), (True, b'\x01')):
            with self.subTest(value=value):
                writer = BitWriter()
                self.assertEqual(self.write_bool(writer, value), 1)
                self.assertEqual((writer.to_bytes(), writer.bit_count), (expected, 1))

    def test_signed_raw32_literals(self):
        for value, literal in ((0, '00000000'), (0x12345678, '78563412'),
                               (-1, 'ffffffff'), (-(1 << 31), '00000080'),
                               ((1 << 31)-1, 'ffffff7f')):
            with self.subTest(value=value):
                writer = BitWriter()
                self.assertEqual(self.write_int(writer, value), 32)
                self.assertEqual(writer.to_bytes(), bytes.fromhex(literal))

    def test_ordinary_guid_literals_have_no_flag_byte(self):
        for value, literal in ((0, '00'), (2, '04'), (3, '06'), (128, '0102'),
                               (255, 'ff02'), (UINT32_MAX, 'ffffffff1e')):
            with self.subTest(value=value):
                writer = BitWriter()
                raw = bytes.fromhex(literal)
                self.assertEqual(self.write_object(writer, value), 8*len(raw))
                self.assertEqual(writer.to_bytes(), raw)

    def test_literal_combination_is_unaligned_and_preserves_following_bits(self):
        writer = BitWriter()
        writer.write_bits(5, 3)
        self.write_bool(writer, True)
        self.write_int(writer, 0x12345678)
        self.write_object(writer, 255)
        writer.write_bits(0xa5, 8)
        # 3b prefix5 + true + raw78563412 + packedff02 + suffixa5 =60bits.
        self.assertEqual((writer.to_bytes(), writer.bit_count),
                         (bytes.fromhex('8d674523f12f500a'), 60))
        reader = BitReader(writer.to_bytes(), bit_count=60)
        self.assertEqual(reader.read_bits(3), 5)
        self.assertTrue(reader.read_bool())
        self.assertEqual(reader.read_bytes(4), bytes.fromhex('78563412'))
        self.assertEqual(reader.read_packed_int(), 255)
        self.assertEqual(reader.read_bits(8), 0xa5)
        self.assertEqual(reader.remaining, 0)

    def test_every_cursor_offset_matches_independent_value_literal(self):
        cases = ((self.write_bool, True, 1, 1),
                 (self.write_int, -2, 0xfffffffe, 32),
                 (self.write_object, 255, 0x02ff, 16))
        for function, value, literal, width in cases:
            for prefix_width in range(8):
                with self.subTest(function=function.__name__, offset=prefix_width):
                    prefix = (1 << prefix_width)-1
                    writer = BitWriter()
                    writer.write_bits(prefix, prefix_width)
                    self.assertEqual(function(writer, value), width)
                    writer.write_bits(0x13, 5)
                    # Literal field integers, not production serializer calls.
                    expected = prefix | (literal << prefix_width) | (0x13 << (prefix_width+width))
                    total = prefix_width+width+5
                    self.assertEqual(writer.to_bytes(), expected.to_bytes((total+7)//8, 'little'))
                    self.assertEqual(writer.bit_count, total)

    def test_strict_value_types_and_bounds(self):
        for value in (0, 1, None, 'True'):
            self.assert_rejected(self.write_bool, value)
        for value in (True, 1.0, None, '1', -(1 << 31)-1, 1 << 31):
            self.assert_rejected(self.write_int, value)
        for value in (True, 1.0, None, '2', 1, -1, 1 << 32):
            self.assert_rejected(self.write_object, value)

    def test_source_hash_is_exact(self):
        for function, value, rva in ((self.write_bool, True, BOOL_SERIALIZER_RVA),
                                    (self.write_int, 1, INT32_SERIALIZER_RVA),
                                    (self.write_object, 2, OBJECT_SERIALIZER_RVA)):
            for source in ('0'*64, SHIPPING_SHA256.upper(), None):
                self.assert_rejected(function, value,
                    binding=NativeScalarBinding(source, rva))

    def test_hook_target_not_opcode_or_property_name(self):
        for function, value, rva in ((self.write_bool, True, BOOL_SERIALIZER_RVA),
                                    (self.write_int, 1, INT32_SERIALIZER_RVA),
                                    (self.write_object, 2, OBJECT_SERIALIZER_RVA)):
            for wrong in (5, 0x10e8ec50, rva+1, str(rva), True):
                self.assert_rejected(function, value,
                    binding=NativeScalarBinding(SHIPPING_SHA256, wrong))
            self.assert_rejected(function, value, binding={'serializer_target_rva': rva})

    def test_int_byteswap_profile_must_be_explicit(self):
        for profile in (False, None, 1, 'no'):
            self.assert_rejected(self.write_int, 1, no_byteswap=profile)

    def test_generic_numeric_hook_does_not_qualify_int_without_exact_leaf_and_table(self):
        for leaf, table in ((None, None), (INT32_SCALAR_LEAF_RVA, None),
                            (None, INT32_PROPERTY_VTABLE_RVA),
                            (INT32_SCALAR_LEAF_RVA+1, INT32_PROPERTY_VTABLE_RVA),
                            (INT32_SCALAR_LEAF_RVA, INT32_PROPERTY_VTABLE_RVA+1),
                            (str(INT32_SCALAR_LEAF_RVA), INT32_PROPERTY_VTABLE_RVA),
                            (INT32_SCALAR_LEAF_RVA, True)):
            with self.subTest(leaf=leaf, table=table):
                self.assert_rejected(self.write_int, 1, binding=NativeScalarBinding(
                    SHIPPING_SHA256, INT32_SERIALIZER_RVA,
                    scalar_leaf_target_rva=leaf, property_vtable_rva=table))

    def test_object_contracts_must_be_explicit_and_ordinary(self):
        for label in ('reference_resolved', 'exports_acknowledged'):
            for invalid in (False, None, 1, 'yes'):
                self.assert_rejected(self.write_object, 2, **{label: invalid})
        for invalid in (True, None, 0, 'no'):
            self.assert_rejected(self.write_object, 2, export_mode=invalid)

    def test_local_capacity_rejection_does_not_leave_partial_field(self):
        for function, value, width in ((self.write_bool, True, 1),
                                       (self.write_int, 0x12345678, 32),
                                       (self.write_object, UINT32_MAX, 40)):
            writer = BitWriter(maximum_bits=3+width-1)
            writer.write_bits(5, 3)
            before = writer.to_bytes(), writer.bit_count
            with self.assertRaises(ValueError):
                function(writer, value)
            self.assertEqual((writer.to_bytes(), writer.bit_count), before)

    def test_exact_capacity_has_no_implicit_padding(self):
        for function, value, width in ((self.write_bool, False, 1),
                                       (self.write_int, -1, 32),
                                       (self.write_object, 255, 16)):
            writer = BitWriter(maximum_bits=3+width)
            writer.write_bits(5, 3)
            self.assertEqual(function(writer, value), width)
            self.assertEqual(writer.bit_count, writer.maximum_bits)

    def test_non_native_writer_is_rejected(self):
        for function, value in ((self.write_bool, True), (self.write_int, 1),
                                (self.write_object, 2)):
            with self.assertRaises(ValueError):
                function(object(), value)


if __name__ == '__main__':
    unittest.main()
