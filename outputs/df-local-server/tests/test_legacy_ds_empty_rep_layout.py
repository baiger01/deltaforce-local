"""Synthetic native-consumer inverse fixtures, not observed game packets."""
import unittest

from dfserver.legacy_ds_actor_content import (
    ActorContentBlock, read_actor_content_block, write_actor_content_block,
)
from dfserver.legacy_ds_bit_archive import BitReader, BitWriter
from dfserver.legacy_ds_rep_layout_refs import (
    EMPTY_REP_LAYOUT_BITS, ObjectReference, build_empty_rep_layout_content,
    build_object_reference_content, read_empty_rep_layout_content,
    read_object_reference_content,
)


class EmptyOrdinaryRepLayoutTests(unittest.TestCase):
    def test_literal_nine_bit_terminator_has_no_property_or_checksum(self):
        block = build_empty_rep_layout_content()
        self.assertEqual(EMPTY_REP_LAYOUT_BITS, 9)
        self.assertEqual(block, ActorContentBlock(True, b'\x00\x00', 9))
        # Independent literal reader: option bit0, then one raw packed unit00.
        reader = BitReader(bytes.fromhex('0000'), bit_count=9)
        self.assertFalse(reader.read_bool())
        self.assertEqual(reader.read_bits(8), 0)
        self.assertEqual((reader.position, reader.remaining), (9, 0))
        self.assertEqual(read_empty_rep_layout_content(block), ())

    def test_literal_nineteen_bit_actor_wrapper(self):
        block = build_empty_rep_layout_content()
        # Literal flags11 + packed length09's octet12 <<2 + nine zero bits.
        expected = (3 | (0x12 << 2)).to_bytes(3, 'little')
        self.assertEqual(expected, bytes.fromhex('4b0000'))
        writer = BitWriter(maximum_bits=19)
        self.assertEqual(write_actor_content_block(writer, block), 19)
        self.assertEqual((writer.to_bytes(), writer.bit_count), (expected, 19))
        reader = BitReader(expected, bit_count=19)
        decoded = read_actor_content_block(reader)
        self.assertEqual(decoded, block)
        self.assertEqual(read_empty_rep_layout_content(decoded), ())
        self.assertEqual((reader.position, reader.remaining), (19, 0))

    def test_unaligned_literal_wrappers_preserve_prefix_and_suffix(self):
        block = build_empty_rep_layout_content()
        for prefix_bits in range(8):
            with self.subTest(prefix_bits=prefix_bits):
                prefix = (1 << prefix_bits) - 1
                expected_value = (prefix | (0x4b << prefix_bits) |
                                  (5 << (prefix_bits + 19)))
                total_bits = prefix_bits + 19 + 3
                expected = expected_value.to_bytes((total_bits + 7) // 8, 'little')
                writer = BitWriter(maximum_bits=total_bits)
                writer.write_bits(prefix, prefix_bits)
                write_actor_content_block(writer, block)
                writer.write_bits(5, 3)
                self.assertEqual(writer.to_bytes(), expected)
                reader = BitReader(expected, bit_count=total_bits)
                self.assertEqual(reader.read_bits(prefix_bits), prefix)
                self.assertEqual(read_empty_rep_layout_content(
                    read_actor_content_block(reader)), ())
                self.assertEqual(reader.position, prefix_bits + 19)
                self.assertEqual(reader.read_bits(3), 5)
                self.assertEqual(reader.remaining, 0)

    def test_every_property_truncation_is_rejected(self):
        for bits in range(9):
            with self.subTest(bits=bits), self.assertRaises(ValueError):
                read_empty_rep_layout_content(
                    ActorContentBlock(True, b'\x00' * ((bits + 7) // 8), bits))

    def test_every_wrapper_truncation_rolls_back(self):
        for bits in range(19):
            reader = BitReader(bytes.fromhex('4b0000'), bit_count=bits)
            with self.subTest(bits=bits), self.assertRaises(ValueError):
                read_actor_content_block(reader)
            self.assertEqual(reader.position, 0)

    def test_trailing_bits_are_not_byte_padding_inside_the_slice(self):
        for bits in range(10, 17):
            for suffix_bit in (0, 1):
                value = suffix_bit << 9
                raw = value.to_bytes((bits + 7) // 8, 'little')
                with self.subTest(bits=bits, suffix=suffix_bit), self.assertRaises(ValueError):
                    read_empty_rep_layout_content(ActorContentBlock(True, raw, bits))

    def test_alternate_option_and_nonzero_handles_are_rejected(self):
        for raw in (bytes.fromhex('0100'), bytes.fromhex('0400'),
                    bytes.fromhex('0001')):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                read_empty_rep_layout_content(ActorContentBlock(True, raw, 9))

    def test_overlong_and_truncated_packed_zero_are_rejected(self):
        # After option0: packed units01 00 are overlong; unit01 alone continues.
        for raw, bits in ((bytes.fromhex('020000'), 17), (bytes.fromhex('0200'), 9)):
            with self.subTest(bits=bits), self.assertRaises(ValueError):
                read_empty_rep_layout_content(ActorContentBlock(True, raw, bits))

    def test_strict_types_exact_storage_and_unused_high_bits(self):
        for block in (object(), ActorContentBlock(False, b'\0\0', 9),
                      ActorContentBlock(1, b'\0\0', 9),
                      ActorContentBlock(True, b'\0\0', True),
                      ActorContentBlock(True, b'\0\0', 9.0),
                      ActorContentBlock(True, b'\0\0', -1),
                      ActorContentBlock(True, b'\0', 9),
                      ActorContentBlock(True, b'\0\0\0', 9),
                      ActorContentBlock(True, bytearray(b'\0\0'), 9),
                      ActorContentBlock(True, bytes.fromhex('0002'), 9)):
            with self.subTest(block=block), self.assertRaises(ValueError):
                read_empty_rep_layout_content(block)

    def test_zero_length_body_is_distinct_and_rejected_as_property_stream(self):
        reader = BitReader(bytes.fromhex('0300'), bit_count=10)
        empty_body = read_actor_content_block(reader)
        self.assertEqual(empty_body, ActorContentBlock(True, b'', 0))
        self.assertEqual(reader.remaining, 0)
        with self.assertRaises(ValueError):
            read_empty_rep_layout_content(empty_body)

    def test_wrapper_budget_failure_is_atomic(self):
        writer = BitWriter(maximum_bits=21)
        writer.write_bits(5, 3)
        before = writer.to_bytes(), writer.bit_count
        with self.assertRaises(ValueError):
            write_actor_content_block(writer, build_empty_rep_layout_content())
        self.assertEqual((writer.to_bytes(), writer.bit_count), before)
        exact = BitWriter(maximum_bits=22)
        exact.write_bits(5, 3)
        self.assertEqual(write_actor_content_block(exact, build_empty_rep_layout_content()), 19)
        self.assertEqual(exact.bit_count, 22)

    def test_existing_nonempty_reference_contract_is_unchanged(self):
        with self.assertRaises(ValueError):
            build_object_reference_content(())
        with self.assertRaises(ValueError):
            read_object_reference_content(build_empty_rep_layout_content())
        refs = (ObjectReference(18, 2),)
        block = build_object_reference_content(refs)
        self.assertEqual(block, ActorContentBlock(True, bytes.fromhex('48080000'), 25))
        self.assertEqual(read_object_reference_content(block), refs)
        with self.assertRaises(ValueError):
            read_empty_rep_layout_content(block)


if __name__ == '__main__':
    unittest.main()
