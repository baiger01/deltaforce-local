"""Literal normal-field fixtures, not evidence of game-class acceptance."""
import unittest

from dfserver.legacy_ds_actor_content import ActorContentBlock
from dfserver.legacy_ds_actor_fields import (
    ClassFieldEnvelope, ClassFieldLimits, NormalClassFieldProfile,
    build_class_field_content, read_class_field_content,
    read_class_field, read_class_fields, write_class_field, write_class_fields,
)
from dfserver.legacy_ds_bit_archive import BitReader, BitWriter, MAX_BITS, UINT32_MAX


PROFILE = NormalClassFieldProfile(6, False)  # Synthetic class maximum, not a game ID.
THREE = ClassFieldEnvelope(3, b'\x05', 3)
ZERO = ClassFieldEnvelope(0, b'', 0)


class ActorFieldTests(unittest.TestCase):
    def assert_literal(self, field, raw, bits, profile=PROFILE):
        writer = BitWriter()
        self.assertEqual(write_class_field(writer, field, profile=profile), bits)
        self.assertEqual(writer.to_bytes(), raw)
        reader = BitReader(raw, bit_count=bits)
        self.assertEqual(read_class_field(reader, profile=profile), field)
        self.assertEqual(reader.remaining, 0)

    def test_literal_value_dependent_index_maximum_not_fixed_width(self):
        # M6/index3 uses two index bits11; packed length06; body bits101.
        self.assert_literal(THREE, bytes.fromhex('1b14'), 13)
        # M3/index1 uses one index bit1, index2 uses two bits01.
        self.assert_literal(ClassFieldEnvelope(1, b'\x05', 3),
                            bytes.fromhex('0d0a'), 12, NormalClassFieldProfile(3, False))
        self.assert_literal(ClassFieldEnvelope(2, b'\x05', 3),
                            bytes.fromhex('1a14'), 13, NormalClassFieldProfile(3, False))

    def test_index_zero_and_zero_length_do_not_end_the_sequence(self):
        # 11 zero bits followed by literal13-bit THREE, no terminator.
        raw = bytes.fromhex('00d8a0')
        fields = (ZERO, THREE)
        reader = BitReader(raw, bit_count=24)
        self.assertEqual(read_class_fields(reader, profile=PROFILE), fields)
        writer = BitWriter()
        self.assertEqual(write_class_fields(writer, fields, profile=PROFILE), 24)
        self.assertEqual(writer.to_bytes(), raw)

    def test_maximum_one_index_has_zero_bits_but_length_still_consumes_eight(self):
        profile = NormalClassFieldProfile(1, False)
        self.assert_literal(ZERO, b'\0', 8, profile)
        self.assert_literal(ClassFieldEnvelope(0, b'\xa5', 8),
                            bytes.fromhex('10a5'), 16, profile)
        reader = BitReader(b'\0\0')
        self.assertEqual(read_class_fields(reader, profile=profile), (ZERO, ZERO))

    def test_literal_nonzero_archive_cursor_and_suffix_preserved(self):
        reader = BitReader(bytes.fromhex('dda0a5'), bit_count=24)
        self.assertEqual(reader.read_bits(3), 5)
        self.assertEqual(read_class_field(reader, profile=PROFILE), THREE)
        self.assertEqual(reader.read_bits(8), 0xa5)
        writer = BitWriter()
        writer.write_bits(5, 3)
        write_class_field(writer, THREE, profile=PROFILE)
        writer.write_bits(0xa5, 8)
        self.assertEqual(writer.to_bytes(), bytes.fromhex('dda0a5'))

    def test_each_truncation_is_atomic(self):
        for length in range(13):
            for operation in (read_class_field, read_class_fields):
                if length == 0 and operation is read_class_fields:
                    continue
                reader = BitReader(bytes.fromhex('1b14'), bit_count=length)
                with self.assertRaises(ValueError, msg=str((length, operation))):
                    operation(reader, profile=PROFILE)
                self.assertEqual(reader.position, 0)

    def test_invalid_second_field_rolls_back_entire_sequence(self):
        # Correct THREE then index0 without its full packed length byte.
        reader = BitReader(bytes.fromhex('1b14'), bit_count=16)
        with self.assertRaises(ValueError):
            read_class_fields(reader, profile=PROFILE)
        self.assertEqual(reader.position, 0)
        writer = BitWriter()
        writer.write_bits(5, 3)
        with self.assertRaises(ValueError):
            write_class_fields(writer, (THREE, ClassFieldEnvelope(6, b'', 0)), profile=PROFILE)
        self.assertEqual((writer.to_bytes(), writer.bit_count), (b'\x05', 3))

    def test_header_payload_and_sequence_limits_are_relative_and_atomic(self):
        for limits in (ClassFieldLimits(max_payload_bits=2), ClassFieldLimits(max_total_bits=12)):
            reader = BitReader(bytes.fromhex('dda0a5'), bit_count=24)
            reader.read_bits(3)
            with self.assertRaises(ValueError):
                read_class_field(reader, profile=PROFILE, limits=limits)
            self.assertEqual(reader.position, 3)
            writer = BitWriter()
            with self.assertRaises(ValueError):
                write_class_field(writer, THREE, profile=PROFILE, limits=limits)
            self.assertEqual(writer.bit_count, 0)
        reader = BitReader(bytes.fromhex('00d8a0'), bit_count=24)
        with self.assertRaises(ValueError):
            read_class_fields(reader, profile=PROFILE, limits=ClassFieldLimits(max_fields=1))
        self.assertEqual(reader.position, 0)

    def test_writer_capacity_failure_preserves_prior_fields(self):
        writer = BitWriter(maximum_bits=15)
        writer.write_bits(5, 3)
        with self.assertRaises(ValueError):
            write_class_field(writer, THREE, profile=PROFILE)
        self.assertEqual((writer.to_bytes(), writer.bit_count), (b'\x05', 3))

    def test_empty_sequence_requires_valid_profile_but_no_count_budget(self):
        limits = ClassFieldLimits(max_fields=0, max_payload_bits=0, max_total_bits=1)
        self.assertEqual(read_class_fields(BitReader(b''), profile=PROFILE, limits=limits), ())
        self.assertEqual(write_class_fields(BitWriter(), (), profile=PROFILE, limits=limits), 0)
        for operation, value in ((read_class_field, BitReader(b'\0\0', bit_count=11)),
                                 (write_class_field, BitWriter())):
            with self.assertRaises(ValueError):
                if operation is read_class_field:
                    operation(value, profile=PROFILE, limits=limits)
                else:
                    operation(value, ZERO, profile=PROFILE, limits=limits)
        with self.assertRaises(ValueError):
            build_class_field_content((), profile=object())

    def test_profile_requires_real_external_maximum_and_normal_branch(self):
        for maximum, internal_ack in ((True, False), (0, False), (-1, False),
                                      (UINT32_MAX+1, False), (3, True), (3, 0), (3, None)):
            with self.assertRaises(ValueError):
                NormalClassFieldProfile(maximum, internal_ack)
        for field in (ClassFieldEnvelope(True, b'', 0), ClassFieldEnvelope(-1, b'', 0),
                      ClassFieldEnvelope(6, b'', 0), ClassFieldEnvelope(3, b'', True),
                      ClassFieldEnvelope(3, b'', -1), object()):
            with self.assertRaises(ValueError):
                write_class_field(BitWriter(), field, profile=PROFILE)

    def test_exact_payload_length_and_high_padding_bits_required_by_writer(self):
        for payload in (b'\xff', b'\x05\0', b'', bytearray(b'\x05')):
            writer = BitWriter()
            writer.write_bits(5, 3)
            with self.assertRaises(ValueError):
                write_class_field(writer, ClassFieldEnvelope(3, payload, 3), profile=PROFILE)
            self.assertEqual((writer.to_bytes(), writer.bit_count), (b'\x05', 3))

    def test_bad_packed_lengths_are_rejected_before_slicing_or_allocation(self):
        profile = NormalClassFieldProfile(1, False)
        for groups in (b'\x01', bytes.fromhex('0100'), bytes.fromhex('ffffffff20'),
                       bytes.fromhex('ffffffff1e')):
            reader = BitReader(groups)
            with self.assertRaises(ValueError):
                read_class_field(reader, profile=profile)
            self.assertEqual(reader.position, 0)

    def test_packed_length_can_cross_multiple_bytes_without_alignment(self):
        # M3/index1 consumes1bit; length128's groups01,02 start immediately.
        field = ClassFieldEnvelope(1, b'\0'*16, 128)
        raw = (1 + (0x0201 << 1)).to_bytes(19, 'little')
        self.assert_literal(field, raw, 145, NormalClassFieldProfile(3, False))

    def test_exact_local_resource_limit_includes_header(self):
        # Index3 uses2bits, length65510 uses24bits(groupscd ff 06).
        field = ClassFieldEnvelope(3, b'\0'*8189, MAX_BITS-26)
        raw = (3 + (int.from_bytes(bytes.fromhex('cdff06'), 'little') << 2)).to_bytes(8192, 'little')
        self.assert_literal(field, raw, MAX_BITS)
        with self.assertRaises(ValueError):
            write_class_field(BitWriter(), ClassFieldEnvelope(3, b'\0'*8189, MAX_BITS-25), profile=PROFILE)

    def test_byte_padding_is_not_a_valid_sequence_terminator(self):
        reader = BitReader(bytes.fromhex('1b14'))
        with self.assertRaises(ValueError):
            read_class_fields(reader, profile=PROFILE)
        self.assertEqual(reader.position, 0)

    def test_wrapper_only_builds_false_replayout_and_preserves_exact_body(self):
        content = build_class_field_content((THREE,), profile=PROFILE)
        self.assertEqual(content, ActorContentBlock(False, bytes.fromhex('1b14'), 13))
        self.assertEqual(read_class_field_content(content, profile=PROFILE), (THREE,))
        with self.assertRaises(ValueError):
            read_class_field_content(ActorContentBlock(True, b'\0', 8), profile=PROFILE)
        self.assertEqual(build_class_field_content((), profile=PROFILE), ActorContentBlock(False, b'', 0))

    def test_limits_archives_and_field_tuple_are_strict(self):
        for kwargs in ({'max_fields':True}, {'max_fields':257}, {'max_fields':-1},
                       {'max_payload_bits':-1}, {'max_payload_bits':MAX_BITS+1},
                       {'max_total_bits':0}, {'max_total_bits':MAX_BITS+1}):
            with self.assertRaises(ValueError):
                ClassFieldLimits(**kwargs)
        for operation in (read_class_field, read_class_fields):
            with self.assertRaises(ValueError):
                operation(object(), profile=PROFILE)
        with self.assertRaises(ValueError):
            write_class_field(object(), THREE, profile=PROFILE)
        with self.assertRaises(ValueError):
            write_class_fields(BitWriter(), [THREE], profile=PROFILE)
        with self.assertRaises(ValueError):
            read_class_fields(BitReader(b''), profile=PROFILE, limits=object())


if __name__ == '__main__':
    unittest.main()
