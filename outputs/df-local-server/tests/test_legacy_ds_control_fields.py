"""Native-derived length/terminator cases and incomplete-protocol rejection."""
import struct
import unittest

from dfserver.legacy_ds_control_fields import (
    ControlMessage, UnsupportedControlProfile, decode_messages, decode_string,
    encode_message, encode_string,
)


class NativeControlFieldTests(unittest.TestCase):
    def test_ascii_and_wide_literal_vectors(self):
        self.assertEqual(encode_string('A'), b'\x02\x00\x00\x00A\x00')
        wide = b'\xfd\xff\xff\xff\x27\x59\x5d\x57\x00\x00'
        self.assertEqual(encode_string('大坝'), wide)
        self.assertEqual(decode_string(wide), ('大坝', 10))

    def test_empty_and_forced_unicode_have_distinct_encodings(self):
        self.assertEqual(encode_string(''), b'\x00' * 4)
        self.assertEqual(encode_string('', force_unicode=True), b'\xff' * 4 + b'\x00\x00')
        self.assertEqual(decode_string(b'\x01\x00\x00\x00X'), ('', 5))
        self.assertEqual(decode_string(b'\xff' * 4 + b'XY'), ('', 6))

    def test_native_overwrites_missing_terminators(self):
        self.assertEqual(decode_string(b'\x03\x00\x00\x00AB!'), ('AB', 7))
        wire = struct.pack('<i', -3) + b'A\x00B\x00!\x00'
        self.assertEqual(decode_string(wire), ('AB', 10))

    def test_interior_nul_survives_ordinary_copy(self):
        self.assertEqual(decode_string(struct.pack('<i', 4) + b'A\x00B!'), ('A\x00B', 8))
        wire = struct.pack('<i', -4) + b'A\x00\x00\x00B\x00!\x00'
        self.assertEqual(decode_string(wire), ('A\x00B', 12))

    def test_wide_ffff_normalizes_and_shrinks_at_first_nul(self):
        wire = struct.pack('<i', -5) + struct.pack('<5H', 65, 0xffff, 66, 67, 33)
        self.assertEqual(decode_string(wire), ('A', 14))
        wire = struct.pack('<i', -5) + struct.pack('<5H', 65, 0, 66, 0xffff, 33)
        self.assertEqual(decode_string(wire), ('A', 14))

    def test_non_bmp_uses_utf16_units_not_python_character_count(self):
        wire = b'\xfd\xff\xff\xff\x3d\xd8\x00\xde\x00\x00'
        self.assertEqual(encode_string('\U0001f600'), wire)
        self.assertEqual(decode_string(wire), ('\U0001f600', 10))
        with self.assertRaises(ValueError):
            encode_string('\U0001f600', max_units=2)

    def test_raw_surrogates_preserve_native_copy(self):
        wire = b'\xfe\xff\xff\xff\x00\xd8\x00\x00'
        self.assertEqual(decode_string(wire), ('\ud800', 8))
        self.assertEqual(encode_string('\ud800'), wire)

    def test_length_failures_are_bounded_without_partial_output(self):
        for wire in (b'', b'123', b'\x00\x00\x00\x80',
                     struct.pack('<i', 3) + b'AB', struct.pack('<i', -3) + b'ABCD'):
            with self.subTest(wire=wire), self.assertRaises(ValueError):
                decode_string(wire)
        with self.assertRaises(ValueError):
            decode_string(struct.pack('<i', 4097))
        with self.assertRaises(ValueError):
            decode_string(b'\x00' * 4, offset=-1)
        with self.assertRaises(ValueError):
            encode_string('A\x00B')  # Canonical local encoder policy.

    def test_native_narrow_conversion_replaces_all_high_bytes(self):
        wire = struct.pack('<i', 5) + b'\x00\x7f\x80\xff!'
        self.assertEqual(decode_string(wire), ('\x00\x7f??', 9))
        # A high final byte is overwritten by the native loader, never converted.
        self.assertEqual(decode_string(struct.pack('<i', 2) + b'A\xff'), ('A', 6))

    def test_narrow_conversion_is_counted_and_does_not_decode_utf8(self):
        wire = struct.pack('<i', 6) + b'A\x00\xc3\xa9B!'
        self.assertEqual(decode_string(wire), ('A\x00??B', 10))
        self.assertEqual(decode_messages(b'\x03' + wire + b'\x09'),
                         (ControlMessage(3, ('A\x00??B',)), ControlMessage(9, ())))

    def test_confirmed_message_zero_field_order(self):
        wire = b'\x00\x01\x78\x56\x34\x12\x00\x00\x00\x00'
        self.assertEqual(encode_message(0, 1, 0x12345678, ''), wire)
        self.assertEqual(decode_messages(wire), (ControlMessage(0, (1, 0x12345678, '')),))
        with self.assertRaises(UnsupportedControlProfile):
            decode_messages(b'\x00\x00' + wire[2:])

    def test_three_strings_and_following_message_stay_separate(self):
        wire = (b'\x01\x02\x00\x00\x00A\x00\x00\x00\x00\x00'
                b'\xfd\xff\xff\xff\x27\x59\x5d\x57\x00\x00\x09')
        self.assertEqual(encode_message(1, 'A', '', '大坝') + encode_message(9), wire)
        self.assertEqual(decode_messages(wire),
                         (ControlMessage(1, ('A', '', '大坝')), ControlMessage(9, ())))

    def test_unknown_identity_truncation_and_bit_shape_are_not_accepted(self):
        for wire in (b'\x05', b'\x09\x05', b'\x02\x01', b'\x03\x00\x00\x00'):
            with self.subTest(wire=wire), self.assertRaises(ValueError):
                decode_messages(wire)
        with self.assertRaises(UnsupportedControlProfile):
            decode_messages(b'\x09', payload_bits=7)
        with self.assertRaises(ValueError):
            decode_messages(b'\x09\x09', max_messages=1)
        with self.assertRaises(ValueError):
            encode_message(2, True)
        with self.assertRaises(ValueError):
            encode_message(1, 'A', '')


if __name__ == '__main__':
    unittest.main()
