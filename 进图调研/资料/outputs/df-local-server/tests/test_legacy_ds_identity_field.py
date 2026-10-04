"""Native-derived physical identity vectors; no registry or object factory."""
import struct
import unittest

from dfserver.legacy_ds_control_fields import UnsupportedControlProfile, encode_string
from dfserver.legacy_ds_identity_field import IdentityWireField, decode_identity_field


class IdentityPhysicalFieldTests(unittest.TestCase):
    def test_explicit_encoded_empty_consumes_only_one_byte(self):
        for flags in (3, 7, 0xfb, 0xff):
            field, end = decode_identity_field(bytes((flags,)) + b'next')
            self.assertEqual(end, 1)
            self.assertTrue(field.explicit_empty)
            self.assertIsNone(field.resolved_type_hash)
            self.assertIsNone(field.encoded_bytes)

    def test_encoded_bytes_keep_their_exact_value_and_next_field_boundary(self):
        field, end = decode_identity_field(b'\x09\x03\x00\x80\xffnext')
        self.assertEqual(field, IdentityWireField(9, 1, 1, None, b'\x00\x80\xff', None, False))
        self.assertEqual(end, 5)

    def test_zero_count_differs_from_explicit_empty_header(self):
        field, end = decode_identity_field(b'\x09\x00')
        self.assertEqual(end, 2)
        self.assertEqual(field.encoded_bytes, b'')
        self.assertFalse(field.explicit_empty)

    def test_hash31_name_precedes_encoded_byte_count(self):
        wire = b'\xf9' + encode_string('LOCAL') + b'\x02\xab\xcd!'
        field, end = decode_identity_field(wire)
        self.assertEqual((field.type_name, field.encoded_bytes, field.identifier_text),
                         ('LOCAL', b'\xab\xcd', None))
        self.assertEqual(end, len(wire) - 1)

    def test_unencoded_bit1_is_not_an_empty_flag_and_bit2_is_preserved(self):
        for flags in (8, 10, 12, 14):
            field, end = decode_identity_field(bytes((flags,)) + encode_string('local-id'))
            self.assertEqual(field.identifier_text, 'local-id')
            self.assertFalse(field.explicit_empty)
            self.assertEqual(field.flags, flags)
            self.assertEqual(end, 14)

    def test_default_hash_requires_explicit_registry_result(self):
        with self.assertRaises(UnsupportedControlProfile):
            decode_identity_field(b'\x01\x01A')
        field, end = decode_identity_field(b'\x01\x01A', default_type_hash=1)
        self.assertEqual((field.wire_type_hash, field.resolved_type_hash, end), (0, 1, 3))
        field, end = decode_identity_field(b'\x01\x01A', default_type_hash=200)
        self.assertEqual((field.wire_type_hash, field.resolved_type_hash, end), (0, 200, 3))
        wire = b'\x00' + encode_string('LOCAL') + encode_string('id')
        field, end = decode_identity_field(wire, default_type_hash=31)
        self.assertEqual((field.type_name, field.identifier_text, end), ('LOCAL', 'id', len(wire)))

    def test_unsigned_byte_count_and_nonzero_offset(self):
        wire = b'prefix\x09\xff' + bytes(range(255)) + b'next'
        field, end = decode_identity_field(wire, 6)
        self.assertEqual(field.encoded_bytes, bytes(range(255)))
        self.assertEqual(end, 263)

    def test_truncation_and_unresolved_parameters_never_return_partial_identity(self):
        for wire in (b'', b'\x09', b'\x09\x02A', b'\xf9\x01', b'\x08\x00\x00\x00'):
            with self.subTest(wire=wire), self.assertRaises(ValueError):
                decode_identity_field(wire)
        for default in (True, 0, 256, -1, 'QQ'):
            with self.subTest(default=default), self.assertRaises(ValueError):
                decode_identity_field(b'\x09\x00', default_type_hash=default)
        with self.assertRaises(ValueError):
            decode_identity_field(b'\x09\x00', offset=True)

    def test_wide_strings_use_the_audited_native_string_loader(self):
        wire = b'\xf8' + encode_string('本地') + struct.pack('<i', 3) + b'\x80A!'
        field, end = decode_identity_field(wire)
        self.assertEqual((field.type_name, field.identifier_text, end), ('本地', '?A', len(wire)))


if __name__ == '__main__':
    unittest.main()
