"""Synthetic native-derived Login vectors; no real account/token/Login bytes.

Real packet metadata below is limited to capture provenance, physical layout
and a payload digest. It is not a live Login acceptance or account claim.
The original packet/URL/identity/platform bytes are deliberately not fixtures.
"""
import hashlib
import struct
import unittest

from dfserver.legacy_ds_control_fields import (
    UnsupportedControlProfile, decode_messages, encode_string,
)
from dfserver.legacy_ds_login_fields import decode_login5_at, decode_single_login5


# Scope: saved capture1790789899859563600 ordinals7/9, decoded with the explicit
# observed client8byte route/MaxPacket1024 profile and byte-exactly reencoded.
# Evidence: work/evidence/login-welcome-offline-review/
# official-Login5-structural-dissection.json SHA
# f9fa311be0d6f3487c946a5b83f754cae8ada96f6dc19639e1cf844e8355f84e.
OFFICIAL_LOGIN_METADATA = {
    'capture_sha256': 'd780a0dc51dc75b1b19308ebd06674a21c5abdf26ae92eeb19ff967fe98ebc4a',
    'payload_sha256': 'e3623e0dabdfbef1f4ab6135767bdb3f4ddbb8ab91ea5f47991d8fa93515109a',
    'payload_bits': 1544,
    'field_ends': (7, 183, 184, 193),
    'response': '0',
    'URL_map_component': '/Game/Maps/Login/Login',
    'URL_keys': ('PlayerId', 'ModularWeapon', 'Cookie', 'MapId', 'SpotGroup',
                 'DSRoomId', 'IsOBPlayer', 'Camp'),
    'identity_flags': 3,
    'platform_character_count': 4,
}


def login(identity=b'\x08' + encode_string('synthetic-opaque-id'),
          response='0', url='Iris_Entry?Name=synthetic-user', platform='Local', tail=b''):
    return (b'\x05' + encode_string(response) + encode_string(url) + identity +
            encode_string(platform) + tail)


class LoginPhysicalFieldTests(unittest.TestCase):
    def test_four_field_order_and_exact_consumption(self):
        payload = login()
        result = decode_single_login5(payload, payload_bits=8 * len(payload))
        self.assertEqual((result.response, result.url, result.platform),
                         ('0', 'Iris_Entry?Name=synthetic-user', 'Local'))
        self.assertEqual(result.identity.identifier_text, 'synthetic-opaque-id')
        self.assertEqual(result.identity.wire_type_hash, 1)
        self.assertEqual(result.field_ends[-1], len(payload))
        self.assertEqual(list(result.field_ends), sorted(result.field_ends))

    def test_native_response_field_is_not_an_authentication_decision(self):
        self.assertEqual(decode_single_login5(login(response='different')).response,
                         'different')

    def test_encoded_bytes_are_preserved_without_provider_guess(self):
        result = decode_single_login5(login(identity=b'\x29\x03\xff\x10\x00'))
        self.assertEqual(result.identity.wire_type_hash, 5)
        self.assertEqual(result.identity.encoded_bytes, b'\xff\x10\x00')
        self.assertIsNone(result.identity.identifier_text)

    def test_hash31_reads_type_name_before_identifier(self):
        value = b'\xf8' + encode_string('SyntheticType') + encode_string('opaque')
        result = decode_single_login5(login(identity=value))
        self.assertEqual((result.identity.type_name, result.identity.identifier_text),
                         ('SyntheticType', 'opaque'))

    def test_explicit_empty_does_not_resolve_default_type_or_read_content(self):
        result = decode_single_login5(login(identity=b'\x03'))
        self.assertTrue(result.identity.explicit_empty)
        self.assertEqual(result.platform, 'Local')
        self.assertIsNone(result.identity.resolved_type_hash)

    def test_hash0_is_rejected_without_explicit_verified_registry_result(self):
        with self.assertRaises(UnsupportedControlProfile):
            decode_single_login5(login(identity=b'\x00' + encode_string('opaque')))

    def test_hash0_resolution_is_external_and_stays_opaque(self):
        result = decode_single_login5(login(identity=b'\x00' + encode_string('opaque')),
                                      default_type_hash=9)
        self.assertEqual((result.identity.wire_type_hash,
                          result.identity.resolved_type_hash), (0, 9))
        self.assertIsNone(result.identity.type_name)

    def test_every_shortened_payload_is_rejected_atomically(self):
        payload = login()
        for end in range(len(payload)):
            with self.subTest(end=end), self.assertRaises(ValueError):
                decode_single_login5(payload[:end])

    def test_truncated_encoded_count_is_not_a_delimiter_guess(self):
        payload = b'\x05' + encode_string('0') + encode_string('url') + b'\x09\xff'
        with self.assertRaises(ValueError):
            decode_single_login5(payload)

    def test_intmin_string_length_is_rejected(self):
        with self.assertRaises(ValueError):
            decode_single_login5(b'\x05' + struct.pack('<i', -(1 << 31)))

    def test_single_message_does_not_swallow_following_control_messages(self):
        with self.assertRaises(ValueError):
            decode_single_login5(login(tail=b'\x09'))

    def test_dispatcher_entry_returns_absolute_next_message_boundary(self):
        first = login()
        result, end = decode_login5_at(b'\x09' + first + b'\x09', offset=1)
        self.assertEqual((end, result.field_ends[-1]), (1 + len(first), 1 + len(first)))

    def test_non_byte_aligned_data_is_not_treated_as_string_payload(self):
        payload = login()
        for count in (8 * len(payload) - 1, True):
            with self.assertRaises(UnsupportedControlProfile):
                decode_single_login5(payload, payload_bits=count)

    def test_unknown_id_and_oversized_payload_are_rejected(self):
        with self.assertRaises(UnsupportedControlProfile):
            decode_single_login5(b'\x04' + login()[1:])
        with self.assertRaises(ValueError):
            decode_single_login5(login() + bytes(8192))

    def test_existing_generic_decoder_still_has_no_login_admission(self):
        with self.assertRaises(UnsupportedControlProfile):
            decode_messages(login())

    def test_repr_omits_all_native_text_and_identity_contents(self):
        value = decode_single_login5(login(response='synthetic-response-secret',
            url='Iris_Entry?Cookie=synthetic-ticket-secret',
            platform='synthetic-platform-private'))
        for secret in ('Cookie', 'synthetic-ticket-secret', 'synthetic-response-secret',
                       'synthetic-opaque-id', 'synthetic-platform-private', 'Iris_Entry'):
            self.assertNotIn(secret, repr(value))
            self.assertNotIn(secret, str(value))
        self.assertIn('field_ends=', repr(value))

    def test_anonymous_fields_match_only_real_packet_layout_metadata(self):
        # Preserve safe field names and total serialized widths while replacing
        # every private value. This is not the original Login fixture.
        prefix = '/Game/Maps/Login/Login?PlayerId=1?ModularWeapon=1?Cookie='
        suffix = '?MapId=2201?SpotGroup=1?DSRoomId=1?IsOBPlayer=false?Camp=1'
        url = prefix + 'X' * (171 - len(prefix) - len(suffix)) + suffix
        payload = login(identity=b'\x03', url=url, platform='Test')
        value = decode_single_login5(payload, payload_bits=len(payload) * 8)
        self.assertEqual(len(payload) * 8, OFFICIAL_LOGIN_METADATA['payload_bits'])
        self.assertEqual(value.field_ends, OFFICIAL_LOGIN_METADATA['field_ends'])
        self.assertEqual(value.identity.flags, OFFICIAL_LOGIN_METADATA['identity_flags'])
        self.assertEqual(len(value.platform), OFFICIAL_LOGIN_METADATA['platform_character_count'])
        self.assertNotEqual(hashlib.sha256(payload).hexdigest(),
                            OFFICIAL_LOGIN_METADATA['payload_sha256'])

    def test_invalid_offsets_bounds_and_parameter_types_fail_closed(self):
        for offset in (True, -1, len(login()), '0'):
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                decode_login5_at(login(), offset)
        for bound in (True, 0, 4097, '4096'):
            with self.subTest(bound=bound), self.assertRaises(ValueError):
                decode_single_login5(login(), max_string_units=bound)
        with self.assertRaises(ValueError):
            decode_single_login5(bytearray(login()))
        with self.assertRaises(ValueError):
            decode_single_login5(login(), default_type_hash='QQ')


if __name__ == '__main__':
    unittest.main()
