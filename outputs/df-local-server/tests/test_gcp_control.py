import unittest

from dfserver.gcp_control import (AuthRequest, AuthResponse, CommonAuthResponse,
                                  ReadyResponse, parse_auth_request, parse_auth_response,
                                  parse_auth_response_prefix, parse_ready_response)


class GcpControlTests(unittest.TestCase):
    def response(self, variant_type=0, variant_value=None):
        return AuthResponse(CommonAuthResponse(0, variant_type, variant_value, 0),
                            0, b'', 0, b'', 0, 0, b'')

    def test_auth_request_independent_wire_vector(self):
        wire = bytes.fromhex('1234 0002 aabb 0003 ccddee 0001 ff')
        expected = AuthRequest(0x1234, bytes.fromhex('aabb'), bytes.fromhex('ccddee'), b'\xff')
        self.assertEqual(parse_auth_request(wire), expected)
        self.assertEqual(expected.encode(), wire)
        self.assertEqual(parse_auth_request(bytes(8)), AuthRequest(0, b'', b'', b''))

    def test_response_independent_wire_vector_and_prefix_consumption(self):
        wire = bytes.fromhex('aa55 01 aabbccdd 1122334455667788 '
                             '0102 0002 dead 03040506 0001 be 0708090a 0b0c 0002 efed')
        expected = AuthResponse(CommonAuthResponse(0xaa55, 1, 0xaabbccdd, 0x1122334455667788),
                                0x0102, b'\xde\xad', 0x03040506, b'\xbe',
                                0x0708090a, 0x0b0c, b'\xef\xed')
        self.assertEqual(parse_auth_response(wire), expected)
        self.assertEqual(expected.encode(), wire)
        self.assertEqual(parse_auth_response_prefix(wire + b'context'), (expected, len(wire)))
        self.assertEqual(self.response().encode(), bytes(29))

    def test_known_response_variant_widths_and_string_length_includes_nul(self):
        for kind, value, prefix in ((0, None, '000000'),
                                    (1, 0x01020304, '00000101020304'),
                                    (2, 0x0102030405060708, '0000020102030405060708'),
                                    (3, b'ab\x00', '00000300000003616200')):
            wire = self.response(kind, value).encode()
            self.assertTrue(wire.startswith(bytes.fromhex(prefix)))
            self.assertEqual(parse_auth_response(wire), self.response(kind, value))

    def test_all_truncated_prefixes_of_populated_bodies_fail(self):
        vectors = [(AuthRequest(1, b'credential', b'auth data', b'context').encode(), parse_auth_request),
                   (self.response(3, b'message\x00').encode(), parse_auth_response)]
        for wire, parse in vectors:
            for end in range(len(wire)):
                with self.subTest(end=end, parser=parse.__name__), self.assertRaises(ValueError):
                    parse(wire[:end])

    def test_request_blob_limits_and_declared_oversize_before_payload(self):
        request = AuthRequest(65535, bytes(64), bytes(4096), bytes(256))
        self.assertEqual(parse_auth_request(request.encode()), request)
        for parts in ((bytes(65), b'', b''), (b'', bytes(4097), b''), (b'', b'', bytes(257))):
            with self.assertRaises(ValueError):
                AuthRequest(0, *parts).encode()
        for wire in (b'\x00\x00\x00\x41', bytes(4) + b'\x10\x01', bytes(6) + b'\x01\x01'):
            with self.assertRaises(ValueError):
                parse_auth_request(wire)

    def test_response_blob_limits_and_maximum_c_string(self):
        response = AuthResponse(CommonAuthResponse(0, 3, b'a' * 255 + b'\x00', 0),
                                0, bytes(4096), 0, bytes(1024), 0, 0, bytes(1024))
        self.assertEqual(parse_auth_response(response.encode()), response)
        for first, second, last in ((bytes(4097), b'', b''), (b'', bytes(1025), b''),
                                   (b'', b'', bytes(1025))):
            with self.assertRaises(ValueError):
                AuthResponse(self.response().common, 0, first, 0, second, 0, 0, last).encode()

    def test_malformed_response_string_and_unknown_variant_are_rejected(self):
        for value in (b'', b'nonterminated', b'a\x00b\x00', b'a' * 256 + b'\x00'):
            with self.assertRaises(ValueError):
                self.response(3, value).encode()
        for wire in (bytes.fromhex('00000300000000'), bytes.fromhex('00000300000101'),
                     bytes.fromhex('000003000000026162'), bytes.fromhex('000003000000026100')[:-1]):
            with self.assertRaises(ValueError):
                parse_auth_response(wire)
        with self.assertRaises(NotImplementedError):
            parse_auth_response(b'\x00\x00\x04')
        with self.assertRaises(NotImplementedError):
            self.response(4, None).encode()

    def test_invalid_scalar_widths_opaque_types_and_empty_variant(self):
        for number in (-1, 65536, True, None):
            with self.assertRaises(ValueError):
                AuthRequest(number, b'', b'', b'').encode()
        with self.assertRaises(ValueError):
            AuthRequest(0, 'credential', b'', b'').encode()
        with self.assertRaises(ValueError):
            self.response(0, 1).encode()
        with self.assertRaises(ValueError):
            self.response(1, 1 << 32).encode()
        with self.assertRaises(ValueError):
            self.response(2, 1 << 64).encode()

    def test_outer_version_and_trailing_data_fail_closed(self):
        for parser, wire in ((parse_auth_request, bytes(8)), (parse_auth_response, bytes(29))):
            with self.assertRaises(ValueError):
                parser(wire + b'\x00')
            for version in (0, 4, 10, 13):
                with self.assertRaises(ValueError):
                    parser(wire, version=version)

    def test_ready_response_native_v12_field_order(self):
        value = ReadyResponse(0x01020304, bytes(range(16)), 0x1122334455667788,
                              1, 500, (1, 2, 3, 4))
        wire = bytes.fromhex('01020304 000102030405060708090a0b0c0d0e0f '
                             '1122334455667788 01 000001f4 '
                             '00000001 00000002 00000003 00000004')
        self.assertEqual(value.encode(), wire)
        self.assertEqual(parse_ready_response(wire), value)
        self.assertEqual(parse_ready_response(wire[:33], version=11),
                         ReadyResponse(0x01020304, bytes(range(16)),
                                       0x1122334455667788, 1, 500))
        with self.assertRaises(ValueError):
            parse_ready_response(wire + b'\x00')
        with self.assertRaises(ValueError):
            ReadyResponse(1, bytes(15), 1).encode()

    def test_repr_omits_credentials_identity_and_opaque_response_payloads(self):
        request = AuthRequest(1, b'private credential', b'private data', b'private context')
        self.assertEqual(repr(request), 'AuthRequest(auth_type=1)')
        common = CommonAuthResponse(0, 3, b'private\x00', 123456789)
        self.assertEqual(repr(common), 'CommonAuthResponse(opaque_word16=0, variant_type=3)')
        self.assertNotIn('private', repr(AuthResponse(common, 0, b'private', 0, b'private', 0, 0, b'private')))


if __name__ == '__main__':
    unittest.main()
