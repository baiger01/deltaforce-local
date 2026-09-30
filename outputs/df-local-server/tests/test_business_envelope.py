import unittest

from dfserver.business_envelope import BusinessEnvelope, MAX_ENVELOPE_BYTES, parse_business_envelope


class BusinessEnvelopeTests(unittest.TestCase):
    def test_manual_wire_vector_preserves_binary_body_and_request_sequence(self):
        # Header: sequence 42, name "Q", service "deposit". Body is arbitrary
        # binary, including invalid UTF-8: it must use buffer semantics.
        expected = bytes.fromhex('0a0e182a3a015142076465706f736974120300ff80')
        value = BusinessEnvelope(b'\x00\xff\x80', {'client_sequence_id': 42, 'name': 'Q', 'service': 'deposit'})
        self.assertEqual(value.encode(), expected)
        self.assertEqual(parse_business_envelope(expected), value)

    def test_signed_and_unsigned_boundaries_and_explicit_zero_presence(self):
        value = BusinessEnvelope(b'', {'plat_id': -(1 << 31), 'client_sequence_id': (1 << 31) - 1,
                                      'mod_route_id': (1 << 64) - 1, 'dst_zone_id': (1 << 32) - 1,
                                      'result': 0, 'language': 'zh'})
        self.assertEqual(parse_business_envelope(value.encode()), value)
        zero = BusinessEnvelope(b'', {'client_sequence_id': 0})
        self.assertEqual(zero.encode(), bytes.fromhex('0a0218001200'))

    def test_unknown_outer_or_header_fields_are_rejected(self):
        for wire in (bytes.fromhex('1801'), bytes.fromhex('0a020801')):
            with self.subTest(wire=wire), self.assertRaises(ValueError):
                parse_business_envelope(wire)

    def test_malformed_lengths_and_header_text_are_rejected(self):
        for wire in (b'\x0a', b'\x12\x04x', bytes.fromhex('0a033a01ff'), b'\x00'):
            with self.subTest(wire=wire), self.assertRaises(ValueError):
                parse_business_envelope(wire)

    def test_invalid_values_size_limits_and_repr_do_not_expose_payload(self):
        for header in ({'unknown': 1}, {'name': b'bytes'}, {'result': True}, {'mod_route_id': -1},
                       {'dst_zone_id': 1 << 32}, {'plat_id': 1 << 31}):
            with self.subTest(header=header), self.assertRaises(ValueError):
                BusinessEnvelope(b'', header).encode()
        for value in (bytearray(), b'x' * (MAX_ENVELOPE_BYTES + 1)):
            with self.assertRaises(ValueError):
                parse_business_envelope(value)
        with self.assertRaises(ValueError):
            BusinessEnvelope(b'x' * MAX_ENVELOPE_BYTES, {}).encode()
        self.assertNotIn('private body', repr(BusinessEnvelope(b'private body', {'name': 'private header'})))
        self.assertNotIn('private header', repr(BusinessEnvelope(b'private body', {'name': 'private header'})))


if __name__ == '__main__':
    unittest.main()
