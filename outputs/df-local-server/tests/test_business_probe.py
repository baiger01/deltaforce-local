import unittest

from dfserver.business_probe import summarize_message_shape, summarize_prefixed_envelope
from dfserver.business_envelope import BusinessEnvelope


class BusinessProbeTests(unittest.TestCase):
    def test_reports_shape_without_values(self):
        secret = b'private-token'
        shape = summarize_message_shape(b'\x0a' + bytes([len(secret)]) + secret + b'\x10\xac\x02')
        self.assertEqual(shape['protobuf_wire_candidates'][0], {
            'offset': 0, 'fields': [
                {'number': 1, 'wire': 2, 'length': len(secret)},
                {'number': 2, 'wire': 0, 'varint_bytes': 2},
            ]})
        self.assertNotIn(secret.decode(), str(shape))

    def test_rejects_unbounded_or_invalid_data(self):
        with self.assertRaises(ValueError):
            summarize_message_shape(b'')
        self.assertEqual(summarize_message_shape(b'\x0a\x05x')['protobuf_wire_candidates'], [])

    def test_prefixed_envelope_retains_only_nonsecret_request_identity(self):
        secret = b'private-token'
        package = BusinessEnvelope(b'\x0a' + bytes([len(secret)]) + secret,
                                   {'name': 'CSStateGetInfoReq', 'service': 'account',
                                    'language': 'private-language'}).encode()
        result = summarize_prefixed_envelope(len(package).to_bytes(4, 'little') + package)
        self.assertTrue(result['candidate_envelope_decoded'])
        self.assertTrue(result['prefix_equals_payload_length_le'])
        self.assertEqual(result['prefix_word_le'], len(package))
        self.assertEqual((result['message_name'], result['service']), ('CSStateGetInfoReq', 'account'))
        self.assertEqual(result['body_shape']['message_length'], len(secret) + 2)
        self.assertNotIn(secret.decode(), str(result))
        self.assertNotIn('private-language', str(result))


if __name__ == '__main__':
    unittest.main()
