import hashlib
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from dfserver.gcp_crypto import IV, decrypt_body
from dfserver.gcp_framing import Frame, StreamDecoder
from dfserver.gcp_handshake import DhAckBody, create_server_ack, parse_ack_body, parse_ack_header
from dfserver.gcp_control import AuthResponse, CommonAuthResponse


class GcpAckBodyTests(unittest.TestCase):
    # Deliberately tiny, public test-only parameters. These are not client settings.
    prime = (23).to_bytes(64, 'big')
    hello = Frame(11, 13, 0x1001, 0, 0,
                  b'\x03\x00\x01\x12' + bytes(64) + b'\x03unresolved tail', b'')

    def acknowledgement(self, body=DhAckBody(b''), prime=None):
        return create_server_ack(self.hello, self.prime if prime is None else prime,
                                 body=body, header_word4=13, header_word9=0,
                                 compression_method=1, compression_threshold=500,
                                 compression_maximum=0)

    def test_native_layout_vector_and_zero_length_context(self):
        wire = bytes.fromhex('00 0004 aabbccdd')
        self.assertEqual(parse_ack_body(wire), DhAckBody(bytes.fromhex('aabbccdd')))
        self.assertEqual(DhAckBody(bytes.fromhex('aabbccdd')).encode(), wire)
        self.assertEqual(parse_ack_body(b'\x00\x00\x00'), DhAckBody(b''))
        self.assertEqual(DhAckBody(b'').encode(), b'\x00\x00\x00')

    def test_context_boundaries_and_all_truncated_prefixes(self):
        for size in (1, 7, 64):
            wire = b'\x00' + size.to_bytes(2, 'big') + bytes(range(size))
            self.assertEqual(parse_ack_body(wire).opaque_context, bytes(range(size)))
            for end in range(len(wire)):
                with self.subTest(size=size, end=end), self.assertRaises(ValueError):
                    parse_ack_body(wire[:end])

    def test_invalid_lengths_discriminators_and_trailing_data(self):
        for wire in (b'\x02\x00\x00', b'\xff\x00\x00', b'\x00\x00\x41' + bytes(65),
                     b'\x00\x00\x00\xff', b'\x00\xff\xff'):
            with self.assertRaises(ValueError):
                parse_ack_body(wire)
        for context in (bytes(65), 'unknown', None):
            with self.assertRaises(ValueError):
                DhAckBody(context).encode()

    def test_truncated_start_response_and_versions_fail_explicitly(self):
        with self.assertRaises(ValueError):
            parse_ack_body(b'\x01\x00\x00')
        for version in (0, 1, 10, 12):
            with self.assertRaises(ValueError):
                parse_ack_body(b'\x00\x00\x00', version=version)

    def test_embedded_start_response_preserves_context_and_consumes_exact_body(self):
        response = AuthResponse(CommonAuthResponse(0, 3, b'example\x00', 17),
                                1, b'one', 2, b'two', 3, 4, b'three')
        body = DhAckBody(b'context', response)
        wire = b'\x01' + response.encode() + b'\x00\x07context'
        self.assertEqual(body.encode(), wire)
        self.assertEqual(parse_ack_body(wire), body)
        for wire in (wire[:-1], wire + b'extra'):
            with self.assertRaises(ValueError):
                parse_ack_body(wire)
        with self.assertRaises(ValueError):
            DhAckBody(b'', b'unknown response').encode()

    def test_minimum_embedded_ack_cannot_fit_in_observed_ciphertext_size(self):
        # This is a length inference, not decryption of the original capture.
        response = AuthResponse(CommonAuthResponse(0, 0, None, 0), 0, b'', 0, b'', 0, 0, b'')
        self.assertEqual(len(DhAckBody(b'', response).encode()), 32)

    def test_combined_ack_matches_independent_dh_and_aes_calculation(self):
        context = bytes(range(1, 8))
        # server exponent 15 -> public 16; 18**15 mod 23 -> shared byte 04.
        with patch('dfserver.gcp_crypto.secrets.randbelow', return_value=13):
            ack = self.acknowledgement(DhAckBody(context))
        self.assertEqual(ack.session_key.hex(), 'ec7f7e7bb43742ce868145f71d37b53c')
        self.assertEqual(ack.frame.extra_header.hex(), '0300011001000001f400000000')
        encryptor = Cipher(algorithms.AES(hashlib.md5(b'\x04').digest()), modes.CBC(IV)).encryptor()
        # A ten-byte plaintext has no random filler, so this ciphertext is exact.
        plaintext_block = bytes.fromhex('00000701020304050607') + b'tsf4g\x06'
        expected = encryptor.update(plaintext_block) + encryptor.finalize()
        self.assertEqual(ack.frame.body, expected)
        self.assertEqual(ack.frame.command, 0x1002)
        self.assertEqual(ack.frame.payload_encryption_flag, 1)

    def test_fragmented_encrypted_ack_can_be_read_by_separate_client(self):
        ack = self.acknowledgement(DhAckBody(b'opaque'))
        decoder, frames = StreamDecoder(), []
        for byte in ack.frame.encode():
            frames.extend(decoder.feed(bytes([byte])))
        decoder.finish()
        self.assertEqual(len(frames), 1)
        server_public = int.from_bytes(parse_ack_header(frames[0]).server_public_key, 'big')
        shared = pow(server_public, 6, 23)
        client_key = hashlib.md5(shared.to_bytes((shared.bit_length() + 7) // 8, 'big')).digest()
        self.assertEqual(parse_ack_body(decrypt_body(frames[0].body, client_key)), DhAckBody(b'opaque'))

    def test_builder_requires_separate_modulus_and_supported_body(self):
        for prime in (None, b'', bytes(64)):
            with self.assertRaises(ValueError):
                create_server_ack(self.hello, prime, body=DhAckBody(b''),
                                  header_word4=13, header_word9=0,
                                  compression_method=1, compression_threshold=500,
                                  compression_maximum=0)
        with self.assertRaises(ValueError):
            self.acknowledgement(body=b'unknown')

    def test_repr_does_not_expose_context_ciphertext_or_session_key(self):
        self.assertEqual(repr(DhAckBody(b'private context')), 'DhAckBody()')
        self.assertEqual(repr(self.acknowledgement()), 'ServerDhAcknowledgement()')


if __name__ == '__main__':
    unittest.main()
