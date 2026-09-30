"""Synthetic keys only; NIST CBC vectors and observed footer boundary rules."""
import unittest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dfserver.gcp_crypto import (IV, FOOTER, decrypt_body, derive_session_key,
    encrypt_body, encrypted_size, server_key_exchange, decode_received_body)
from dfserver.gcp_framing import Frame, MAX_BODY


class GcpCryptoTests(unittest.TestCase):
    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')

    def raw_encrypt(self, padded):
        encryptor = Cipher(algorithms.AES(self.key), modes.CBC(IV)).encryptor()
        return encryptor.update(padded) + encryptor.finalize()

    def test_nist_sp800_38a_three_block_cbc_known_answer(self):
        # Appendix F.2.1; the transport footer creates a fourth block.
        plaintext = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a'
                                  'ae2d8a571e03ac9c9eb76fac45af8e51'
                                  '30c81c46a35ce411e5fbc1191a0a52ef')
        expected = bytes.fromhex('7649abac8119b246cee98e9b12e9197d'
                                 '5086cb9b507219ee95db113a917678b2'
                                 '73bed6b8e3c1743b7116e69e22229516')
        ciphertext = encrypt_body(plaintext, self.key, random_bytes=lambda n: bytes(n))
        self.assertEqual(ciphertext[:48], expected)
        self.assertEqual(decrypt_body(ciphertext, self.key), plaintext)

    def test_footer_and_padding_for_all_remainders_and_large_body(self):
        for size in list(range(1, 81)) + [65537, MAX_BODY - 16]:
            with self.subTest(size=size):
                plaintext = b'a' * size
                encrypted = encrypt_body(plaintext, self.key, random_bytes=lambda n: b'X' * n)
                decryptor = Cipher(algorithms.AES(self.key), modes.CBC(IV)).decryptor()
                padded = decryptor.update(encrypted) + decryptor.finalize()
                padding = (16 if size % 16 <= 10 else 32) - size % 16
                self.assertEqual(padded, plaintext + b'X' * (padding - 6) + FOOTER + bytes([padding]))
                self.assertEqual(decrypt_body(encrypted, self.key), plaintext)

    def test_minimum_footer_padding_boundary_known_plaintext(self):
        ciphertext = self.raw_encrypt(b'0123456789' + b'tsf4g\x06')
        self.assertEqual(decrypt_body(ciphertext, self.key), b'0123456789')
        self.assertEqual(encrypted_size(10), 16)
        self.assertEqual(encrypted_size(11), 32)

    def test_footer_corruption_and_impossible_padding_are_rejected(self):
        for padded in (b'0123456789' + b'wrong\x06',
                       b'0123456789' + b'tsf4g\x05',
                       b'0123456789' + b'tsf4g\xff',
                       b'0123456789' + b'tsf4g\x00'):
            with self.assertRaises(ValueError):
                decrypt_body(self.raw_encrypt(padded), self.key)

    def test_wrong_key_and_truncated_ciphertext_fail(self):
        ciphertext = encrypt_body(b'own test payload', self.key, random_bytes=lambda n: bytes(n))
        for body, key in ((ciphertext, bytes(16)), (ciphertext[:-1], self.key), (b'', self.key),
                          (ciphertext, bytes(15)), (b'a' * (MAX_BODY + 16), self.key)):
            with self.assertRaises(ValueError):
                decrypt_body(body, key)

    def test_plaintext_and_rng_bounds_are_enforced(self):
        for size in (0, -1, MAX_BODY, MAX_BODY + 1):
            with self.assertRaises(ValueError):
                encrypted_size(size)
        with self.assertRaises(ValueError):
            encrypt_body(b'one', self.key, random_bytes=lambda n: b'')

    def test_direction_rule_decrypts_client_flag_zero(self):
        body = encrypt_body(b'own test payload', self.key)
        frame = Frame(11, 13, 0x4013, 0, 0, bytes(4), body)
        self.assertEqual(decode_received_body(frame, self.key, direction='client_to_server'), b'own test payload')
        self.assertEqual(decode_received_body(frame, self.key, direction='server_to_client'), body)
        frame = Frame(11, 13, 0x4013, 1, 0, bytes(4), body)
        self.assertEqual(decode_received_body(frame, self.key, direction='server_to_client'), b'own test payload')

    def test_dh_shared_value_uses_minimal_big_endian_bytes(self):
        # p=23,g=2,a=6,b=15: A=18,B=16, shared=4; MD5 of one byte 04.
        expected = bytes.fromhex('ec7f7e7bb43742ce868145f71d37b53c')
        self.assertEqual(derive_session_key(23, 16, 6), expected)
        self.assertEqual(derive_session_key(23, 18, 15), expected)

    def test_our_ephemeral_server_exchange_matches_client_computation(self):
        for _ in range(8):
            server_public, server_key = server_key_exchange((23).to_bytes(64, 'big'), b'\x12')
            self.assertEqual(server_key, derive_session_key(23, int.from_bytes(server_public, 'big'), 6))

    def test_dh_wire_size_and_invalid_values_are_rejected(self):
        for prime, public, private in ((4, 2, 2), (23, 1, 2), (23, 22, 2),
                                       (23, 2, 1), (1 << 512, 2, 2)):
            with self.assertRaises(ValueError):
                derive_session_key(prime, public, private)
        for prime, public in ((b'\x17', b'\x12'), ((23).to_bytes(64, 'big'), b''),
                              ((23).to_bytes(64, 'big'), bytes(65))):
            with self.assertRaises(ValueError):
                server_key_exchange(prime, public)
