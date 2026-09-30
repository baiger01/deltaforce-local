"""Manual wire vectors and receive ordering; official sessions are not decrypted."""
import unittest
import zlib

from dfserver.gcp_crypto import encrypt_body
from dfserver.gcp_data import (DataHeader, compress_body, decompress_body, decode_data_frame,
                               encode_data_frame, parse_data_header, split_messages)
from dfserver.gcp_framing import Frame


def frame(extra, body=b'body', *, version=11, command=0x4013, encryption=0):
    return Frame(version, 13, command, encryption, 0, extra, body)


class GcpDataTests(unittest.TestCase):
    def test_manual_header_and_three_message_split(self):
        header = parse_data_header(frame(bytes.fromhex('0040000200030005')))
        self.assertEqual(header, DataHeader(0, 64, (3, 5)))
        self.assertEqual(split_messages(header, b'oneTWO!!tail'), (b'one', b'TWO!!', b'tail'))
        self.assertEqual(header.encode(), bytes.fromhex('0040000200030005'))

    def test_one_leading_length_means_two_messages(self):
        header = parse_data_header(frame(bytes.fromhex('000000010004')))
        self.assertEqual(split_messages(header, b'headremainder'), (b'head', b'remainder'))

    def test_zero_merge_count_keeps_whole_body(self):
        header = parse_data_header(frame(bytes.fromhex('01000000')))
        self.assertEqual(split_messages(header, b'whole'), (b'whole',))

    def test_maximum_merge_count_and_rejected_255(self):
        raw = b'\x00\x00\x00\xfe' + b'\x00\x01' * 254
        header = parse_data_header(frame(raw))
        self.assertEqual(split_messages(header, b'x' * 255), (b'x',) * 255)
        with self.assertRaises(ValueError):
            parse_data_header(frame(b'\x00\x00\x00\xff' + b'\x00\x01' * 255))

    def test_unsupported_header_layouts_and_inexact_length(self):
        for raw in (b'', b'\x00\x00\x00', b'\x00\x00\x00\x01\x00',
                    b'\x00\x00\x00\x00\x00', b'\x00\x00\x02\x00'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_data_header(frame(raw))
        for version, command in ((10, 0x4013), (11, 0x4023)):
            with self.subTest(version=version, command=command), self.assertRaises(ValueError):
                parse_data_header(frame(b'\x00' * 4, version=version, command=command))

    def test_merge_lengths_reject_empty_and_overrun(self):
        for header, body in ((DataHeader(0, 0, (0,)), b'a'), (DataHeader(0, 0, (2,)), b'a'),
                             (DataHeader(0, 0, (1,)), b'a')):
            with self.subTest(header=header, size=len(body)), self.assertRaises(ValueError):
                split_messages(header, body, max_output=100000)
        self.assertEqual(len(split_messages(DataHeader(0, 0, (1,)),
                                            b'a' * 65537, max_output=100000)[-1]), 65536)

    def test_manual_lz4_literal_and_overlapping_match_vectors(self):
        self.assertEqual(decompress_body(b'\x50hello', 1, max_output=5), b'hello')
        # Four literals, an eight-byte overlapping match at offset four,
        # then the final five literal bytes. No stored-size prefix is present.
        self.assertEqual(decompress_body(b'\x44abcd\x04\x00\x50efghi', 1), b'abcdabcdabcdefghi')

    def test_manual_zlib_vector(self):
        self.assertEqual(decompress_body(bytes.fromhex('789ccb48cdc9c90700062c0215'), 2), b'hello')

    def test_corrupt_compressed_data_and_limit(self):
        for method, raw, limit in ((1, b'\x50hello', 4), (1, b'\x10a\x00\x00', 100),
                                   (1, b'\x50hell', 100), (1, b'\x00', 100),
                                   (2, zlib.compress(b'a' * 1001), 1000),
                                   (2, zlib.compress(b'a')[:-1], 100),
                                   (2, zlib.compress(b'a') + b'trailing', 100),
                                   (2, zlib.compress(b''), 100)):
            with self.subTest(method=method, raw=raw, limit=limit), self.assertRaises(ValueError):
                decompress_body(raw, method, max_output=limit)

    def test_unknown_compression_and_invalid_limits(self):
        for method in (0, 3, 255):
            with self.subTest(method=method), self.assertRaises(ValueError):
                decompress_body(b'\x50hello', method)
        for limit in (0, -1, 1048577, 'large'):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                decompress_body(b'\x50hello', 1, max_output=limit)

    def test_c2s_decrypts_flag_zero_then_decompresses_then_splits(self):
        key = bytes(range(16))
        # A literal-only LZ4 block containing two messages of lengths 3 and 2.
        encrypted = encrypt_body(b'\x50abcde', key, random_bytes=lambda n: b'\x00' * n)
        received = frame(bytes.fromhex('010000010003'), encrypted, encryption=0)
        decoded = decode_data_frame(received, key, direction='client_to_server', compression_method=1)
        self.assertEqual(decoded.messages, (b'abc', b'de'))

    def test_s2c_clear_compressed_and_encrypted_uncompressed(self):
        received = frame(bytes.fromhex('01400000'), b'\x50hello')
        decoded = decode_data_frame(received, None, direction='server_to_client', compression_method=1)
        self.assertEqual((decoded.header.opaque_flag, decoded.messages), (64, (b'hello',)))
        key = bytes(range(16))
        received = frame(bytes.fromhex('00000000'), encrypt_body(b'hello', key), encryption=1)
        self.assertEqual(decode_data_frame(received, key, direction='server_to_client',
                                          compression_method=0).messages, (b'hello',))

    def test_lz4_encoder_omits_size_prefix(self):
        self.assertEqual(compress_body(b'hello', 1), b'\x50hello')

    def test_encrypted_compressed_merged_roundtrip_both_methods(self):
        key = bytes(range(16))
        expected = (b'first' * 100, b'second' * 200, b'third')
        for method in (1, 2):
            for direction in ('client_to_server', 'server_to_client'):
                with self.subTest(method=method, direction=direction):
                    encoded = encode_data_frame(expected, key, direction=direction, compression_method=method,
                                                compressed=True, opaque_flag=64)
                    decoded = decode_data_frame(encoded, key, direction=direction, compression_method=method)
                    self.assertEqual(decoded.messages, expected)
                    self.assertEqual(encoded.payload_encryption_flag, int(direction == 'server_to_client'))

    def test_encode_rejects_empty_excessive_and_oversized_messages(self):
        for messages in ((), (b'',), (b'a',) * 256, (b'a' * 65537,), (b'a' * 65536, b'b')):
            with self.subTest(sizes=tuple(map(len, messages))), self.assertRaises(ValueError):
                encode_data_frame(messages, bytes(16), direction='client_to_server')

    def test_receive_plaintext_limit_and_wrong_key(self):
        received = frame(bytes.fromhex('00000000'), b'a' * 101)
        with self.assertRaises(ValueError):
            decode_data_frame(received, None, direction='server_to_client', compression_method=0, max_output=100)
        received = frame(bytes.fromhex('01000000'), encrypt_body(b'\x50hello', bytes(16)), encryption=1)
        with self.assertRaises(ValueError):
            decode_data_frame(received, b'\x01' * 16, direction='server_to_client', compression_method=1)


if __name__ == '__main__':
    unittest.main()
