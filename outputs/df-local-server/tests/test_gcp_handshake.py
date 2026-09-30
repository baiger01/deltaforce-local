import unittest
from dfserver.gcp_framing import Frame
from dfserver.gcp_handshake import DhAckHeader, parse_ack_header, parse_hello


class GcpHandshakeTests(unittest.TestCase):
    hello = b'\x03\x00\x01\x12' + bytes(64) + b'\x03opaque tail'

    def frame(self, command, extension, *, version=11, body=b''):
        return Frame(version, 13, command, 0, 0, extension, body)

    def test_hello_prefix_layout_preserves_undecoded_remainder(self):
        hello = parse_hello(self.frame(0x1001, self.hello))
        self.assertEqual(hello.client_public_key, b'\x12')
        self.assertEqual(hello.opaque_dh_context, bytes(64))
        self.assertEqual(hello.encryption_method, 3)
        self.assertEqual(hello.opaque_remaining_header, b'opaque tail')

    def test_ack_known_header_layout(self):
        wire = bytes.fromhex('03 0001 10 01 000001f4 00000000')
        header = parse_ack_header(self.frame(0x1002, wire))
        self.assertEqual(header, DhAckHeader(b'\x10', 1, 500, 0))
        self.assertEqual(header.encode(), wire)

    def test_truncated_and_oversized_hello_prefixes_fail(self):
        for wire in (self.hello[:2], b'\x03\x00\x00', b'\x03\x00\x41' + bytes(200), self.hello[:68]):
            with self.assertRaises(ValueError):
                parse_hello(self.frame(0x1001, wire))

    def test_unknown_modes_versions_and_nonempty_hello_are_rejected(self):
        for frame in (self.frame(0x1002, self.hello), self.frame(0x1001, self.hello, version=10),
                      self.frame(0x1001, self.hello, body=b'unknown'),
                      self.frame(0x1001, b'\x04' + self.hello[1:]),
                      self.frame(0x1001, self.hello[:68] + b'\x04')):
            with self.assertRaises(ValueError):
                parse_hello(frame)

    def test_ack_must_consume_exact_extension(self):
        valid = bytes.fromhex('03 0001 10 01 000001f4 00000000')
        for wire in (valid[:-1], valid + b'\x00', b'\x03\x00\x41' + bytes(74), b'\x04' + valid[1:]):
            with self.assertRaises(ValueError):
                parse_ack_header(self.frame(0x1002, wire))

    def test_header_repr_omits_material_and_opaque_data(self):
        self.assertEqual(repr(parse_hello(self.frame(0x1001, self.hello))), 'DhHello(encryption_method=3)')
        self.assertEqual(repr(DhAckHeader(b'sensitive', 1, 500, 0)),
                         'DhAckHeader(compression_method=1, compression_threshold=500, compression_maximum=0)')
