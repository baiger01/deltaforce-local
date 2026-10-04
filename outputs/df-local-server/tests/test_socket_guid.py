import unittest

from dfserver import socket_guid


class SocketGuidTests(unittest.TestCase):
    def test_observed_purchase_guid_matches_its_exact_decimal_and_hex(self):
        root_guid = 281474976710710
        self.assertEqual(root_guid, 0x0001000000000036)
        self.assertEqual(socket_guid.socket_path(root_guid), (54,))
        guid = 72339069014645763
        self.assertEqual(guid, 0x0101000000001C03)
        self.assertEqual(socket_guid.socket_type(guid), 1)
        self.assertEqual(socket_guid.socket_depth(guid), 1)
        self.assertEqual(socket_guid.decode_socket_id(guid), 28)
        self.assertEqual(socket_guid.decode_socket_parent(guid), 0x0001000000000003)
        self.assertEqual(socket_guid.socket_path(guid), (3, 28))

    def test_native_decoder_permits_zero_child_slot_boundary(self):
        guid = 0x0101000000000003
        self.assertEqual(guid, 72339069014638595)
        self.assertEqual(socket_guid.socket_path(guid), (3, 0))

    def test_root_and_multiple_depths_follow_native_parent_chain(self):
        self.assertEqual(socket_guid.socket_path(0x0001000000000000), (0,))
        self.assertEqual(socket_guid.socket_path(0x0201000000040203), (3, 2, 4))
        self.assertEqual(socket_guid.socket_path(0x0301000006040203), (3, 2, 4, 6))

    def test_native_parent_mask_is_63_bits_and_not_an_invented_byte_mask(self):
        self.assertEqual(socket_guid.decode_socket_parent(0x01010000000000FF),
                         0x000100000000007F)
        self.assertEqual(socket_guid.socket_path(0x01010000000000FF), (127, 0))

    def test_decoder_matches_the_native_32_bit_shift_boundaries(self):
        self.assertEqual(socket_guid.decode_socket_id(0x03010000FF000003), 255)
        self.assertEqual(socket_guid.decode_socket_id(0x04010000AA000003), 0)
        self.assertEqual(socket_guid.decode_socket_id(0x05010000AA000003), 0)
        self.assertEqual(socket_guid.decode_socket_id(0x06010000AA000003), 0)
        self.assertEqual(socket_guid.decode_socket_id(0x07010000AA000003), 7)
        for depth in (4, 5, 6, 7):
            with self.assertRaises(ValueError):
                socket_guid.socket_path((depth << 56) | (1 << 48) | 3)

    def test_native_zero_sentinel_type_two_and_invalid_depth_returns(self):
        invalid = 0x7FFFFFFFFFFFFFFF
        self.assertEqual(socket_guid.decode_socket_id(0), 0)
        self.assertEqual(socket_guid.decode_socket_parent(0), invalid)
        for guid in (invalid, 0x0801000000000003):
            self.assertEqual(socket_guid.decode_socket_id(guid), invalid)
            self.assertEqual(socket_guid.decode_socket_parent(guid), invalid)
            with self.assertRaises(ValueError):
                socket_guid.socket_path(guid)
        self.assertEqual(socket_guid.decode_socket_id(0x0102000000000003), invalid)
        self.assertEqual(socket_guid.decode_socket_parent(0x0102000000000003), 0)
        with self.assertRaises(ValueError):
            socket_guid.socket_path(0)
        with self.assertRaises(ValueError):
            socket_guid.socket_path(0x0102000000000003)

    def test_requires_an_exact_unsigned_64_bit_integer(self):
        for bad in (-1, 1 << 64, '72339069014645763', True, None):
            with self.assertRaises(ValueError):
                socket_guid.socket_path(bad)


if __name__ == '__main__':
    unittest.main()
