import math
import struct
import unittest

from dfserver.legacy_ds_bit_archive import BitReader, BitWriter
from dfserver.legacy_ds_pc_rpc_fields import (
    OrdinaryRPCScalarProfile, ServerBouncePingParams, ClientReturnPingParams,
    write_server_bounce_ping, read_server_bounce_ping,
    write_client_return_ping, read_client_return_ping)


PROFILE = OrdinaryRPCScalarProfile(False, False)


def literal_presence_payload(raw):
    # Independent bit placement, without using the production bit writer.
    number = (int.from_bytes(raw, 'little') << 1) | 1
    bits = len(raw) * 8 + 1
    return number.to_bytes((bits + 7) // 8, 'little'), bits


class PCRPCScalarFieldsTests(unittest.TestCase):
    def test_server_ping_independent_literal_225_bits_and_exact_order(self):
        expected = ServerBouncePingParams(1024.5, .5, .25, .125, .0625, .03125)
        raw, bits = literal_presence_payload(struct.pack('<d5f', 1024.5, .5, .25, .125, .0625, .03125))
        self.assertEqual(bits, 225)
        self.assertEqual(read_server_bounce_ping(BitReader(raw, bit_count=bits), profile=PROFILE), expected)
        writer = BitWriter()
        self.assertEqual(write_server_bounce_ping(writer, expected, profile=PROFILE), bits)
        self.assertEqual(writer.to_bytes(), raw)

    def test_client_return_independent_literal_is_161_bits_not_ping_echo(self):
        expected = ClientReturnPingParams(1024.5, .0625, 64.25)
        raw, bits = literal_presence_payload(struct.pack('<ddf', 1024.5, .0625, 64.25))
        self.assertEqual(bits, 161)
        self.assertEqual(read_client_return_ping(BitReader(raw, bit_count=bits), profile=PROFILE), expected)
        writer = BitWriter()
        self.assertEqual(write_client_return_ping(writer, expected, profile=PROFILE), bits)
        self.assertEqual(writer.to_bytes(), raw)

    def test_absent_struct_is_one_bit_and_not_filled_with_invented_fields(self):
        for write, read in ((write_server_bounce_ping, read_server_bounce_ping),
                            (write_client_return_ping, read_client_return_ping)):
            writer = BitWriter()
            self.assertEqual(write(writer, None, profile=PROFILE), 1)
            self.assertEqual(writer.to_bytes(), b'\x00')
            self.assertIsNone(read(BitReader(b'\x00', bit_count=1), profile=PROFILE))

    def test_all_present_struct_truncations_fail_atomically(self):
        for read, raw in ((read_server_bounce_ping, struct.pack('<d5f', 1., 2., 3., 4., 5., 6.)),
                          (read_client_return_ping, struct.pack('<ddf', 1., 2., 3.))):
            data, bits = literal_presence_payload(raw)
            for length in range(bits):
                with self.subTest(read=read.__name__, length=length):
                    reader = BitReader(data[:(length + 7) // 8], bit_count=length)
                    with self.assertRaises(ValueError):
                        read(reader, profile=PROFILE)
                    self.assertEqual(reader.position, 0)

    def test_trailing_bits_are_not_consumed_as_another_rpc(self):
        for read, raw in ((read_server_bounce_ping, struct.pack('<d5f', 1., 2., 3., 4., 5., 6.)),
                          (read_client_return_ping, struct.pack('<ddf', 1., 2., 3.))):
            data, bits = literal_presence_payload(raw)
            reader = BitReader(data, bit_count=bits + 1)
            with self.assertRaises(ValueError):
                read(reader, profile=PROFILE)
            self.assertEqual(reader.position, 0)

    def test_unaligned_writer_places_no_byte_padding_before_presence(self):
        writer = BitWriter()
        writer.write_payload(b'\x05', 3)
        write_client_return_ping(writer, ClientReturnPingParams(1., 2., 3.), profile=PROFILE)
        independent, bits = literal_presence_payload(struct.pack('<ddf', 1., 2., 3.))
        expected = ((int.from_bytes(independent, 'little') << 3) | 5).to_bytes((bits + 10) // 8, 'little')
        self.assertEqual(writer.bit_count, bits + 3)
        self.assertEqual(writer.to_bytes(), expected)

    def test_alternate_profiles_cannot_silently_choose_this_grammar(self):
        for internal, swap in ((True, False), (False, True), (0, False), (False, 0)):
            with self.subTest(internal=internal, swap=swap), self.assertRaises(ValueError):
                OrdinaryRPCScalarProfile(internal, swap)
        with self.assertRaises(ValueError):
            write_client_return_ping(BitWriter(), None, profile=None)

    def test_bad_scalar_and_budget_do_not_partially_write_outer_archive(self):
        for params in (ClientReturnPingParams(True, 1., 1.),
                       ClientReturnPingParams(1., 1., 1e100)):
            writer = BitWriter()
            writer.write_bool(True)
            with self.assertRaises(ValueError):
                write_client_return_ping(writer, params, profile=PROFILE)
            self.assertEqual(writer.bit_count, 1)
        writer = BitWriter(maximum_bits=160)
        with self.assertRaises(ValueError):
            write_client_return_ping(writer, ClientReturnPingParams(1., 2., 3.), profile=PROFILE)
        self.assertEqual(writer.bit_count, 0)

    def test_codec_preserves_ieee_special_values_without_claiming_validation(self):
        raw, bits = literal_presence_payload(struct.pack('<ddf', float('nan'), float('inf'), -0.))
        params = read_client_return_ping(BitReader(raw, bit_count=bits), profile=PROFILE)
        self.assertTrue(math.isnan(params.server_returned_client_time_stamp))
        self.assertTrue(math.isinf(params.delta_ts))
        self.assertEqual(math.copysign(1., params.in_server_time_stamp), -1.)


if __name__ == '__main__':
    unittest.main()
