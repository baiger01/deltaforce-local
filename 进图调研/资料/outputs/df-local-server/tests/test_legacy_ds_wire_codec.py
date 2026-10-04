from dataclasses import replace
import hashlib
import unittest

from dfserver.legacy_ds_bit_archive import BitWriter
from dfserver.legacy_ds_control_fields import ControlMessage, decode_messages, encode_message
from dfserver.legacy_ds_wire_codec import (ChannelName, WireBunch, WirePacket,
    decode_native_packet, decode_observed_application,
    encode_native_packet, encode_observed_application)

# Credential-free application bodies from two private, local Hello captures.
# Opaque routing bytes and challenge cookies are deliberately absent.
# Original datagram SHA256s:
# 09: 1af7dae39fc6b98d0683d0f3bc9236dce8f65357c158066f93ff20e1a5dd9e3a
# 14: e76c10e89e1b9e433dea45d0de738b559cf10ab4df26b45c53a5760ab519f1c5
HELLO_BODIES = tuple(bytes.fromhex(value) for value in (
    'e01a402700000000004c0048e7bf00140008688198010200000018',
    'e01a682700000000004c0048e7bf00140008688198010200000018'))
MAX_PACKET = 1024  # Explicit fixture profile, not a universal engine constant.


class NativeWireCodecTests(unittest.TestCase):
    def decode(self, body):
        return decode_observed_application(body, max_packet_bytes=MAX_PACKET,
                                           received_by_server=True)

    def test_real_hello_boundary_is_derived_by_fields_and_reencodes_exactly(self):
        for body, sequence in zip(HELLO_BODIES, (1256, 1261)):
            packet = self.decode(body)
            self.assertEqual((packet.sequence, packet.acknowledged_sequence,
                              packet.history, packet.consumed_bits),
                             (sequence, 215, (0,), 210))
            self.assertEqual(len(packet.bunches), 1)
            bunch = packet.bunches[0]
            self.assertEqual((bunch.header_start_bit, bunch.payload_start_bit,
                              bunch.payload_bits), (73, 130, 80))
            self.assertEqual((bunch.channel_index, bunch.open, bunch.reliable,
                              bunch.channel_sequence, bunch.channel_name),
                             (0, True, True, 233, ChannelName(hardcoded_index=255)))
            self.assertEqual(decode_messages(bunch.payload, payload_bits=bunch.payload_bits),
                             (ControlMessage(0, (1, 1077088301, '')),))
            self.assertEqual(hashlib.sha256(bunch.payload).hexdigest(),
                             '8aea96fc825c793df5b6e692d627e99463e4c0b1cce44925d7a3e09a641bc0bc')
            self.assertEqual(encode_observed_application(packet,
                max_packet_bytes=MAX_PACKET, received_by_server=True), body)

    def test_partial_close_header_and_non_byte_aligned_payload(self):
        bunch = WireBunch(256, b'\x15', 5, close=True, close_reason=7,
            flag4=True, reliable=True, connection_flag=True,
            package_exports=True, must_be_mapped=True, partial=True,
            partial_initial=True, partial_final=True, channel_sequence=1023,
            channel_name=ChannelName(hardcoded_index=255))
        packet = WirePacket(16383, 0, (0x80000001, 5), False, 255, None, (bunch,), 0)
        raw, bits = encode_native_packet(packet, max_packet_bytes=MAX_PACKET,
                                         received_by_server=True)
        result = decode_native_packet(raw, bit_count=bits, max_packet_bytes=MAX_PACKET,
                                      received_by_server=True)
        self.assertEqual(replace(result.bunches[0], header_start_bit=None,
                                 payload_start_bit=None), bunch)
        self.assertEqual(result.consumed_bits, bits)
        self.assertEqual(encode_native_packet(result, max_packet_bytes=MAX_PACKET,
                                               received_by_server=True), (raw, bits))

    def test_multiple_bunches_and_text_channel_name_preserve_unaligned_cursor(self):
        named = WireBunch(1, b'\x03', 2, open=True,
                          channel_name=ChannelName(text='CustomChannel', number=7))
        unnamed = WireBunch(2, b'\x04', 3)
        packet = WirePacket(0, 16383, (1,), True, 8, 16, (named, unnamed), 0)
        raw, bits = encode_native_packet(packet, max_packet_bytes=MAX_PACKET,
                                         received_by_server=False)
        result = decode_native_packet(raw, bit_count=bits, max_packet_bytes=MAX_PACKET,
                                      received_by_server=False)
        self.assertEqual((result.packet_info, result.frame, result.server_frame_time),
                         (True, 8, 16))
        self.assertEqual([replace(b, header_start_bit=None, payload_start_bit=None)
                          for b in result.bunches], [named, unnamed])
        self.assertEqual(encode_native_packet(result, max_packet_bytes=MAX_PACKET,
                                               received_by_server=False), (raw, bits))

    def test_truncated_native_fields_fail_before_returning_any_bunches(self):
        packet = self.decode(HELLO_BODIES[0])
        raw, bits = encode_native_packet(packet, max_packet_bytes=MAX_PACKET,
                                         received_by_server=True)
        for truncated in (31, 63, 72, 129, bits - 1):
            with self.assertRaises(ValueError):
                decode_native_packet(raw, bit_count=truncated,
                                     max_packet_bytes=MAX_PACKET, received_by_server=True)
        for body in (b'', HELLO_BODIES[0] + b'\0',
                     bytes([HELLO_BODIES[0][0] | 1]) + HELLO_BODIES[0][1:]):
            with self.assertRaises(ValueError):
                self.decode(body)

    def test_invalid_encoder_flags_and_sequence_profiles_are_rejected(self):
        bunch = self.decode(HELLO_BODIES[0]).bunches[0]
        packet = self.decode(HELLO_BODIES[0])
        for invalid in (replace(bunch, channel_sequence=1024),
                        replace(bunch, close_reason=1),
                        replace(bunch, partial_initial=True),
                        replace(bunch, reliable=False),
                        replace(bunch, channel_name=ChannelName(hardcoded_index=605)),
                        replace(bunch, payload=b'\xff', payload_bits=3)):
            with self.assertRaises(ValueError):
                encode_native_packet(replace(packet, bunches=(invalid,)),
                                     max_packet_bytes=MAX_PACKET, received_by_server=True)
        with self.assertRaises(ValueError):
            decode_native_packet(None, bit_count=0, max_packet_bytes=MAX_PACKET,
                                 received_by_server=True)

    def test_native_history_reader_difference_is_an_explicit_local_rejection(self):
        # Native reads min(advertised,8), whereas our current canonical
        # ordinary profile rejects advertised 9..16 rather than guessing.
        header = (8).to_bytes(4, 'little') + bytes(33)
        with self.assertRaisesRegex(ValueError, 'history count'):
            decode_native_packet(header, bit_count=len(header)*8,
                                 max_packet_bytes=MAX_PACKET, received_by_server=True)

    def test_challenge_fields_do_not_depend_on_hello_payload_offset(self):
        packet = self.decode(HELLO_BODIES[0])
        payload = encode_message(3, 'local-challenge')
        bunch = replace(packet.bunches[0], payload=payload,
                        payload_bits=len(payload)*8, channel_sequence=1)
        output = encode_observed_application(replace(packet, bunches=(bunch,)),
            max_packet_bytes=MAX_PACKET, received_by_server=False)
        decoded = decode_observed_application(output, max_packet_bytes=MAX_PACKET,
                                              received_by_server=False)
        self.assertEqual(decode_messages(decoded.bunches[0].payload),
                         (ControlMessage(3, ('local-challenge',)),))

    def test_noncanonical_control_bit_without_open_or_close_is_rejected(self):
        packet = self.decode(HELLO_BODIES[0])
        raw, _ = encode_native_packet(packet, max_packet_bytes=MAX_PACKET,
                                       received_by_server=True)
        writer = BitWriter()
        writer.write_bits(int.from_bytes(raw, 'little') & ((1 << 73)-1), 73)
        writer.write_bits(1, 3)  # control=1, open=0, close=0
        with self.assertRaisesRegex(ValueError, 'Noncanonical control bit'):
            decode_native_packet(writer.to_bytes(), bit_count=writer.bit_count,
                                 max_packet_bytes=MAX_PACKET, received_by_server=True)


if __name__ == '__main__':
    unittest.main()
