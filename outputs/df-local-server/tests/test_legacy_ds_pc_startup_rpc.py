from dataclasses import replace
import struct
import unittest

from dfserver.legacy_ds_bit_archive import BitWriter, BitReader
from dfserver.legacy_ds_actor_fields import ClassFieldEnvelope, NormalClassFieldProfile, build_class_field_content, read_class_fields
from dfserver.legacy_ds_actor_content import write_actor_content_blocks, read_actor_content_blocks
from dfserver.legacy_ds_pc_startup_rpc import PCStartupProfile, PCStartupField, decode_pc_startup_bunch
from dfserver.legacy_ds_wire_codec import WireBunch, ChannelName
import tests.test_legacy_ds_pc_ping_receiver as ping_fixture
import tests.test_legacy_ds_control_connection as controls


PROFILE = PCStartupProfile(ping_fixture.PROFILE.class_path, 245, (
    PCStartupField('ServerShortTimeout', 79, 'empty'),
    PCStartupField('Server_RcvACWorldTime', 150, 'float32'),
    PCStartupField('ServerFieldOfView', 216, 'float32'),
    PCStartupField('NotifySeamlessLoginReady', 141, 'bool')), 131, 'b' * 64)


def rpc(sequence, index, value=None):
    parameter = BitWriter(maximum_bits=64)
    if index == 141:
        parameter.write_bool(value)
    elif index in (150, 216):
        parameter.write_bool(value is not None)
        if value is not None:
            parameter.write_payload(struct.pack('<f', value), 32)
    block = build_class_field_content((ClassFieldEnvelope(index, parameter.to_bytes(), parameter.bit_count),),
                                     profile=NormalClassFieldProfile(245, False))
    writer = BitWriter(maximum_bits=512)
    write_actor_content_blocks(writer, (block,))
    return WireBunch(2, writer.to_bytes(), writer.bit_count, reliable=True,
                     channel_sequence=sequence, channel_name=ChannelName(hardcoded_index=102))


class StartupReceiverTests(unittest.TestCase):
    def setUp(self):
        fixture = ping_fixture.PingReceiverTests()
        fixture.setUp()
        self.f = fixture.f
        opened = self.f.probe.control_peers[controls.PEER].actor_opens[2]
        opened.bunch = replace(opened.bunch, reliable=True, channel_sequence=0,
                               channel_name=ChannelName(hardcoded_index=102))
        self.f.probe.set_pc_startup_profile(controls.PEER, 2, 4, PROFILE)

    def send(self, bunches, now=0.5):
        transport = self.f.probe.peers[controls.PEER]
        packet = replace(self.f.template, sequence=(transport.in_sequence + 1) & 16383,
            acknowledged_sequence=(transport.out_sequence - 1) & 16383,
            history=(0xffffffff,), bunches=bunches)
        return self.f.raw(packet, now)

    def state(self):
        return self.f.probe.control_peers[controls.PEER]

    def test_complete_startup_keeps_actual_boolean_and_queues_empty_reliable_ack(self):
        event, response = self.send((rpc(200, 79), rpc(201, 150, 12.5),
                                    rpc(202, 216, 90.0), rpc(203, 141, False)))
        self.assertEqual(event, 'pc_startup_packet_consumed')
        self.assertEqual(self.f.decode(response).history[0] & 1, 1)
        state = self.state()
        self.assertEqual(state.pc_startup_expected_sequence, 204)
        self.assertEqual(state.pc_startup_request_count, 4)
        self.assertEqual(state.pc_client_world_time, 12.5)
        self.assertEqual(state.pc_client_field_of_view, 90.0)
        self.assertIs(state.pc_seamless_enter_requested, False)
        self.assertIsNotNone(state.pc_ready_ack)
        responses = [r for r in self.f.probe.poll(0.6) if r[1] == 'pc_ready_ack_send_prepared']
        self.assertEqual(len(responses), 1)
        packet = self.f.decode(responses[0][2]);bunch, = packet.bunches
        self.assertTrue(bunch.reliable)
        self.assertEqual(bunch.channel_index, 2)
        self.assertEqual(bunch.channel_sequence, 1)  # Synthetic open sequence0, no content followup.
        block, = read_actor_content_blocks(BitReader(bunch.payload, bit_count=bunch.payload_bits))
        field, = read_class_fields(BitReader(block.payload, bit_count=block.payload_bit_count),
                                  profile=NormalClassFieldProfile(245, False))
        self.assertEqual((field.rep_index, field.payload_bit_count, field.payload), (131, 0, b''))
        self.assertFalse(self.f.probe.summary()['player_spawn_implemented'])

    def test_ready_ack_next_sequence_retry_bytes_and_delivery_history(self):
        self.send((rpc(200, 79), rpc(201, 141, True)))
        response = next(r for r in self.f.probe.poll(0.6) if r[1] == 'pc_ready_ack_send_prepared')
        first = self.f.decode(response[2]).bunches[0]
        retry = next(r for r in self.f.probe.poll(1.2) if r[1] == 'pc_ready_ack_timer_retransmit_prepared')
        self.assertEqual(self.f.decode(retry[2]).bunches[0], first)
        self.send((), now=1.3)
        self.assertTrue(self.state().pc_ready_ack.delivered)
        self.assertFalse(any('pc_ready_ack' in r[1] for r in self.f.probe.poll(2.0)))
        self.assertIs(self.state().pc_seamless_enter_requested, True)

    def test_reliable_retries_are_idempotent_and_conflicting_values_refused(self):
        marker, ready = rpc(1023, 79), rpc(0, 141, False)
        self.send((marker, ready))
        self.send((marker, ready), now=0.7)
        self.assertEqual(self.state().pc_startup_expected_sequence, 1)
        self.assertEqual(self.state().pc_startup_request_count, 2)
        before = self.state().pc_ready_ack.bunch
        self.assertIsNone(self.send((rpc(0, 141, True),), now=0.9)[1])
        self.assertIs(self.state().pc_seamless_enter_requested, False)
        self.assertEqual(self.state().pc_ready_ack.bunch, before)

    def test_known_bunches_in_mixed_packet_commit_without_acknowledging_unknown_bunch(self):
        unknown = replace(rpc(500, 141, False), channel_index=4)
        event, response = self.send((rpc(200, 79), rpc(201, 141, False), unknown))
        self.assertEqual(event, 'pc_startup_mixed_packet_consumed')
        self.assertIsNone(response)
        self.assertEqual(self.f.probe.peers[controls.PEER].history & 1, 0)
        self.assertEqual(self.state().pc_startup_expected_sequence, 202)
        self.assertIsNotNone(self.state().pc_ready_ack)
        self.assertTrue(any(r[1] == 'pc_ready_ack_send_prepared' for r in self.f.probe.poll(0.6)))
        # Repeated recognized pieces do not emit a second acknowledgement namespace.
        self.send((rpc(200, 79), rpc(201, 141, False), unknown), now=0.7)
        self.assertEqual(self.state().pc_startup_request_count, 2)

    def test_ready_without_marker_wrong_sequence_and_undelivered_actor_are_refused(self):
        self.assertIsNone(self.send((rpc(200, 141, False),))[1])
        self.assertFalse(self.state().pc_ready_notification_received)
        self.send((rpc(200, 79),))
        self.assertIsNone(self.send((rpc(202, 141, False),), now=0.7)[1])
        self.assertFalse(self.state().pc_ready_notification_received)
        self.state().actor_opens[2].delivered = False
        self.assertIsNone(self.send((rpc(201, 141, False),), now=0.9)[1])

    def test_empty_scalar_presence_and_exact_eof(self):
        absent, = decode_pc_startup_bunch(rpc(201, 150, None), channel_index=2, profile=PROFILE)
        self.assertEqual(absent.value, 0.0)
        with self.assertRaises(ValueError):
            decode_pc_startup_bunch(rpc(201, 216, float('nan')), channel_index=2, profile=PROFILE)
        boolean = rpc(201, 141, False)
        with self.assertRaises(ValueError):
            decode_pc_startup_bunch(replace(boolean, payload_bits=boolean.payload_bits-1),
                                    channel_index=2, profile=PROFILE)

    def test_ping_still_replies_alongside_startup_and_unknown_bunches(self):
        unknown = replace(rpc(500, 141, False), channel_index=4)
        event, response = self.send((rpc(200, 79), ping_fixture.request(), unknown))
        self.assertEqual(event, 'pc_startup_mixed_packet_consumed')
        self.assertEqual(self.f.decode(response).history[0] & 1, 0)
        self.assertEqual(self.state().pc_ping_reply_count, 1)
        self.assertTrue(self.state().pc_short_timeout_observed)


if __name__ == '__main__':
    unittest.main()
