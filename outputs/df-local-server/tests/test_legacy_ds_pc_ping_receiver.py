from dataclasses import replace
import unittest

from dfserver.legacy_ds_bit_archive import BitReader, BitWriter
from dfserver.legacy_ds_actor_content import read_actor_content_blocks, write_actor_content_blocks
from dfserver.legacy_ds_actor_fields import (
    ClassFieldEnvelope, build_class_field_content, read_class_fields, NormalClassFieldProfile,
)
from dfserver.legacy_ds_pc_rpc_fields import (
    ServerBouncePingParams, OrdinaryRPCScalarProfile, write_server_bounce_ping, read_client_return_ping,
)
from dfserver.legacy_ds_pc_ping_receiver import PCPingProfile, decode_pc_ping_bunches
from dfserver.legacy_ds_control_connection import ActorOpenDelivery
from dfserver.legacy_ds_control_fields import encode_message
from dfserver.legacy_ds_wire_codec import WireBunch, ChannelName
import tests.test_legacy_ds_control_connection as fixtures


PROFILE = PCPingProfile('/Game/BluePrints/Characters/BP_DFMPlayerController.BP_DFMPlayerController_C',
                        245, 151, 138, 'a' * 64)
PARAMS = ServerBouncePingParams(123.5, 0.01, 0.01, 0.01, 0.01, 0.01)


def request(params=PARAMS, *, index=151):
    writer = BitWriter(maximum_bits=225)
    write_server_bounce_ping(writer, params, profile=OrdinaryRPCScalarProfile(False, False))
    block = build_class_field_content((ClassFieldEnvelope(index, writer.to_bytes(), writer.bit_count),),
                                     profile=NormalClassFieldProfile(245, False))
    content = BitWriter(maximum_bits=512)
    write_actor_content_blocks(content, (block,))
    return WireBunch(2, content.to_bytes(), content.bit_count)


class PingReceiverTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.NativeControlConnectionTests()
        self.f.setUp()
        self.f.login()
        self.f.send(1258, 217, 235, encode_message(4, 25000), now=0.2)
        self.f.send(1259, 218, 236, encode_message(9), now=0.3)
        state = self.f.probe.control_peers[fixtures.PEER]
        state.actor_opens[2] = ActorOpenDelivery(WireBunch(2, b'', 0), 4, delivered=True)
        self.f.probe.set_pc_ping_profile(fixtures.PEER, 2, 4, PROFILE)

    def send_ping(self, bunches=None, *, now=0.5):
        transport = self.f.probe.peers[fixtures.PEER]
        packet = replace(self.f.template, sequence=(transport.in_sequence + 1) & 16383,
            acknowledged_sequence=(transport.out_sequence - 1) & 16383,
            history=(0xffffffff,), bunches=(request(),) if bunches is None else bunches)
        return self.f.raw(packet, now)

    def test_ping_is_admitted_and_reply_echoes_tc1_on_the_same_actor_channel(self):
        transport = self.f.probe.peers[fixtures.PEER]
        budget = transport.replies
        control_sequence = self.f.probe.control_peers[fixtures.PEER].next_server_sequence
        event, response = self.send_ping()
        self.assertEqual(event, 'pc_ping_rpc_reply_prepared')
        packet = self.f.decode(response)
        self.assertEqual(packet.history[0] & 1, 1)
        bunch, = packet.bunches
        self.assertEqual(bunch.channel_index, 2)
        self.assertFalse(bunch.reliable)
        block, = read_actor_content_blocks(BitReader(bunch.payload, bit_count=bunch.payload_bits))
        field, = read_class_fields(BitReader(block.payload, bit_count=block.payload_bit_count),
                                  profile=NormalClassFieldProfile(245, False))
        self.assertEqual((field.rep_index, field.payload_bit_count), (138, 161))
        value = read_client_return_ping(BitReader(field.payload, bit_count=field.payload_bit_count),
                                       profile=OrdinaryRPCScalarProfile(False, False))
        self.assertEqual(value.server_returned_client_time_stamp, PARAMS.tc1)
        self.assertAlmostEqual(value.delta_ts, 0.2)
        self.assertAlmostEqual(value.in_server_time_stamp, 0.2, places=6)
        self.assertEqual(transport.replies, budget)
        self.assertEqual(self.f.probe.control_peers[fixtures.PEER].next_server_sequence, control_sequence)
        self.assertFalse(self.f.probe.summary()['player_spawn_implemented'])

    def test_authenticated_joined_client_still_receives_ping_after_the_login_ticket_expires(self):
        self.f.clock[0] = 130.0  # Default admission deadline120, joined session still current.
        self.send_ping(bunches=(), now=129.8)  # The normal authenticated transport is still active.
        event, response = self.send_ping(now=130.0)
        self.assertEqual(event, 'pc_ping_rpc_reply_prepared')
        self.assertIsNotNone(response)
        self.assertTrue(self.f.admissions.is_active(self.f.ticket))
        self.assertEqual(self.f.admissions.summary()['expired_ticket_count'], 0)

    def test_unknown_mixed_and_nonfinite_payloads_are_never_acknowledged(self):
        for bunches in ((request(index=141),),
                        (replace(request(), reliable=True, channel_sequence=200,
                                 channel_name=ChannelName(hardcoded_index=102)),),
                        (request(replace(PARAMS, tc1=float('nan'))),),
                        (replace(request(), channel_index=4),)):
            with self.subTest(bunches=bunches):
                before = self.f.probe.control_peers[fixtures.PEER]
                event, response = self.send_ping(bunches)
                self.assertEqual((event, response), ('application_channel_payload_unsupported', None))
                current = self.f.probe.control_peers[fixtures.PEER]
                self.assertIs(current.ticket, before.ticket)
                self.assertEqual(current.expected_client_sequence, before.expected_client_sequence)
                self.assertEqual(current.pc_ping_reply_count, before.pc_ping_reply_count)
                self.assertEqual(current.pc_startup_expected_sequence, before.pc_startup_expected_sequence)
                self.assertEqual(current.last_received_at, .5)
                self.assertEqual(self.f.probe.peers[fixtures.PEER].history & 1, 0)
                self.assertEqual(current.pc_ping_reply_count, 0)

    def test_mixed_packet_replies_only_to_ping_and_leaves_packet_unacknowledged(self):
        state = self.f.probe.control_peers[fixtures.PEER]
        reliable_sequence = state.expected_client_sequence
        event, response = self.send_ping((request(), request(index=141)))
        self.assertEqual(event, 'pc_ping_reply_for_unacknowledged_mixed_packet')
        packet = self.f.decode(response)
        self.assertEqual(packet.history[0] & 1, 0)
        self.assertEqual(self.f.probe.peers[fixtures.PEER].history & 1, 0)
        state = self.f.probe.control_peers[fixtures.PEER]
        self.assertEqual(state.expected_client_sequence, reliable_sequence)
        self.assertEqual(state.pc_ping_reply_count, 1)
        self.assertEqual(len(packet.bunches), 1)

    def test_unknown_fields_inside_one_bunch_are_not_partially_consumed(self):
        from dfserver.legacy_ds_pc_ping_receiver import select_pc_ping_bunches
        block, = read_actor_content_blocks(BitReader(request().payload, bit_count=request().payload_bits))
        field, = read_class_fields(BitReader(block.payload, bit_count=block.payload_bit_count),
                                  profile=NormalClassFieldProfile(245, False))
        mixed = build_class_field_content((field, ClassFieldEnvelope(141, b'\0', 1)),
                                         profile=NormalClassFieldProfile(245, False))
        writer = BitWriter(maximum_bits=512)
        write_actor_content_blocks(writer, (mixed,))
        bunch = WireBunch(2, writer.to_bytes(), writer.bit_count)
        self.assertEqual(select_pc_ping_bunches((bunch,), channel_index=2, profile=PROFILE), ())
        self.assertIsNone(self.send_ping((bunch,))[1])

    def test_unsupported_authenticated_packets_update_clock_without_positive_ack(self):
        self.assertIsNone(self.send_ping((request(index=141),), now=4.0)[1])
        state = self.f.probe.control_peers[fixtures.PEER]
        self.assertEqual(state.last_received_at, 4.0)
        self.assertEqual(self.f.probe.peers[fixtures.PEER].history & 1, 0)
        event, response = self.send_ping(now=4.2)
        self.assertEqual(event, 'pc_ping_rpc_reply_prepared')
        self.assertIsNotNone(response)

    def test_undelivered_actor_and_expired_ticket_cannot_receive_ping_replies(self):
        state = self.f.probe.control_peers[fixtures.PEER]
        state.actor_opens[2].delivered = False
        self.assertIsNone(self.send_ping()[1])
        state.actor_opens[2].delivered = True
        self.f.clock[0] = 10000
        self.assertIsNone(self.send_ping()[1])

    def test_throttle_and_separate_reply_budget_do_not_mutate_control_sequence(self):
        self.assertIsNotNone(self.send_ping(now=0.5)[1])
        event, response = self.send_ping(now=0.55)
        self.assertEqual((event, response), ('pc_ping_rpc_consumed_without_reply', None))
        state = self.f.probe.control_peers[fixtures.PEER]
        self.assertEqual(state.pc_ping_reply_count, 1)
        state.pc_ping_reply_count = PROFILE.maximum_replies
        self.assertIsNone(self.send_ping(now=0.7)[1])

    def test_exhausted_control_budget_does_not_disable_the_separate_ping_budget(self):
        transport = self.f.probe.peers[fixtures.PEER]
        transport.replies = self.f.probe.max_replies
        self.assertIsNotNone(self.send_ping()[1])
        self.assertEqual(transport.replies, self.f.probe.max_replies)

    def test_missing_present_struct_or_changed_index_is_not_a_ping(self):
        for bunch in (request(None), request(index=138)):
            with self.assertRaises(ValueError):
                decode_pc_ping_bunches((bunch,), channel_index=2, profile=PROFILE)


if __name__ == '__main__':
    unittest.main()
