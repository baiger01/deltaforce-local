from dataclasses import replace
import unittest
from unittest.mock import patch

from dfserver.legacy_ds_actor_content import read_actor_content_blocks
from dfserver.legacy_ds_bit_archive import BitReader
from dfserver.legacy_ds_control_connection import ActorOpenDelivery
from dfserver.legacy_ds_game_state_start import GameStateStartProfile
from dfserver.legacy_ds_scalar_serializers import SHIPPING_SHA256
from dfserver.legacy_ds_wire_codec import ChannelName
from tests.test_legacy_ds_pc_startup_rpc import StartupReceiverTests, rpc
import tests.test_legacy_ds_control_connection as controls


PROFILE = GameStateStartProfile('/Game/Fixture.GameState_C', 19, SHIPPING_SHA256, 'c' * 64)


class GameStateStartTests(unittest.TestCase):
    def setUp(self):
        self.startup = StartupReceiverTests();self.startup.setUp()
        self.f = self.startup.f
        state = self.startup.state()
        pc = state.actor_opens[2]
        opened = replace(pc.bunch, channel_index=3, channel_sequence=1023,
                         reliable=True, channel_name=ChannelName(hardcoded_index=102))
        state.actor_opens[3] = ActorOpenDelivery(opened, 6, delivered=True)
        content = replace(opened, open=False, channel_sequence=0)
        state.actor_contents[3] = ActorOpenDelivery(content, 6, delivered=True)
        self.f.probe.set_game_state_start_profile(controls.PEER, 3, 6, PROFILE)

    def ready(self):
        self.startup.send((rpc(200, 79), rpc(201, 141, False)))
        self.f.probe.poll(0.6)
        self.startup.send((), now=0.7)  # Positive history for the actual ready-ack packet.

    def test_start_requires_ready_ack_delivery_and_exact_existing_game_state_channel(self):
        self.assertFalse(any('game_state_start' in r[1] for r in self.f.probe.poll(0.4)))
        self.startup.send((rpc(200, 79), rpc(201, 141, False)))
        self.assertFalse(any('game_state_start' in r[1] for r in self.f.probe.poll(0.6)))
        self.startup.send((), now=0.7)
        sent = next(r for r in self.f.probe.poll(0.8) if r[1]=='game_state_start_send_prepared')
        bunch, = self.f.decode(sent[2]).bunches
        self.assertEqual((bunch.channel_index, bunch.channel_sequence, bunch.reliable), (3, 1, True))
        block, = read_actor_content_blocks(BitReader(bunch.payload, bit_count=bunch.payload_bits))
        # Source-qualified consumer arithmetic, independent literal oracle:
        # false checksum bit + packed handle19 + true bit + packed zero terminal.
        self.assertEqual((block.has_rep_layout, block.payload_bit_count, block.payload.hex()),
                         (True, 18, '4c0200'))
        self.assertFalse(self.f.probe.summary()['all_player_ready_implemented'])

    def test_transport_retry_preserves_sequence_and_stops_after_delivery(self):
        self.ready()
        first = next(r for r in self.f.probe.poll(0.8) if r[1]=='game_state_start_send_prepared')
        self.assertFalse(any('game_state_start' in r[1] for r in self.f.probe.poll(1.0)))
        again = next(r for r in self.f.probe.poll(1.4) if r[1]=='game_state_start_timer_retransmit_prepared')
        self.assertEqual(self.f.decode(first[2]).bunches, self.f.decode(again[2]).bunches)
        self.startup.send((), now=1.5)
        self.assertTrue(self.startup.state().game_state_start.delivered)
        self.assertFalse(any('game_state_start' in r[1] for r in self.f.probe.poll(2.1)))

    def test_incomplete_associations_expired_ticket_wrong_owner_and_closed_peer_never_start(self):
        self.ready()
        state = self.startup.state()
        state.actor_contents[3].delivered = False
        self.assertFalse(any('game_state_start' in r[1] for r in self.f.probe.poll(0.8)))
        state.actor_contents[3].delivered = True
        with patch.object(self.f.probe.admissions, 'is_active', return_value=False):
            self.assertFalse(any('game_state_start' in r[1] for r in self.f.probe.poll(0.9)))
        previous = self.f.probe.ticket_peers[state.ticket.cookie]
        self.f.probe.ticket_peers[state.ticket.cookie] = ('127.0.0.1', 9999)
        self.assertFalse(any('game_state_start' in r[1] for r in self.f.probe.poll(1.0)))
        self.f.probe.ticket_peers[state.ticket.cookie] = previous
        state.client_closed = True
        self.assertFalse(any('game_state_start' in r[1] for r in self.f.probe.poll(1.1)))
        self.assertFalse(state.local_start_play_requested)

    def test_ack_cannot_be_attached_to_the_player_controller_or_wrong_actor(self):
        for channel, guid in ((2, 4), (3, 8), (17, 6)):
            with self.subTest(channel=channel), self.assertRaises(ValueError):
                self.f.probe.set_game_state_start_profile(controls.PEER, channel, guid, PROFILE)

    def enable_room_ready(self):
        self.startup.state().game_state_start_profile = replace(PROFILE, all_ready_handle=24)
        self.ready()
        self.f.probe.poll(0.8)
        self.startup.send((), now=0.9)  # BeginPlay delivery.

    def test_single_actual_ready_participant_receives_the_next_reliable_room_ready_field(self):
        self.enable_room_ready()
        sent = next(r for r in self.f.probe.poll(1.0) if r[1]=='game_state_all_ready_send_prepared')
        bunch, = self.f.decode(sent[2]).bunches
        self.assertEqual((bunch.channel_index, bunch.channel_sequence), (3, 2))
        block, = read_actor_content_blocks(BitReader(bunch.payload, bit_count=bunch.payload_bits))
        self.assertEqual((block.payload_bit_count, block.payload.hex()), (18, '600200'))
        self.startup.send((), now=1.1)
        self.assertTrue(self.startup.state().game_state_all_ready.delivered)
        self.assertFalse(any('game_state_all_ready' in r[1] for r in self.f.probe.poll(1.8)))

    def test_unjoined_participant_in_the_same_room_blocks_ready_but_another_room_does_not(self):
        ticket = self.startup.state().ticket
        self.f.admissions.issue(999, ticket.room_id, ticket.map_id, ticket.match_mode_id)
        self.enable_room_ready()
        self.assertFalse(any('game_state_all_ready' in r[1] for r in self.f.probe.poll(1.0)))
        self.assertFalse(self.startup.state().local_all_player_ready_requested)
        self.f.clock[0] = 130.0  # Pending admission expires; the actual joined participant remains.
        self.f.admissions.issue(998, ticket.room_id+1, ticket.map_id, ticket.match_mode_id)
        self.assertTrue(any('game_state_all_ready' in r[1] for r in self.f.probe.poll(130.0)))

    def enable_abseil(self):
        self.startup.state().game_state_start_profile = replace(PROFILE, all_ready_handle=24, abseil_handle=107)
        self.ready()
        self.f.probe.poll(0.8)
        self.startup.send((), now=0.9)
        self.f.probe.poll(1.0)

    def test_abseil_permission_waits_for_ready_delivery_uses_actual_handle_and_retries_idempotently(self):
        self.enable_abseil()
        self.assertFalse(any('game_state_abseil' in r[1] for r in self.f.probe.poll(1.05)))
        self.startup.send((), now=1.1)
        first = next(r for r in self.f.probe.poll(1.2) if r[1]=='game_state_abseil_send_prepared')
        bunch, = self.f.decode(first[2]).bunches
        self.assertEqual((bunch.channel_index, bunch.channel_sequence), (3, 3))
        block, = read_actor_content_blocks(BitReader(bunch.payload, bit_count=bunch.payload_bits))
        # false checksum + packed107 + true + zero terminal, independent bit arithmetic.
        self.assertEqual((block.payload_bit_count, block.payload.hex()), (18, 'ac0300'))
        retry = next(r for r in self.f.probe.poll(1.8) if r[1]=='game_state_abseil_timer_retransmit_prepared')
        self.assertEqual(self.f.decode(first[2]).bunches, self.f.decode(retry[2]).bunches)
        self.startup.send((), now=1.9)
        self.assertEqual(self.f.probe.summary()['game_state_abseil_delivery_acks'], 1)
        self.assertFalse(any('game_state_abseil' in r[1] for r in self.f.probe.poll(2.5)))

    def test_abseil_permission_never_releases_a_new_unjoined_member_closed_or_expired_room(self):
        self.enable_abseil()
        self.startup.send((), now=1.1)
        ticket = self.startup.state().ticket
        self.f.admissions.issue(999, ticket.room_id, ticket.map_id, ticket.match_mode_id)
        self.assertFalse(any('game_state_abseil' in r[1] for r in self.f.probe.poll(1.2)))
        self.f.clock[0] = 130.0
        with patch.object(self.f.probe.admissions, 'active_room_tickets', return_value=()):
            self.assertFalse(any('game_state_abseil' in r[1] for r in self.f.probe.poll(130.0)))
        self.startup.state().client_closed = True
        self.assertFalse(any('game_state_abseil' in r[1] for r in self.f.probe.poll(131.0)))

    def test_match_info_from_admitted_ticket_is_delivered_before_begin_play(self):
        self.startup.state().game_state_start_profile = replace(
            PROFILE, all_ready_handle=24, abseil_handle=107, map_id_handle=52, room_id_handle=53)
        self.ready()
        sent = self.f.probe.poll(0.8)
        self.assertFalse(any('game_state_start' in r[1] for r in sent))
        first = next(r for r in sent if r[1]=='game_state_match_info_send_prepared')
        bunch, = self.f.decode(first[2]).bunches
        self.assertEqual((bunch.channel_index, bunch.channel_sequence), (3, 1))
        block, = read_actor_content_blocks(BitReader(bunch.payload, bit_count=bunch.payload_bits))
        ticket = self.startup.state().ticket
        # Independent integer oracle for the unaligned ordinary stream.
        expected = (104 << 1) | (ticket.map_id << 9) | (106 << 73) | (ticket.room_id << 81)
        self.assertEqual((block.payload_bit_count, block.payload), (153, expected.to_bytes(20, 'little')))
        retry = next(r for r in self.f.probe.poll(1.4) if r[1]=='game_state_match_info_timer_retransmit_prepared')
        self.assertEqual(self.f.decode(first[2]).bunches, self.f.decode(retry[2]).bunches)
        self.startup.send((), now=1.5)
        start = next(r for r in self.f.probe.poll(1.6) if r[1]=='game_state_start_send_prepared')
        self.assertEqual(self.f.decode(start[2]).bunches[0].channel_sequence, 2)
        self.assertEqual(self.f.probe.summary()['game_state_match_info_delivery_acks'], 1)


if __name__ == '__main__':
    unittest.main()
