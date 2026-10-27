"""Opaque, synthetic post-open content transport; no native possession claim."""
from dataclasses import replace
import unittest
from unittest.mock import Mock, PropertyMock, patch

from dfserver.game_server_probe import GameServerProbe
from dfserver.legacy_ds_actor_content import ActorContentBlock
from dfserver.legacy_ds_bit_archive import BitReader
from dfserver.legacy_ds_control_probe import CONTROL_NAME
from dfserver.legacy_ds_handshake_probe import PendingChallenge
from dfserver.legacy_ds_wire_codec import WireBunch, encode_observed_application
from tests.test_legacy_ds_actor_bootstrap import manifest
from tests.test_legacy_ds_actor_delivery import actor_fields, decode
from tests.test_legacy_ds_control_probe import PEER
from tests import test_legacy_ds_actor_bootstrap as bootstrap_tests
from tests import test_legacy_ds_actor_delivery as delivery_tests
from tests import test_game_server_probe_rebind as rebind_tests


BLOCK = ActorContentBlock(True, b'\x15', 5)


def plan(channel=2, actor=4, blocks=(BLOCK,)):
    return dict(channel_index=channel, actor_guid=actor, content_blocks=blocks)


class ActorContentFollowupTests(unittest.TestCase):
    def setUp(self):
        self.fixture = delivery_tests.ActorDeliveryTests()
        self.fixture.setUp()
        self.connection = self.fixture.connection
        self.ticket = self.fixture.ticket
        self.client_sequence = 1259

    def ack(self, sequence, *, history=(1,), now=.2, peer=PEER, bunches=()):
        packet = replace(self.fixture.template, sequence=self.client_sequence,
            acknowledged_sequence=sequence, history=history, bunches=bunches)
        self.client_sequence += 1
        return self.connection.handle(b'opaque!!' + encode_observed_application(packet,
            max_packet_bytes=1024, received_by_server=True), peer, now)

    def queue(self, *, three=False, plans=None):
        fields = (actor_fields(channel_index=2, actor_guid=4),)
        if three:
            fields += (actor_fields(channel_index=3, actor_guid=6),
                       actor_fields(channel_index=4, actor_guid=2))
        self.connection.queue_actor_opens(PEER, fields,
            post_open_actor_contents=(plan(),) if plans is None else plans)

    def open_ack(self):
        first = decode(self.connection.poll(.1)[0][2])
        self.assertEqual(self.ack(first.sequence)[0], 'control_ack_only_consumed')
        return first

    def test_all_initial_actors_need_exact_acks_before_content_and_wire_is_only_content(self):
        self.queue(three=True, plans=(plan(), plan(4, 2)))
        opens = [decode(row[2]) for row in self.connection.poll(.1)]
        self.assertEqual([packet.sequence for packet in opens], [219, 220, 221])
        self.assertEqual(self.ack(221, history=(5,))[1], None)  # Missing packet220.
        self.assertEqual(self.connection.poll(.3), [])
        self.assertEqual(self.connection.summary()['post_open_actor_content_delivery_acks'], 0)
        self.ack(221, history=(7,), now=.35)
        follows = [decode(row[2]) for row in self.connection.poll(.4)]
        self.assertEqual([packet.bunches[0].channel_index for packet in follows], [2, 4])
        for packet in follows:
            bunch = packet.bunches[0]
            self.assertTrue(bunch.reliable)
            self.assertFalse(bunch.open or bunch.close or bunch.package_exports or
                             bunch.must_be_mapped or bunch.partial)
            self.assertEqual(bunch.channel_sequence, (opens[0].bunches[0].channel_sequence + 1) & 1023)
            self.assertEqual(bunch.channel_name.hardcoded_index, 102)
            reader = BitReader(bunch.payload, bit_count=bunch.payload_bits)
            self.assertTrue(reader.read_bool())  # Caller-selected hasRepLayout.
            self.assertTrue(reader.read_bool())  # Existing channel Actor selector.
            self.assertEqual(reader.read_packed_int(), 5)
            self.assertEqual(reader.read_bits(5), 0x15)
            self.assertEqual(reader.remaining, 0)  # No Actor GUID/spawn header/padding.
        self.assertFalse(self.connection.summary()['native_actor_resolution_verified'])

    def test_retry_keeps_bunch_and_reliable_sequence_but_new_packet_and_exact_ack(self):
        self.queue()
        self.open_ack()
        first = decode(self.connection.poll(.3)[0][2])
        event, response = self.ack(first.sequence, history=(1 << 5,), now=.35)
        self.assertEqual((event, response), ('control_ack_only_consumed', None))
        self.assertEqual(self.connection.summary()['post_open_actor_content_delivery_acks'], 0)
        self.assertEqual(self.connection.poll(.4), [])
        retry = decode(self.connection.poll(.9)[0][2])
        self.assertEqual(retry.sequence, first.sequence + 1)
        self.assertEqual(retry.bunches[0], first.bunches[0])
        self.ack(retry.sequence, now=.95)
        self.assertEqual(self.connection.summary()['post_open_actor_content_delivery_acks'], 1)
        self.assertEqual(self.connection.poll(2), [])

    def test_unknown_incoming_channel_keeps_header_receipt_without_accepting_body(self):
        self.queue()
        self.open_ack()
        first = decode(self.connection.poll(.3)[0][2])
        event, response = self.ack(first.sequence, bunches=first.bunches, now=.35)
        self.assertEqual((event, response), ('application_channel_payload_unsupported', None))
        self.assertEqual(self.connection.summary()['post_open_actor_content_delivery_acks'], 1)
        self.assertEqual(self.connection.peers[PEER].history & 1, 0)
        self.assertEqual(self.connection.poll(.9), [])

    def test_invalid_plan_rolls_back_entire_initial_set_and_events(self):
        bad_plans = (
            (plan(), plan(9, 2)), (plan(actor=2),), (plan(channel=True),),
            (plan(), plan()), (dict(plan(), open=True),),
            (plan(blocks=[]),), (plan(blocks=()),),
            # Logical assembly remains bounded, and bytes must cover every bit.
            (plan(blocks=(ActorContentBlock(True, bytes(8192), 65536),)),),
            (plan(blocks=(ActorContentBlock(True, bytes(1024), 8193),)),),
        )
        for plans in bad_plans:
            with self.subTest(plans=plans):
                state = self.connection.control_peers[PEER]
                events = dict(self.connection.control_events)
                packet_sequence = self.connection.peers[PEER].out_sequence
                with self.assertRaises(ValueError):
                    self.queue(three=True, plans=plans)
                self.assertIs(self.connection.control_peers[PEER], state)
                self.assertEqual((state.actor_opens, state.actor_contents, state.actor_exports), ({}, {}, {}))
                self.assertEqual(dict(self.connection.control_events), events)
                self.assertEqual(self.connection.peers[PEER].out_sequence, packet_sequence)

    def test_default_profile_stays_property_free(self):
        self.queue(plans=())
        self.open_ack()
        self.assertEqual(self.connection.poll(1), [])
        self.assertEqual(self.connection.control_peers[PEER].actor_contents, {})
        self.assertEqual(self.connection.summary()['post_open_actor_content_channels_queued'], 0)

    def test_reliable_sequence_wrap_and_further_initial_open_is_blocked_after_followup(self):
        self.connection.control_peers[PEER].initial_actor_sequence = 1023
        self.queue()
        opened = self.open_ack()
        follow = decode(self.connection.poll(.3)[0][2])
        self.assertEqual(opened.bunches[0].channel_sequence, 1023)
        self.assertEqual(follow.bunches[0].channel_sequence, 0)
        with self.assertRaisesRegex(ValueError, 'advanced'):
            self.connection.queue_actor_open(PEER, **actor_fields(channel_index=3, actor_guid=6))

    def test_content_transmissions_and_packet_reply_limits_are_bounded(self):
        self.queue()
        self.open_ack()
        self.connection.max_transmissions = 2
        first = self.connection.poll(.3)
        retry = self.connection.poll(.9)
        self.assertEqual((len(first), len(retry)), (1, 1))
        self.assertEqual(self.connection.poll(2), [])
        self.assertEqual(self.connection.summary()['post_open_actor_content_retries_exhausted'], 1)
        self.assertEqual(self.connection.peers[PEER].replies, 6)

    def test_content_cannot_consume_a_spent_packet_budget(self):
        self.queue()
        self.open_ack()
        self.connection.max_replies = self.connection.peers[PEER].replies
        self.assertEqual(self.connection.poll(.3), [])
        self.assertEqual(self.connection.control_peers[PEER].actor_contents[2].transmissions, 0)

    def test_expired_ticket_or_wrong_owner_stops_followup_without_activity_refresh(self):
        for reason in ('expired', 'owner'):
            with self.subTest(reason=reason):
                self.setUp()
                self.queue()
                self.open_ack()
                before = self.connection.peers[PEER].out_sequence
                if reason == 'expired':
                    self.fixture.admissions._clock = lambda: 3600.0
                else:
                    self.connection.ticket_peers[self.ticket.cookie] = ('127.0.0.1', 49999)
                self.assertEqual(self.connection.poll(.3), [])
                self.assertEqual(self.connection.peers[PEER].out_sequence, before)

    def test_control_close_cancels_followup_without_late_ack_reviving_it(self):
        self.queue()
        opened = self.open_ack()
        state = self.connection.control_peers[PEER]
        close = WireBunch(0, b'', 0, close=True, reliable=True,
            channel_sequence=state.expected_client_sequence, channel_name=CONTROL_NAME)
        self.assertEqual(self.ack(opened.sequence, bunches=(close,), now=.3)[0],
                         'control_client_close_consumed')
        self.assertEqual(self.connection.poll(1), [])
        self.assertEqual(self.connection.summary()['post_open_actor_content_cancelled_by_client_close'], 1)
        self.ack(self.connection.peers[PEER].out_sequence - 1, now=1.1)
        self.assertEqual(self.connection.summary()['post_open_actor_content_delivery_acks'], 0)

    def test_authenticated_rebind_preserves_followup_payload_ack_history_and_channel(self):
        self.queue()
        self.open_ack()
        first = decode(self.connection.poll(.3)[0][2])
        state = self.connection.control_peers[PEER]
        transport = self.connection.peers[PEER]
        delivery = state.actor_contents[2]
        new_peer = ('127.0.0.1', PEER[1] + 99)
        self.connection.rebind_verified_peer(PEER, new_peer)
        self.assertIs(self.connection.control_peers[new_peer], state)
        self.assertIs(self.connection.peers[new_peer], transport)
        self.assertIs(state.actor_contents[2], delivery)
        retry = self.connection.poll(.9)
        self.assertEqual(retry[0][0], new_peer)
        packet = decode(retry[0][2])
        self.assertEqual(packet.bunches[0], first.bunches[0])
        self.ack(packet.sequence, now=.95, peer=new_peer)
        self.assertEqual(self.connection.summary()['post_open_actor_content_delivery_acks'], 1)
        self.connection.forget_peer(new_peer)
        self.assertEqual(self.connection.poll(2), [])


class ProbeContentFollowupTests(unittest.TestCase):
    def setUp(self):
        self.fixture = bootstrap_tests.BootstrapLifetimeTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.server = self.fixture.server
        self.connection = self.fixture.connection
        self.ticket = self.fixture.ticket
        self.server._registered_bootstraps.clear()
        with patch.object(GameServerProbe, 'listening', new_callable=PropertyMock, return_value=True):
            self.server.register_initial_actor_manifests(self.ticket, (manifest(),),
                post_open_actor_contents=(plan(1, 2),))

    def prepare_followup(self):
        with self.server._lock:
            self.server._queue_registered_bootstraps_locked()
            initial = decode(self.connection.poll(.01)[0][2])
            self.connection.control_peers[PEER].actor_opens[1].delivered = True
        # Dedicated control tests above cover real exact history ACK gating.
        return initial

    def fake_socket(self):
        original = self.server._udp
        self.server._udp = Mock()
        self.server._udp.sendto.side_effect = lambda payload, peer: len(payload)
        self.addCleanup(original.close)

    def test_configured_profile_detaches_plans_and_applies_to_future_ticket(self):
        supplied = plan(1, 2)
        with patch.object(GameServerProbe, 'listening', new_callable=PropertyMock, return_value=True):
            self.server.set_initial_actor_manifests(2201, (manifest(),),
                post_open_actor_contents=(supplied,))
            supplied['actor_guid'] = 999
            ticket = self.server.issue_match_admission(player_id=102, room_id=202,
                map_id=2201, match_mode_id=142201103)
        stored = self.server._registered_bootstraps[ticket.cookie]['post_open_actor_contents']
        self.assertEqual(stored, (plan(1, 2),))
        self.assertIsNot(stored[0], supplied)

    def test_invalid_profile_does_not_replace_good_configuration_or_register_ticket(self):
        with patch.object(GameServerProbe, 'listening', new_callable=PropertyMock, return_value=True):
            self.server.set_initial_actor_manifests(2201, (manifest(),))
            previous = self.server._initial_actor_profiles[2201]
            with self.assertRaises(ValueError):
                self.server.set_initial_actor_manifests(2201, (manifest(),),
                    post_open_actor_contents=(plan(7, 2),))
            self.assertIs(self.server._initial_actor_profiles[2201], previous)
        self.assertEqual(self.connection.control_peers[PEER].actor_contents, {})

    def test_resolver_actor_identity_change_rejects_whole_open_and_followup_set(self):
        registration = self.server._registered_bootstraps[self.ticket.cookie]
        registration['resolver'] = lambda ticket, fields: (dict(fields[0], actor_guid=4),)
        with self.server._lock:
            self.server._queue_registered_bootstraps_locked()
        self.assertEqual(registration['status'], 'rejected')
        state = self.connection.control_peers[PEER]
        self.assertEqual((state.actor_opens, state.actor_contents, state.actor_exports), ({}, {}, {}))

    def test_followup_counters_do_not_report_content_as_initial_actor_or_native_spawn(self):
        self.prepare_followup()
        self.fake_socket()
        self.server._send_control_retries()
        self.server._udp.sendto.assert_called_once()
        self.assertEqual(self.server._actor_content_sent, 1)
        self.assertEqual(self.server._actor_open_sent, 0)
        self.assertFalse(self.server.actor_transport_progress['native_spawn_verified'])
        self.assertFalse(self.connection.summary()['actor_replication_implemented'])

    def test_encoded_followup_is_dropped_on_close_expiry_or_replaced_generation(self):
        for reason in ('close', 'expired', 'generation'):
            with self.subTest(reason=reason):
                self.setUp()
                self.prepare_followup()
                self.fake_socket()
                expire = self.server._handshake._expire
                calls = [0]

                def change_after_encoding(now):
                    expire(now)
                    calls[0] += 1
                    if calls[0] == 3:
                        if reason == 'close':
                            self.connection.control_peers[PEER].client_closed = True
                        elif reason == 'expired':
                            self.server._admissions._clock = lambda: 3600.0
                        else:
                            self.server._handshake.pending[PEER] = PendingChallenge(2., b'new!' * 5, now)

                with patch.object(self.server._handshake, '_expire', side_effect=change_after_encoding):
                    self.server._send_control_retries()
                self.server._udp.sendto.assert_not_called()
                self.assertEqual(self.server._actor_content_sent, 0)
                self.assertEqual(self.server._bootstrap_events['stale_actor_datagrams_discarded'], 1)

    def test_already_encoded_followup_routes_to_authenticated_new_owner_unchanged(self):
        self.prepare_followup()
        self.fake_socket()
        helper = rebind_tests.ProbeQueuedSendRebindTests()
        helper.server, helper.connection, helper.ticket = self.server, self.connection, self.ticket
        helper.new_peer = ('127.0.0.1', PEER[1] + 55)
        expire = self.server._handshake._expire
        calls = [0]

        def migrate_after_encoding(now):
            expire(now)
            calls[0] += 1
            if calls[0] == 3:
                helper.migrate(now)

        with patch.object(self.server._handshake, '_expire', side_effect=migrate_after_encoding):
            self.server._send_control_retries()
        self.server._udp.sendto.assert_called_once()
        body, peer = self.server._udp.sendto.call_args.args
        self.assertEqual(peer, helper.new_peer)
        self.assertFalse(decode(body).bunches[0].open)
        self.assertEqual(decode(body).bunches[0].channel_sequence, 218)
        self.assertEqual(self.server._actor_content_sent, 1)
        self.assertEqual(self.server._bootstrap_events['authenticated_peer_rebinds'], 1)


if __name__ == '__main__':
    unittest.main()
