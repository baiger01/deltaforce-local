"""Observed empty reliable Control closes; synthetic actors are not spawn evidence."""
from dataclasses import replace
import time
import unittest
from unittest.mock import Mock, patch

from dfserver.legacy_ds_control_fields import encode_message
from dfserver.legacy_ds_wire_codec import decode_observed_application, encode_observed_application
from tests import test_legacy_ds_actor_delivery as delivery
from tests import test_legacy_ds_actor_bootstrap as bootstrap
from tests import test_legacy_ds_actor_transport_progress as progress
from tests.test_legacy_ds_control_connection import login_payload
from tests.test_legacy_ds_control_probe import COOKIE, PEER
from tests.test_legacy_ds_wire_codec import HELLO_BODIES

OTHER = progress.OTHER


class ControlCloseTests(unittest.TestCase):
    def setUp(self):
        fixture = delivery.ActorDeliveryTests()
        fixture.setUp()
        self.connection, self.ticket = fixture.connection, fixture.ticket
        self.template = fixture.template
        self.connection.queue_actor_open(PEER, **delivery.actor_fields())
        self.actor = delivery.decode(self.connection.poll(0.1)[0][2])

    def close_packet(self, *, peer=PEER, sequence=None, ack=None, history=(0,), **changes):
        state, transport = self.connection.control_peers[peer], self.connection.peers[peer]
        bunch = replace(self.template.bunches[0], open=False, close=True,
            channel_sequence=state.expected_client_sequence, payload=b'', payload_bits=0,
            **changes)
        return replace(self.template,
            sequence=(transport.in_sequence + 1) & 16383 if sequence is None else sequence,
            acknowledged_sequence=(transport.out_sequence - 1) & 16383 if ack is None else ack,
            history=history, bunches=(bunch,))

    def raw(self, packet, peer=PEER, now=0.2):
        return self.connection.handle(b'opaque!!' + encode_observed_application(packet,
            max_packet_bytes=1024, received_by_server=True), peer, now)

    def test_joined_close_stops_control_and_actor_without_fabricating_delivery(self):
        state = self.connection.control_peers[PEER]
        self.connection._queue(state, 1, state.welcome_payload)
        event, response = self.raw(self.close_packet())
        self.assertEqual(event, 'control_client_close_consumed')
        self.assertEqual(delivery.decode(response).bunches, ())
        state = self.connection.control_peers[PEER]
        self.assertTrue(state.client_closed)
        self.assertEqual((state.client_close_sequence, state.client_close_reason), (236, 0))
        self.assertEqual(state.expected_client_sequence, 237)
        self.assertIsNone(state.pending)
        self.assertEqual(state.actor_exports, {})
        self.assertNotIn(self.ticket.cookie, self.connection.ticket_peers)
        self.assertEqual(self.connection.poll(10), [])
        summary = self.connection.summary()
        self.assertEqual(summary['initial_actor_delivery_acks'], 0)
        self.assertEqual(summary['initial_actor_channels_pending'], 0)
        self.assertEqual(summary['initial_actor_channels_cancelled_by_client_close'], 1)
        self.assertNotIn('control_login_or_order_rejected', summary['events'])

    def test_reliable_close_retry_is_idempotent_and_acknowledged(self):
        packet = self.close_packet()
        _, ack = self.raw(packet)
        ack = delivery.decode(ack)
        retry = replace(packet, sequence=packet.sequence + 1, acknowledged_sequence=ack.sequence)
        event, response = self.raw(retry, now=0.3)
        self.assertEqual(event, 'control_client_close_retry_consumed')
        self.assertEqual(delivery.decode(response).bunches, ())
        self.assertEqual(self.connection.summary()['client_closed_peers'], 1)
        self.assertEqual(self.connection.control_events['control_client_close_consumed'], 1)
        self.assertEqual(self.connection.control_peers[PEER].expected_client_sequence, 237)
        self.assertEqual(self.connection.poll(10), [])
        # A byte-identical UDP duplicate cannot advance state or close again.
        self.assertEqual(self.raw(retry)[0], 'application_sequence_rejected')

    def test_out_of_order_close_does_not_commit_its_actor_ack(self):
        for offset in (-1, 1):
            with self.subTest(offset=offset):
                self.setUp()
                packet = self.close_packet(history=(1,))
                bunch = replace(packet.bunches[0], channel_sequence=236 + offset)
                event, response = self.raw(replace(packet, bunches=(bunch,)))
                self.assertEqual((event, response), ('control_close_rejected', None))
                self.assertFalse(self.connection.control_peers[PEER].client_closed)
                self.assertEqual(self.connection.summary()['initial_actor_delivery_acks'], 0)
                self.assertEqual(len(self.connection.poll(0.8)), 1)

    def test_nonempty_open_partial_or_wrong_channel_close_is_rejected(self):
        changes = ({'payload': b'\x09', 'payload_bits': 8}, {'open': True},
                   {'partial': True, 'partial_initial': True, 'partial_final': True},
                   {'channel_index': 1}, {'reliable': False, 'channel_sequence': None,
                                          'channel_name': None})
        for fields in changes:
            with self.subTest(fields=tuple(fields)):
                self.setUp()
                packet = self.close_packet()
                packet = replace(packet, bunches=(replace(packet.bunches[0], **fields),))
                event, response = self.raw(packet)
                self.assertEqual((event, response), ('control_close_rejected', None))
                self.assertFalse(self.connection.control_peers[PEER].client_closed)

    def test_close_before_join_is_rejected(self):
        self.connection.control_peers[PEER].client_join_observed = False
        event, response = self.raw(self.close_packet())
        self.assertEqual((event, response), ('control_close_rejected', None))
        self.assertFalse(self.connection.control_peers[PEER].client_closed)
        self.assertEqual(self.connection.ticket_peers[self.ticket.cookie], PEER)

    def test_foreign_peer_cannot_close_any_ticket(self):
        event, response = self.raw(self.close_packet(), OTHER)
        self.assertEqual((event, response), ('application_without_verified_echo', None))
        self.assertFalse(self.connection.control_peers[PEER].client_closed)
        self.assertEqual(self.connection.ticket_peers[self.ticket.cookie], PEER)

    def test_other_joined_peer_and_its_ticket_remain_active(self):
        other_ticket = self.connection.admissions.issue(102, 202, 2201, 142201103)
        self.connection.register_verified_echo(OTHER, COOKIE)
        self.connection.handle(b'opaque!!' + HELLO_BODIES[0], OTHER, 0)
        for sequence, ack, chseq, payload in (
                (1257, 216, 234, login_payload(other_ticket)),
                (1258, 217, 235, encode_message(4, 25000) + encode_message(9))):
            bunch = replace(self.template.bunches[0], open=False, channel_sequence=chseq,
                            payload=payload, payload_bits=len(payload) * 8)
            self.raw(replace(self.template, sequence=sequence, acknowledged_sequence=ack,
                            history=(1,), bunches=(bunch,)), OTHER)
        self.connection.queue_actor_open(OTHER, **delivery.actor_fields())
        self.raw(self.close_packet())
        self.assertEqual(self.connection.ticket_peers, {other_ticket.cookie: OTHER})
        self.assertFalse(self.connection.control_peers[OTHER].client_closed)
        self.assertEqual([peer for peer, _, _ in self.connection.poll(1)], [OTHER])

    def test_cleanup_does_not_delete_a_replaced_ticket_binding(self):
        self.connection.ticket_peers[self.ticket.cookie] = OTHER
        self.raw(self.close_packet())
        self.assertEqual(self.connection.ticket_peers[self.ticket.cookie], OTHER)

    def test_closed_peer_cannot_restart_control_or_queue_actors(self):
        self.raw(self.close_packet())
        closed = self.connection.control_peers[PEER]
        transport = self.connection.peers[PEER]
        bunch = replace(self.template.bunches[0], open=False, channel_sequence=234,
                        payload=login_payload(self.ticket), payload_bits=len(login_payload(self.ticket)) * 8)
        packet = replace(self.template, sequence=transport.in_sequence + 1,
                         acknowledged_sequence=transport.out_sequence - 1, bunches=(bunch,))
        self.assertEqual(self.raw(packet), ('application_after_client_close', None))
        self.assertIs(self.connection.control_peers[PEER], closed)
        with self.assertRaisesRegex(ValueError, 'admitted joined'):
            self.connection.queue_actor_open(PEER, **delivery.actor_fields(channel_index=2, actor_guid=4))
        self.connection.register_verified_echo(PEER, COOKIE)
        self.assertTrue(self.connection.control_peers[PEER].client_closed)

    def test_spent_reply_budget_still_commits_close_without_extra_datagram(self):
        transport = self.connection.peers[PEER]
        self.connection.max_replies = transport.replies
        event, response = self.raw(self.close_packet())
        self.assertEqual((event, response), ('control_client_close_consumed', None))
        self.assertTrue(self.connection.control_peers[PEER].client_closed)
        self.assertEqual(transport.replies, self.connection.max_replies)
        self.assertEqual(self.connection.poll(10), [])

    def test_mixed_close_and_data_is_atomic_rejection(self):
        packet = self.close_packet(history=(1,))
        data = replace(packet.bunches[0], close=False, channel_sequence=237,
                       payload=b'\x09', payload_bits=8)
        event, response = self.raw(replace(packet, bunches=(*packet.bunches, data)))
        self.assertEqual((event, response), ('control_close_rejected', None))
        self.assertFalse(self.connection.control_peers[PEER].client_closed)
        self.assertEqual(self.connection.summary()['initial_actor_delivery_acks'], 0)

    def test_close_preserves_only_real_actor_delivery_and_late_ack_cannot_add_it(self):
        self.raw(self.close_packet(history=(1,)))
        self.assertEqual(self.connection.summary()['initial_actor_delivery_acks'], 1)
        self.setUp()
        self.raw(self.close_packet(history=(0,)))
        transport = self.connection.peers[PEER]
        packet = replace(self.template, sequence=transport.in_sequence + 1,
            acknowledged_sequence=transport.out_sequence - 1, history=(3,), bunches=())
        self.assertEqual(self.raw(packet), ('application_after_client_close', None))
        self.assertEqual(self.connection.summary()['initial_actor_delivery_acks'], 0)

    def test_conflicting_close_retry_cannot_mutate_the_closed_state(self):
        self.raw(self.close_packet())
        for fields in ({'channel_sequence': 237}, {'close_reason': 1}):
            with self.subTest(fields=fields):
                packet = self.close_packet()
                bunch = replace(packet.bunches[0], channel_sequence=236, **
                                {k: v for k, v in fields.items() if k != 'channel_sequence'})
                if 'channel_sequence' in fields:
                    bunch = replace(bunch, channel_sequence=fields['channel_sequence'])
                event, response = self.raw(replace(packet, bunches=(bunch,)))
                self.assertEqual((event, response), ('control_close_rejected', None))
                self.assertEqual(self.connection.control_peers[PEER].client_close_sequence, 236)
                self.assertEqual(self.connection.poll(10), [])


class ControlCloseBootstrapTests(unittest.TestCase):
    def test_closed_ticket_is_not_a_delivered_set_and_other_peer_survives(self):
        fixture = progress.RegisteredSetProgressTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        connection = fixture.connection
        bunch = replace(fixture.template.bunches[0], open=False, close=True,
                        channel_sequence=236, payload=b'', payload_bits=0)
        packet = replace(fixture.template, sequence=1259, acknowledged_sequence=221,
                         history=(0,), bunches=(bunch,))
        event, _ = connection.handle(b'opaque!!' + encode_observed_application(packet,
            max_packet_bytes=1024, received_by_server=True), PEER, 0.2)
        self.assertEqual(event, 'control_client_close_consumed')
        self.assertEqual(fixture.server.actor_transport_progress['fully_delivered_sets'], 0)
        self.assertEqual(fixture.server.actor_transport_progress['delivery_acks'], 0)
        registration = fixture.server._registered_bootstraps[fixture.ticket.cookie]
        self.assertEqual(registration['status'], 'client_closed')
        self.assertEqual(fixture.server._bootstrap_events['client_closed_sets'], 1)
        self.assertEqual({peer for peer, _, _ in connection.poll(1)}, {OTHER})
        fixture._send(OTHER, 1259, 221, history=(7,))
        self.assertEqual(fixture.server.actor_transport_progress['fully_delivered_sets'], 1)

    def test_close_after_encoding_discards_both_control_and_actor_datagrams(self):
        fixture = bootstrap.BootstrapLifetimeTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        connection, server = fixture.connection, fixture.server
        server._started_at = time.monotonic() - 1
        state = connection.control_peers[PEER]
        connection._queue(state, 1, state.welcome_payload)
        template = decode_observed_application(HELLO_BODIES[0],
            max_packet_bytes=1024, received_by_server=True)
        original_expire = server._handshake._expire
        calls = [0]

        def close_after_poll(now):
            original_expire(now)
            calls[0] += 1
            if calls[0] == 3:  # Batch is encoded, but no send has occurred.
                state, transport = connection.control_peers[PEER], connection.peers[PEER]
                bunch = replace(template.bunches[0],
                    open=False, close=True, payload=b'', payload_bits=0,
                    channel_sequence=state.expected_client_sequence)
                packet = replace(template, sequence=(transport.in_sequence + 1) & 16383,
                    acknowledged_sequence=(transport.out_sequence - 1) & 16383,
                    history=(0,), bunches=(bunch,))
                event, _ = connection.handle(b'opaque!!' + encode_observed_application(packet,
                    max_packet_bytes=1024, received_by_server=True), PEER, now)
                self.assertEqual(event, 'control_client_close_consumed')

        original_socket = server._udp
        server._udp = Mock()
        self.addCleanup(original_socket.close)
        with patch.object(server._handshake, '_expire', side_effect=close_after_poll):
            server._send_control_retries()
        server._udp.sendto.assert_not_called()
        self.assertEqual(connection.control_events['stale_control_datagrams_discarded'], 1)
        self.assertEqual(server._bootstrap_events['stale_actor_datagrams_discarded'], 1)
        self.assertEqual(server._actor_open_sent, 0)
        self.assertEqual(connection.summary()['initial_actor_delivery_acks'], 0)


if __name__ == '__main__':
    unittest.main()
