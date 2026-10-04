"""Control/session lifecycle checks without a native client or privileged I/O."""
from dataclasses import replace
import unittest
from unittest.mock import patch

from dfserver.legacy_ds_control_connection import LegacyDSControlConnection
from dfserver.legacy_ds_control_fields import encode_message
from dfserver.legacy_ds_handshake_probe import LegacyDSHandshakeProbe
from dfserver.legacy_ds_match_admission import LocalMatchAdmissions
from dfserver.legacy_ds_packet_ack_probe import MASK
from dfserver.legacy_ds_wire_codec import decode_observed_application, encode_observed_application
from tests.test_legacy_ds_control_connection import MAPS, login_payload
from tests.test_legacy_ds_control_probe import COOKIE, PEER
from tests.test_legacy_ds_wire_codec import HELLO_BODIES


OTHER_PEER = ('127.0.0.1', PEER[1] + 1)
INITIAL = b'opaque!!' + b'\x01' + bytes(23) + b'\x08'
NET_VERSION = 1077088301


class NativeControlLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.admissions = LocalMatchAdmissions(clock=lambda: 0.0)
        self.ticket = self.admissions.issue(101, 201, 2201, 142201103, 88000000025)
        self.template = decode_observed_application(HELLO_BODIES[0],
            max_packet_bytes=1024, received_by_server=True)

    def connection(self, **kwargs):
        connection = LegacyDSControlConnection(admissions=self.admissions,
            welcome_maps=MAPS, expected_net_version=NET_VERSION, **kwargs)
        connection.register_verified_echo(PEER, COOKIE)
        return connection

    def handshake(self, **kwargs):
        return LegacyDSHandshakeProbe(packet_ack_probe=True, control_probe=True,
            control_admissions=self.admissions, control_welcome_maps=MAPS,
            expected_net_version=NET_VERSION, **kwargs)

    def verify_handshake(self, handshake, peer=PEER, cookie=COOKIE):
        with patch('dfserver.legacy_ds_handshake_probe.secrets.token_bytes', return_value=cookie):
            challenge = handshake.handle(INITIAL, peer, 0.0).response
        echo = b'opaque!!' + challenge
        self.assertEqual(handshake.handle(echo, peer, 0.01).event,
                         'valid_challenge_echo_ack_prepared')
        return echo

    def packet(self, connection, peer, payload=None, *, history=(1,), channel_sequence=None):
        transport, state = connection.peers[peer], connection.control_peers[peer]
        bunches = ()
        if payload is not None:
            bunches = (replace(self.template.bunches[0],
                open=not state.hello_received,
                channel_sequence=(state.expected_client_sequence
                                  if channel_sequence is None else channel_sequence),
                payload=payload, payload_bits=len(payload) * 8),)
        return replace(self.template, sequence=(transport.in_sequence + 1) & MASK,
            acknowledged_sequence=(transport.out_sequence - 1) & MASK,
            history=history, bunches=bunches)

    @staticmethod
    def datagram(packet):
        return b'opaque!!' + encode_observed_application(packet,
            max_packet_bytes=1024, received_by_server=True)

    @staticmethod
    def decode(response):
        return decode_observed_application(response,
            max_packet_bytes=1024, received_by_server=False)

    def send(self, connection, peer, payload=None, *, now=1.0, handshake=None,
             history=(1,), channel_sequence=None):
        data = self.datagram(self.packet(connection, peer, payload,
            history=history, channel_sequence=channel_sequence))
        if handshake is not None:
            decision = handshake.handle(data, peer, now)
            return decision.event, decision.response
        return connection.handle(data, peer, now)

    def login(self, connection, peer=PEER, *, handshake=None, now=1.0):
        event, _ = self.send(connection, peer, encode_message(0, 1, NET_VERSION, ''),
                             now=now, handshake=handshake)
        self.assertEqual(event, 'control_hello_challenge_prepared')
        event, response = self.send(connection, peer, login_payload(self.ticket),
                                   now=now + 0.1, handshake=handshake)
        self.assertEqual(event, 'control_login_welcome_prepared')
        return response

    def test_same_ticket_rejects_other_peer_until_owner_is_forgotten(self):
        connection = self.connection()
        connection.register_verified_echo(OTHER_PEER, COOKIE)
        self.login(connection)
        self.send(connection, OTHER_PEER, encode_message(0, 1, NET_VERSION, ''), now=1.2)
        event, response = self.send(connection, OTHER_PEER, login_payload(self.ticket), now=1.3)
        self.assertEqual((event, response), ('control_login_or_order_rejected', None))
        self.assertIsNone(connection.control_peers[OTHER_PEER].ticket)
        self.assertEqual(connection.ticket_peers.get(self.ticket.cookie), PEER)
        connection.forget_peer(PEER)
        self.assertFalse(self.ticket.cookie in connection.ticket_peers)
        self.assertFalse(PEER in connection.control_peers or PEER in connection.peers)
        # The refused packet advanced transport sequence, not reliable Login sequence.
        event, response = self.send(connection, OTHER_PEER, login_payload(self.ticket), now=1.4)
        self.assertEqual(event, 'control_login_welcome_prepared')
        self.assertIsNotNone(response)
        self.assertEqual(connection.ticket_peers.get(self.ticket.cookie), OTHER_PEER)

    def test_forgetting_refused_peer_does_not_release_owner_binding(self):
        connection = self.connection()
        connection.register_verified_echo(OTHER_PEER, COOKIE)
        self.login(connection)
        self.send(connection, OTHER_PEER, encode_message(0, 1, NET_VERSION, ''), now=1.2)
        self.send(connection, OTHER_PEER, login_payload(self.ticket), now=1.3)
        connection.forget_peer(OTHER_PEER)
        self.assertEqual(connection.ticket_peers.get(self.ticket.cookie), PEER)
        self.assertIs(connection.control_peers[PEER].ticket, self.ticket)

    def test_idle_expiry_poll_clears_binding_before_outbox_retransmission(self):
        handshake = self.handshake(verified_session_ttl=5, verified_idle_ttl=2)
        self.verify_handshake(handshake)
        connection = handshake.packet_ack_probe
        self.login(connection, handshake=handshake)
        self.assertIsNotNone(connection.control_peers[PEER].pending)
        expiry = handshake.pending[PEER].last_valid_activity_at + 2
        self.assertEqual(handshake.poll(expiry), [])
        self.assertFalse(PEER in handshake.pending or PEER in connection.peers)
        self.assertFalse(PEER in connection.control_peers)
        self.assertFalse(self.ticket.cookie in connection.ticket_peers)
        self.assertEqual(handshake.poll(expiry + 10), [])
        self.assertIs(self.admissions.authorize_login_url(
            '/Map?Cookie=' + self.ticket.cookie + '?PlayerId=101?DSRoomId=201?MapId=2201'),
            self.ticket)

    def test_timed_retransmissions_never_refresh_client_activity(self):
        handshake = self.handshake(verified_session_ttl=10, verified_idle_ttl=2)
        self.verify_handshake(handshake)
        connection = handshake.packet_ack_probe
        first = self.decode(self.login(connection, handshake=handshake))
        activity = handshake.pending[PEER].last_valid_activity_at
        for now in (1.61, 2.12, 2.63):
            responses = handshake.poll(now)
            self.assertEqual(len(responses), 1)
            self.assertEqual(responses[0][1], 'control_timer_retransmit_prepared')
            retry = self.decode(responses[0][2])
            self.assertEqual(retry.bunches[0].channel_sequence, first.bunches[0].channel_sequence)
            self.assertEqual(retry.bunches[0].payload, first.bunches[0].payload)
            self.assertEqual(handshake.pending[PEER].last_valid_activity_at, activity)
        self.assertEqual(handshake.poll(activity + 2), [])
        self.assertFalse(self.ticket.cookie in connection.ticket_peers)

    def test_valid_ack_only_refreshes_activity_and_clears_delivered_outbox(self):
        handshake = self.handshake(verified_session_ttl=10, verified_idle_ttl=2)
        self.verify_handshake(handshake)
        connection = handshake.packet_ack_probe
        self.login(connection, handshake=handshake)
        replies = connection.peers[PEER].replies
        event, response = self.send(connection, PEER, now=2.9, handshake=handshake)
        self.assertEqual((event, response), ('control_ack_only_consumed', None))
        self.assertEqual(handshake.pending[PEER].last_valid_activity_at, 2.9)
        self.assertEqual(connection.peers[PEER].replies, replies)
        self.assertIsNone(connection.control_peers[PEER].pending)
        self.assertEqual(handshake.poll(3.2), [])
        self.assertTrue(PEER in handshake.pending)
        self.assertEqual(handshake.poll(4.91), [])
        self.assertFalse(PEER in handshake.pending)
        self.assertFalse(self.ticket.cookie in connection.ticket_peers)

    def test_valid_activity_cannot_extend_absolute_session_lifetime(self):
        handshake = self.handshake(verified_session_ttl=5, verified_idle_ttl=3)
        self.verify_handshake(handshake)
        connection = handshake.packet_ack_probe
        self.login(connection, handshake=handshake)
        for now in (2.9, 4.8):
            event, response = self.send(connection, PEER, now=now, handshake=handshake)
            self.assertEqual((event, response), ('control_ack_only_consumed', None))
        self.assertEqual(handshake.pending[PEER].last_valid_activity_at, 4.8)
        self.assertEqual(handshake.poll(5.02), [])
        self.assertFalse(PEER in handshake.pending)
        self.assertFalse(self.ticket.cookie in connection.ticket_peers)

    def test_replayed_ack_and_invalid_packets_cannot_refresh_activity(self):
        for kind in ('replayed_ack', 'future_ack', 'invalid_payload'):
            with self.subTest(kind=kind):
                handshake = self.handshake(verified_session_ttl=10, verified_idle_ttl=2)
                self.verify_handshake(handshake)
                connection = handshake.packet_ack_probe
                self.login(connection, handshake=handshake)
                packet = self.packet(connection, PEER)
                if kind == 'replayed_ack':
                    handshake.handle(self.datagram(packet), PEER, 1.2)
                elif kind == 'future_ack':
                    packet = replace(packet, acknowledged_sequence=connection.peers[PEER].out_sequence)
                else:
                    packet = self.packet(connection, PEER, b'\xfa')
                activity = handshake.pending[PEER].last_valid_activity_at
                decision = handshake.handle(self.datagram(packet), PEER, 2.8)
                self.assertIsNone(decision.response)
                self.assertEqual(handshake.pending[PEER].last_valid_activity_at, activity)
                self.assertEqual(handshake.poll(activity + 2), [])
                self.assertFalse(self.ticket.cookie in connection.ticket_peers)

    def test_unverified_challenge_retains_its_short_ttl(self):
        handshake = self.handshake(ttl=1, verified_session_ttl=10, verified_idle_ttl=2)
        handshake.handle(INITIAL, PEER, 0.0)
        self.assertTrue(PEER in handshake.pending)
        self.assertEqual(handshake.poll(1), [])
        self.assertFalse(PEER in handshake.pending)
        self.assertFalse(PEER in handshake.packet_ack_probe.control_peers)

    def test_handshake_reply_limit_does_not_reset_admitted_connection(self):
        handshake = self.handshake(max_replies=2, verified_session_ttl=10, verified_idle_ttl=2)
        echo = self.verify_handshake(handshake)
        connection = handshake.packet_ack_probe
        self.login(connection, handshake=handshake)
        pending = connection.control_peers[PEER].pending
        activity = handshake.pending[PEER].last_valid_activity_at
        decision = handshake.handle(echo, PEER, 1.8)
        self.assertEqual((decision.event, decision.response), ('reply_limit_reached', None))
        self.assertIs(connection.control_peers[PEER].pending, pending)
        self.assertIs(connection.control_peers[PEER].ticket, self.ticket)
        self.assertEqual(handshake.pending[PEER].last_valid_activity_at, activity)

    def test_valid_echo_retry_preserves_admission_and_does_not_refresh_activity(self):
        handshake = self.handshake(verified_session_ttl=10, verified_idle_ttl=2)
        echo = self.verify_handshake(handshake)
        connection = handshake.packet_ack_probe
        self.login(connection, handshake=handshake)
        state = connection.control_peers[PEER]
        activity = handshake.pending[PEER].last_valid_activity_at
        decision = handshake.handle(echo, PEER, 1.8)
        self.assertEqual(decision.event, 'valid_challenge_echo_ack_prepared')
        self.assertIsNotNone(decision.response)
        self.assertIs(connection.control_peers[PEER], state)
        self.assertIs(state.ticket, self.ticket)
        self.assertEqual(connection.ticket_peers.get(self.ticket.cookie), PEER)
        self.assertEqual(handshake.pending[PEER].last_valid_activity_at, activity)

    def test_ten_bit_client_and_server_reliable_sequences_wrap(self):
        connection = self.connection()
        connection.forget_peer(PEER)
        cookie = (1022).to_bytes(2, 'little') + (1022).to_bytes(2, 'little') + bytes(16)
        connection.register_verified_echo(PEER, cookie)
        self.assertEqual(connection.control_peers[PEER].expected_client_sequence, 1023)
        event, challenge = self.send(connection, PEER, encode_message(0, 1, NET_VERSION, ''), now=0)
        self.assertEqual(event, 'control_hello_challenge_prepared')
        self.assertEqual(self.decode(challenge).bunches[0].channel_sequence, 1023)
        self.assertEqual(connection.control_peers[PEER].expected_client_sequence, 0)
        event, welcome = self.send(connection, PEER, login_payload(self.ticket), now=0.1)
        self.assertEqual(event, 'control_login_welcome_prepared')
        self.assertEqual(self.decode(welcome).bunches[0].channel_sequence, 0)
        self.assertEqual(connection.control_peers[PEER].expected_client_sequence, 1)
        event, _ = self.send(connection, PEER, encode_message(4, 25000) + encode_message(9), now=0.2)
        self.assertEqual(event, 'control_join_ack_prepared')
        self.assertEqual(connection.control_peers[PEER].expected_client_sequence, 2)

    def test_fourteen_bit_packet_sequences_and_ack_history_wrap(self):
        connection = self.connection()
        connection.forget_peer(PEER)
        cookie = (MASK - 1).to_bytes(2, 'little') + MASK.to_bytes(2, 'little') + bytes(16)
        connection.register_verified_echo(PEER, cookie)
        _, challenge = self.send(connection, PEER, encode_message(0, 1, NET_VERSION, ''), now=0)
        self.assertEqual(self.decode(challenge).sequence, MASK - 1)
        _, welcome = self.send(connection, PEER, login_payload(self.ticket), now=0.1)
        self.assertEqual(self.decode(welcome).sequence, MASK)
        self.assertEqual(connection.peers[PEER].in_sequence, 0)
        self.assertEqual(connection.peers[PEER].history, 3)
        retry = connection.poll(0.61)
        self.assertEqual(len(retry), 1)
        self.assertEqual(self.decode(retry[0][2]).sequence, 0)
        # ACK cursor0/history bit1 delivers original Welcome16383 even when
        # bit0 does not acknowledge its packet0 retransmission.
        event, response = self.send(connection, PEER, history=(2,), now=0.7)
        self.assertEqual((event, response), ('control_ack_only_consumed', None))
        self.assertIsNone(connection.control_peers[PEER].pending)
        self.assertEqual(connection.peers[PEER].acknowledged_out_sequence, 0)
        self.assertEqual(connection.peers[PEER].in_sequence, 1)

    def test_retransmission_cap_never_marks_unacknowledged_control_delivered(self):
        connection = self.connection(max_transmissions=3, retry_interval=0.5)
        self.login(connection)
        self.assertEqual(len(connection.poll(1.61)), 1)
        self.assertEqual(len(connection.poll(2.12)), 1)
        pending = connection.control_peers[PEER].pending
        self.assertEqual(pending.transmissions, 3)
        self.assertEqual(len(pending.sent_packets), 3)
        sequence = pending.channel_sequence
        self.assertEqual(connection.poll(100), [])
        event, response = self.send(connection, PEER, login_payload(self.ticket),
            channel_sequence=(connection.control_peers[PEER].expected_client_sequence - 1) & 1023,
            history=(0,), now=101)
        self.assertEqual(event, 'control_reliable_retry_consumed')
        self.assertEqual(self.decode(response).bunches, ())
        pending = connection.control_peers[PEER].pending
        self.assertEqual((pending.transmissions, pending.channel_sequence), (3, sequence))
        self.assertFalse(connection.summary()['native_connection_completed'])

    def test_reply_limit_bounds_timer_and_reliable_responses_but_not_ack_processing(self):
        connection = self.connection(max_replies=2)
        self.login(connection)
        self.assertEqual(connection.peers[PEER].replies, 2)
        self.assertEqual(connection.poll(100), [])
        state = connection.control_peers[PEER]
        event, response = self.send(connection, PEER, encode_message(4, 25000), now=101)
        self.assertEqual((event, response), ('application_reply_limit_reached', None))
        self.assertIs(connection.control_peers[PEER], state)
        self.assertIsNone(state.netspeed)
        self.assertEqual(connection.peers[PEER].replies, 2)
        event, response = self.send(connection, PEER, now=102)
        self.assertEqual((event, response), ('control_ack_only_consumed', None))
        self.assertIsNone(connection.control_peers[PEER].pending)
        self.assertEqual(connection.peers[PEER].replies, 2)


if __name__ == '__main__':
    unittest.main()
