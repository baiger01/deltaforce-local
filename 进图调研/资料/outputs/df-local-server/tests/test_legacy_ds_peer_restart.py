"""Authenticated source-port migration fixtures; no client/process/socket I/O."""
from dataclasses import asdict, replace
import unittest
from unittest.mock import patch

from dfserver.legacy_ds_control_fields import encode_message
from dfserver.legacy_ds_handshake_probe import LegacyDSHandshakeProbe
from dfserver.legacy_ds_wire_codec import decode_observed_application, encode_observed_application
from dfserver.unreal_handshake_payload import decode_payload, encode_payload
from tests.test_legacy_ds_restart_handshake import (
    RestartFlowFixture, RestartControlActorIntegrationTests, INITIAL, RESTART_INITIAL,
    PREFIX, FRESH_COOKIE, NET_VERSION,
)
from tests.test_legacy_ds_control_probe import COOKIE, PEER


NEW_PEER = ('127.0.0.1', PEER[1] + 1)
NEXT_PEER = ('127.0.0.1', PEER[1] + 2)
THIRD_PEER = ('127.0.0.1', PEER[1] + 3)


class PeerRestartTests(RestartFlowFixture, unittest.TestCase):
    setup_joined = RestartControlActorIntegrationTests.setup_joined

    def send(self, payload=None, *, now, peer=PEER, history=(1,), close=False):
        transport, state = self.connection.peers[peer], self.connection.control_peers[peer]
        bunches = ()
        if payload is not None or close:
            bunches = (replace(self.template.bunches[0], open=not state.hello_received,
                close=close, channel_sequence=state.expected_client_sequence,
                payload=payload or b'', payload_bits=len(payload or b'') * 8),)
        packet = replace(self.template, sequence=(transport.in_sequence + 1) & 16383,
            acknowledged_sequence=(transport.out_sequence - 1) & 16383,
            history=history, bunches=bunches)
        return self.probe.handle(PREFIX + encode_observed_application(packet,
            max_packet_bytes=1024, received_by_server=True), peer, now)

    def start_peer_restart(self, peer=NEW_PEER, now=1.0):
        with patch('dfserver.legacy_ds_handshake_probe.secrets.token_bytes', return_value=FRESH_COOKIE):
            result = self.probe.handle(RESTART_INITIAL, peer, now)
        self.assertEqual(result.event, 'restart_peer_challenge_reply_prepared')
        value = decode_payload(result.response)
        return PREFIX + encode_payload(replace(value, restart=True, old_cookie=COOKIE))

    def migrate(self, *, peer=NEW_PEER, now=1.0):
        echo = self.start_peer_restart(peer, now)
        result = self.probe.handle(echo, peer, now + 0.1)
        self.assertEqual(result.event, 'valid_restart_peer_echo_ack_prepared')
        return echo, result

    def test_initial_nonce_has_no_owner_and_changes_no_session_activity(self):
        self.setup_joined()
        generation = self.probe.pending[PEER]
        transport, control = self.connection.peers[PEER], self.connection.control_peers[PEER]
        before = asdict(generation), asdict(transport), asdict(control)
        echo = self.start_peer_restart()
        self.assertNotIn(NEW_PEER, self.probe.pending)
        self.assertNotIn(NEW_PEER, self.connection.peers)
        self.assertNotIn(NEW_PEER, self.connection.control_peers)
        self.assertIsNone(self.probe.peer_restart_pending[NEW_PEER].generation)
        self.assertEqual(self.connection.ticket_peers[self.ticket.cookie], PEER)
        self.assertEqual((asdict(generation), asdict(transport), asdict(control)), before)
        # Another source cannot consume this challenge even with the old cookie.
        self.assertIsNone(self.probe.handle(echo, NEXT_PEER, 1.05).response)

    def test_join_actor_exact_ack_retry_and_all_object_identities_survive_migration(self):
        self.setup_joined()
        generation, transport = self.probe.pending[PEER], self.connection.peers[PEER]
        control = self.connection.control_peers[PEER]
        actor = control.actor_opens[4]
        before = asdict(transport), asdict(control), generation.issued_at, generation.verified_at
        authorized = self.connection.admissions.summary()['authorized_login_count']
        with patch.object(self.connection, 'register_verified_echo') as register, \
                patch.object(self.connection, 'forget_peer') as forget:
            _, result = self.migrate()
        self.assertEqual(result.rebound_from_peer, PEER)
        self.assertEqual(len(result.response), 25)
        self.assertEqual(decode_payload(result.response).cookie, COOKIE)
        register.assert_not_called()
        forget.assert_not_called()
        self.assertNotIn(PEER, self.probe.pending)
        self.assertNotIn(PEER, self.connection.peers)
        self.assertNotIn(PEER, self.connection.control_peers)
        self.assertIs(self.probe.pending[NEW_PEER], generation)
        self.assertIs(self.connection.peers[NEW_PEER], transport)
        self.assertIs(self.connection.control_peers[NEW_PEER], control)
        self.assertIs(control.actor_opens[4], actor)
        self.assertIs(control.ticket, self.ticket)
        self.assertEqual((asdict(transport), asdict(control), generation.issued_at,
                          generation.verified_at), before)
        self.assertEqual(generation.last_valid_activity_at, 1.1)
        self.assertEqual(self.connection.ticket_peers[self.ticket.cookie], NEW_PEER)
        self.assertEqual(self.connection.joined_count, 1)
        self.assertEqual(self.connection.admissions.summary()['authorized_login_count'], authorized)
        retry = self.probe.poll(1.2)
        self.assertEqual(len(retry), 1)
        self.assertEqual(retry[0][0], NEW_PEER)
        body = decode_observed_application(retry[0][2], max_packet_bytes=1024,
                                          received_by_server=False)
        self.assertEqual(body.sequence, (self.first_actor.sequence + 1) & 16383)
        self.assertEqual(body.bunches[0], self.first_actor.bunches[0])
        self.assertEqual(actor.transmissions, 2)
        self.assertIsNone(self.send(now=1.3, peer=NEW_PEER, history=(1 << 10,)).response)
        self.assertEqual(self.connection.summary()['initial_actor_delivery_acks'], 0)
        self.assertIsNone(self.send(now=1.4, peer=NEW_PEER, history=(1,)).response)
        self.assertEqual(self.connection.summary()['initial_actor_delivery_acks'], 1)
        self.assertEqual(self.probe.poll(2.0), [])

    def test_already_encoded_timer_reply_resolves_new_owner_without_consuming_again(self):
        self.setup_joined()
        generation = self.probe.pending[PEER]
        retries = self.probe.poll(0.7)
        before_seq = self.connection.peers[PEER].out_sequence
        before_transmissions = self.connection.control_peers[PEER].actor_opens[4].transmissions
        self.assertEqual(retries[0][0], PEER)
        encoded = retries[0][2]
        self.migrate()
        self.assertEqual(self.probe.current_peer_for_generation(generation, self.ticket), NEW_PEER)
        self.assertEqual(self.connection.peers[NEW_PEER].out_sequence, before_seq)
        self.assertEqual(self.connection.control_peers[NEW_PEER].actor_opens[4].transmissions,
                         before_transmissions)
        # The immutable saved response is still the same packet/bunch delivery.
        self.assertEqual(decode_observed_application(encoded, max_packet_bytes=1024,
            received_by_server=False).bunches[0], self.first_actor.bunches[0])

    def test_retired_port_cannot_replay_handshakes_or_ack_or_migrate_back(self):
        self.setup_joined()
        old_transport = self.connection.peers[PEER]
        old_packet = replace(self.template, sequence=(old_transport.in_sequence + 1) & 16383,
            acknowledged_sequence=(old_transport.out_sequence - 1) & 16383,
            history=(1,), bunches=())
        old_application = PREFIX + encode_observed_application(old_packet,
            max_packet_bytes=1024, received_by_server=True)
        echo, _ = self.migrate()
        generation = self.probe.pending[NEW_PEER]
        for datagram in (INITIAL, RESTART_INITIAL, echo, old_application):
            with self.subTest(shape=len(datagram)):
                result = self.probe.handle(datagram, PEER, 1.2)
                self.assertEqual((result.event, result.response), ('retired_peer_rejected', None))
        self.assertEqual(generation.last_valid_activity_at, 1.1)
        self.assertEqual(self.connection.summary()['initial_actor_delivery_acks'], 0)
        self.assertIsNone(self.probe.current_peer_for_generation(generation, object()))

    def test_completed_duplicate_and_zero_initial_never_refresh_session_or_nonce(self):
        self.setup_joined()
        echo, result = self.migrate()
        original = self.probe.pending[NEW_PEER]
        nonce = self.probe.peer_restart_pending[NEW_PEER]
        issued = nonce.issued_at
        repeated = self.probe.handle(echo, NEW_PEER, 1.2)
        self.assertEqual(repeated.response, result.response)
        self.assertEqual(repeated.rebound_from_peer, PEER)
        self.assertEqual(repeated.event, 'restart_peer_echo_retry_ack_prepared')
        initial = self.probe.handle(RESTART_INITIAL, NEW_PEER, 1.3)
        self.assertEqual(decode_payload(initial.response).cookie, FRESH_COOKIE)
        self.assertEqual(self.probe.handle(echo, NEW_PEER, 1.4).response, result.response)
        self.assertEqual(original.last_valid_activity_at, 1.1)
        self.assertEqual(nonce.issued_at, issued)

    def test_old_fresh_cookie_time_or_third_flag_mismatch_cannot_commit(self):
        self.setup_joined()
        echo = self.start_peer_restart()
        original = self.probe.pending[PEER]
        nonce = self.probe.peer_restart_pending[NEW_PEER]
        before = asdict(original), asdict(nonce), dict(self.connection.ticket_peers)
        value = decode_payload(echo[8:])
        invalid = (replace(value, cookie=bytes(20)), replace(value, old_cookie=bytes(20)),
                   replace(value, timestamp=2), replace(value, third_flag=True))
        for candidate in invalid:
            with self.subTest(candidate=candidate.third_flag):
                self.assertIsNone(self.probe.handle(PREFIX + encode_payload(candidate),
                                                  NEW_PEER, 1.1).response)
        self.assertEqual((asdict(original), asdict(nonce), dict(self.connection.ticket_peers)), before)
        self.assertNotIn(NEW_PEER, self.probe.pending)

    def test_expired_inactive_wrong_ticket_owner_and_closed_source_cannot_migrate(self):
        for reason in ('inactive', 'wrong_owner', 'closed', 'absolute_expired', 'idle_expired'):
            with self.subTest(reason=reason):
                self.setup_joined()
                echo = self.start_peer_restart()
                original = self.probe.pending[PEER]
                now = 1.1
                if reason == 'inactive':
                    self.clock[0] = 120
                elif reason == 'wrong_owner':
                    self.connection.ticket_peers[self.ticket.cookie] = THIRD_PEER
                elif reason == 'closed':
                    self.assertEqual(self.send(close=True, now=1.05, history=(0,)).event,
                                     'control_client_close_consumed')
                elif reason == 'absolute_expired':
                    self.probe.verified_session_ttl = 1
                else:
                    self.probe.verified_idle_ttl = 1
                activity = original.last_valid_activity_at
                result = self.probe.handle(echo, NEW_PEER, now)
                self.assertIsNone(result.response)
                self.assertIsNone(result.rebound_from_peer)
                self.assertNotIn(NEW_PEER, self.probe.pending)
                self.assertEqual(original.last_valid_activity_at, activity)

    def test_duplicate_old_cookie_is_ambiguous_even_with_invalid_other_owner(self):
        self.setup_joined()
        echo = self.start_peer_restart()
        self.probe.pending[THIRD_PEER] = replace(self.probe.pending[PEER])
        result = self.probe.handle(echo, NEW_PEER, 1.1)
        self.assertEqual((result.event, result.response), ('restart_old_cookie_ambiguous', None))
        self.assertEqual(self.connection.ticket_peers[self.ticket.cookie], PEER)

    def test_concurrent_old_nonce_refused_but_fresh_later_port_can_migrate_again(self):
        self.setup_joined()
        original = self.probe.pending[PEER]
        first = self.start_peer_restart(NEW_PEER, 1)
        concurrent = self.start_peer_restart(NEXT_PEER, 1.01)
        self.assertIsNotNone(self.probe.handle(first, NEW_PEER, 1.1).response)
        result = self.probe.handle(concurrent, NEXT_PEER, 1.2)
        self.assertEqual(result.event, 'restart_candidate_predates_migration')
        self.assertIsNone(result.response)
        self.assertEqual(self.connection.ticket_peers[self.ticket.cookie], NEW_PEER)
        later = self.start_peer_restart(THIRD_PEER, 1.3)
        second = self.probe.handle(later, THIRD_PEER, 1.4)
        self.assertEqual(second.rebound_from_peer, NEW_PEER)
        self.assertIs(self.probe.pending[THIRD_PEER], original)
        self.assertEqual(original.verified_at, 0.01)
        self.assertEqual(original.issued_at, 0)
        self.assertEqual(set(self.probe.retired_peers), {PEER, NEW_PEER})
        self.assertNotIn(NEW_PEER, self.probe.peer_restart_pending)
        self.assertEqual(self.connection.joined_count, 1)

    def test_unverified_packet_only_or_prelogin_control_cannot_migrate(self):
        probe, _ = self.verified()
        self.assertIsNone(probe.handle(RESTART_INITIAL, NEW_PEER, 1).response)
        probe, _ = self.verified(control_probe=True, expected_net_version=NET_VERSION)
        self.assertIsNone(probe.handle(RESTART_INITIAL, NEW_PEER, 1).response)
        self.setup_joined()
        state = self.connection.control_peers[PEER]
        state.ticket = None
        self.assertIsNone(self.probe.handle(RESTART_INITIAL, NEW_PEER, 1).response)
        self.assertEqual(self.probe.peer_restart_pending, {})

    def test_candidate_and_retired_port_capacities_fail_closed_without_eviction(self):
        self.setup_joined()
        self.probe.max_restart_candidates = 1
        first = self.start_peer_restart()
        self.assertEqual(self.probe.handle(RESTART_INITIAL, NEXT_PEER, 1.01).event,
                         'restart_candidate_limit_reached')
        self.probe.handle(first, NEW_PEER, 1.1)
        self.probe.max_restart_candidates = 2
        self.probe.max_retired_peers = 1
        second = self.start_peer_restart(NEXT_PEER, 1.3)
        result = self.probe.handle(second, NEXT_PEER, 1.4)
        self.assertEqual(result.event, 'restart_retired_peer_limit_reached')
        self.assertIsNone(result.response)
        self.assertEqual(self.connection.ticket_peers[self.ticket.cookie], NEW_PEER)
        self.assertEqual(set(self.probe.retired_peers), {PEER})

    def test_candidate_ttl_and_original_absolute_deadline_are_not_extended(self):
        self.setup_joined()
        self.probe.ttl = 1
        self.probe.verified_session_ttl = 4
        self.probe.verified_idle_ttl = 4
        echo = self.start_peer_restart(now=1)
        self.assertIsNone(self.probe.handle(echo, NEW_PEER, 2).response)
        self.assertIn(PEER, self.probe.pending)
        self.assertNotIn(NEW_PEER, self.probe.peer_restart_pending)
        echo, _ = self.migrate(peer=NEXT_PEER, now=2.1)
        generation = self.probe.pending[NEXT_PEER]
        self.assertEqual(self.probe.retired_peers[PEER].absolute_expiry, 4.01)
        # A valid restart refreshed idle activity once, not the original lifetime.
        self.assertEqual(generation.verified_at, 0.01)
        self.assertIsNone(self.probe.handle(echo, NEXT_PEER, 4.011).response)
        self.assertNotIn(NEXT_PEER, self.probe.pending)
        self.assertNotIn(PEER, self.probe.retired_peers)
        self.assertEqual(self.connection.ticket_peers, {})

    def test_occupied_destination_and_foreign_ticket_binding_do_not_overwrite(self):
        self.setup_joined()
        echo = self.start_peer_restart()
        occupied = object()
        self.connection.peers[NEW_PEER] = occupied
        result = self.probe.handle(echo, NEW_PEER, 1.1)
        self.assertEqual(result.event, 'restart_destination_occupied')
        self.assertIs(self.connection.peers[NEW_PEER], occupied)
        self.connection.peers.pop(NEW_PEER)
        self.connection.ticket_peers['unrelated-ticket'] = NEW_PEER
        result = self.probe.handle(echo, NEW_PEER, 1.2)
        self.assertEqual(result.event, 'restart_transport_rebind_rejected')
        self.assertIn(PEER, self.probe.pending)
        self.assertEqual(self.connection.ticket_peers[self.ticket.cookie], PEER)
        self.assertFalse(self.probe.peer_restart_pending[NEW_PEER].completed)

    def test_query_supports_only_exact_unambiguous_generation_and_ticket(self):
        self.setup_joined()
        generation = self.probe.pending[PEER]
        self.assertEqual(self.probe.current_peer_for_generation(generation, self.ticket), PEER)
        self.assertIsNone(self.probe.current_peer_for_generation(None, self.ticket))
        self.assertIsNone(self.probe.current_peer_for_generation(generation, None))
        self.connection.control_peers[PEER].ticket = None
        self.assertEqual(self.probe.current_peer_for_generation(generation, None), PEER)
        self.assertIsNone(self.probe.current_peer_for_generation(generation, self.ticket))
        self.probe.pending[NEW_PEER] = generation
        self.assertIsNone(self.probe.current_peer_for_generation(generation, None))

    def test_close_after_rebind_cancels_retry_recovery_and_current_owner(self):
        self.setup_joined()
        echo, _ = self.migrate()
        generation = self.probe.pending[NEW_PEER]
        self.assertEqual(self.send(close=True, now=1.2, peer=NEW_PEER, history=(0,)).event,
                         'control_client_close_consumed')
        activity = generation.last_valid_activity_at
        self.assertEqual(self.probe.handle(echo, NEW_PEER, 1.3).event, 'restart_client_closed')
        self.assertIsNone(self.probe.handle(RESTART_INITIAL, NEXT_PEER, 1.4).response)
        self.assertIsNone(self.probe.current_peer_for_generation(generation, self.ticket))
        self.assertEqual(self.probe.poll(1.5), [])
        self.assertEqual(generation.last_valid_activity_at, activity)
        self.assertNotIn(self.ticket.cookie, self.connection.ticket_peers)

    def test_capacity_types_and_nonloopback_restart_are_refused(self):
        for kwargs in ({'max_restart_candidates': True}, {'max_restart_candidates': 33},
                       {'max_retired_peers': 0}, {'max_retired_peers': 513}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                LegacyDSHandshakeProbe(**kwargs)
        self.setup_joined()
        echo = self.start_peer_restart()
        for peer in (('127.0.0.2', NEW_PEER[1]), ('0.0.0.0', NEW_PEER[1]),
                     ('127.0.0.1', True), ('127.0.0.1', 0)):
            with self.subTest(peer=peer):
                self.assertEqual(self.probe.handle(echo, peer, 1.1).event,
                                 'non_loopback_peer_rejected')
        self.assertNotIn(NEW_PEER, self.probe.pending)
