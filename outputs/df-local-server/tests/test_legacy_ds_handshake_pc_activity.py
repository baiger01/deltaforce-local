"""Real offline admission/RPC codecs; no native client, sockets or process APIs."""
from dataclasses import replace
import unittest

from dfserver.legacy_ds_handshake_probe import LegacyDSHandshakeProbe, PendingChallenge
from dfserver.legacy_ds_wire_codec import encode_observed_application
from tests.test_legacy_ds_control_probe import COOKIE, PEER


class VerifiedPCActivityTests(unittest.TestCase):
    @staticmethod
    def attach(connection):
        handshake = LegacyDSHandshakeProbe(packet_ack_probe=True,
            verified_session_ttl=180, verified_idle_ttl=60)
        # The real fixture connection has already completed its local admission;
        # bind that same transport to an explicitly verified synthetic generation.
        handshake.packet_ack_probe = connection
        handshake.pending[PEER] = PendingChallenge(0.1, COOKIE, 0,
            echoed=True, verified_at=0.1, last_valid_activity_at=0.3)
        return handshake

    @staticmethod
    def startup():
        from tests.test_legacy_ds_pc_startup_rpc import StartupReceiverTests
        fixture = StartupReceiverTests()
        fixture.setUp()
        return fixture, fixture.f.probe

    @staticmethod
    def restart(*, view=False):
        from tests.test_legacy_ds_control_connection import PCRestartLifecycleTests
        fixture = PCRestartLifecycleTests()
        fixture.setUp()
        if view:
            fixture.install_view_target()
        fixture.ready()
        fixture.connection.request_pc_restart(PEER)
        fixture.connection.poll(1.6)
        return fixture, fixture.connection

    @staticmethod
    def datagram(connection, template, bunches=(), **changes):
        transport = connection.peers[PEER]
        packet = replace(template, sequence=(transport.in_sequence + 1) & 16383,
            acknowledged_sequence=(transport.out_sequence - 1) & 16383,
            history=(0xffffffff,), bunches=bunches)
        packet = replace(packet, **changes)
        return b'opaque!!' + encode_observed_application(packet,
            max_packet_bytes=1024, received_by_server=True)

    def test_complete_startup_extends_sixty_second_idle_but_not_absolute_lifetime(self):
        from tests.test_legacy_ds_pc_startup_rpc import rpc
        fixture, connection = self.startup()
        handshake = self.attach(connection)
        verified_at = handshake.pending[PEER].verified_at
        bunches = (rpc(200, 79), rpc(201, 141, False))
        for now in (59.0, 118.0, 177.0):
            decision = handshake.handle(self.datagram(connection, fixture.f.template, bunches), PEER, now)
            self.assertEqual(decision.event, 'pc_startup_packet_consumed')
            self.assertIsNotNone(decision.response)
            self.assertEqual(handshake.pending[PEER].last_valid_activity_at, now)
            self.assertEqual(handshake.pending[PEER].verified_at, verified_at)
            handshake.poll(now + 0.5)
            self.assertIn(PEER, handshake.pending)
            self.assertEqual(handshake.pending[PEER].last_valid_activity_at, now)
        handshake.poll(180.11)
        self.assertNotIn(PEER, handshake.pending)
        self.assertNotIn(PEER, connection.peers)

    def test_whole_possession_ack_and_view_target_keep_the_verified_generation_active(self):
        for view, event in ((False, 'pc_possession_ack_packet_consumed'),
                            (True, 'pc_verify_view_target_packet_consumed')):
            fixture, connection = self.restart(view=view)
            handshake = self.attach(connection)
            bunch = fixture.verify_view_target() if view else fixture.acknowledgement()
            with self.subTest(view=view):
                decision = handshake.handle(self.datagram(connection, fixture.fixture.template,
                    (bunch,)), PEER, 59.0)
                self.assertEqual(decision.event, event)
                self.assertEqual(handshake.pending[PEER].last_valid_activity_at, 59.0)
                handshake.poll(60.4)
                self.assertIn(PEER, handshake.pending)

    def test_fully_decoded_ping_refreshes_with_reply_and_when_rate_gate_suppresses_reply(self):
        from tests.test_legacy_ds_pc_ping_receiver import PingReceiverTests, request
        fixture = PingReceiverTests()
        fixture.setUp()
        connection = fixture.f.probe
        handshake = self.attach(connection)
        first = handshake.handle(self.datagram(connection, fixture.f.template, (request(),)), PEER, 0.5)
        self.assertEqual(first.event, 'pc_ping_rpc_reply_prepared')
        self.assertIsNotNone(first.response)
        self.assertEqual(handshake.pending[PEER].last_valid_activity_at, 0.5)
        gated = handshake.handle(self.datagram(connection, fixture.f.template, (request(),)), PEER, 59.0)
        self.assertEqual(gated.event, 'pc_ping_rpc_consumed_without_reply')
        self.assertIsNone(gated.response)
        self.assertEqual(handshake.pending[PEER].last_valid_activity_at, 59.0)
        handshake.poll(60.6)
        self.assertIn(PEER, handshake.pending)

    def test_unknown_mixed_invalid_or_unqualified_startup_cannot_extend_idle(self):
        from tests.test_legacy_ds_pc_startup_rpc import rpc
        for kind in ('unknown', 'mixed', 'invalid_scalar', 'ready_without_marker',
                     'bad_header', 'replay', 'future_sequence', 'future_ack'):
            fixture, connection = self.startup()
            handshake = self.attach(connection)
            bunches = (rpc(200, 79),)
            changes = {}
            if kind == 'unknown':
                bunches = (rpc(200, 154),)
            elif kind == 'mixed':
                bunches += (replace(rpc(500, 79), channel_index=4),)
            elif kind == 'invalid_scalar':
                bunches = (rpc(200, 79), rpc(201, 216, float('nan')))
            elif kind == 'ready_without_marker':
                bunches = (rpc(200, 141, False),)
            elif kind == 'replay':
                changes['sequence'] = connection.peers[PEER].in_sequence
            elif kind == 'future_sequence':
                changes['sequence'] = (connection.peers[PEER].in_sequence + 33) & 16383
            elif kind == 'future_ack':
                changes['acknowledged_sequence'] = (connection.peers[PEER].out_sequence + 100) & 16383
            data = self.datagram(connection, fixture.f.template, bunches, **changes)
            if kind == 'bad_header':
                data = b'opaque!!' + bytes(10)
            with self.subTest(kind=kind):
                decision = handshake.handle(data, PEER, 59.0)
                self.assertNotEqual(decision.event, 'pc_startup_packet_consumed')
                self.assertEqual(handshake.pending[PEER].last_valid_activity_at, 0.3)
                handshake.poll(60.4)
                self.assertNotIn(PEER, handshake.pending)

    def test_mixed_or_invalid_ping_cannot_extend_idle_even_when_known_ping_has_a_reply(self):
        from tests.test_legacy_ds_pc_ping_receiver import PingReceiverTests, request, PARAMS
        for kind in ('mixed', 'invalid_scalar', 'budget_exhausted'):
            fixture = PingReceiverTests()
            fixture.setUp()
            connection = fixture.f.probe
            handshake = self.attach(connection)
            bunches = (request(), request(index=141)) if kind == 'mixed' else (
                request(replace(PARAMS, tc1=float('nan'))) if kind == 'invalid_scalar' else request(),)
            if kind == 'budget_exhausted':
                state = connection.control_peers[PEER]
                state.pc_ping_reply_count = state.pc_ping_profile.maximum_replies
            with self.subTest(kind=kind):
                decision = handshake.handle(self.datagram(connection, fixture.f.template, bunches), PEER, 0.5)
                if kind == 'mixed':
                    self.assertEqual(decision.event, 'pc_ping_reply_for_unacknowledged_mixed_packet')
                    self.assertIsNotNone(decision.response)
                else:
                    self.assertIsNone(decision.response)
                self.assertEqual(handshake.pending[PEER].last_valid_activity_at, 0.3)

    def test_unverified_generation_cannot_gain_activity_from_a_detached_joined_fixture(self):
        from tests.test_legacy_ds_pc_startup_rpc import rpc
        fixture, connection = self.startup()
        handshake = self.attach(connection)
        handshake.pending[PEER].echoed = False
        decision = handshake.handle(self.datagram(connection, fixture.f.template,
            (rpc(200, 79),)), PEER, 0.5)
        self.assertEqual(decision.event, 'pc_startup_packet_consumed')
        self.assertEqual(handshake.pending[PEER].last_valid_activity_at, 0.3)

    def test_bad_possession_guid_and_unvalidated_view_target_cannot_extend_idle(self):
        for view in (False, True):
            fixture, connection = self.restart(view=view)
            handshake = self.attach(connection)
            bunch = (fixture.verify_view_target(parameter_bits=1) if view
                     else fixture.acknowledgement(guid=4))
            with self.subTest(view=view):
                decision = handshake.handle(self.datagram(connection, fixture.fixture.template,
                    (bunch,)), PEER, 59.0)
                self.assertNotIn(decision.event, ('pc_possession_ack_packet_consumed',
                                                 'pc_verify_view_target_packet_consumed'))
                self.assertEqual(handshake.pending[PEER].last_valid_activity_at, 0.3)

    def admitted_receipts(self):
        from tests.test_admitted_actor_reliable_receipts import AdmittedActorReceiptTests
        fixture = AdmittedActorReceiptTests()
        fixture.setUp()
        fixture.deliver()
        fixture.enable()
        handshake = self.attach(fixture.connection)
        handshake.pending[PEER] = fixture.generation
        fixture.generation.last_valid_activity_at = .3
        return fixture, fixture.connection, handshake

    def test_admitted_opaque_actor_receipt_refreshes_current_generation_with_absolute_limit(self):
        fixture, connection, handshake = self.admitted_receipts()
        verified_at = fixture.generation.verified_at
        for now in (59., 118., 177.):
            data = self.datagram(connection, fixture.fixture.template, (fixture.bunch(),), history=(0,))
            decision = handshake.handle(data, PEER, now)
            self.assertEqual(decision.event, 'admitted_actor_reliable_packet_received')
            self.assertIsNotNone(decision.response)
            self.assertEqual(fixture.generation.last_valid_activity_at, now)
            self.assertEqual(fixture.generation.verified_at, verified_at)
        handshake.poll(180.01)
        self.assertNotIn(PEER, handshake.pending)

    def test_refused_admitted_receipt_foreign_generation_or_ticket_cannot_extend_idle(self):
        for kind in ('malformed_unreliable', 'beyond_window_reliable', 'unopened', 'foreign_generation',
                     'foreign_ticket', 'expired_admission', 'closed'):
            fixture, connection, handshake = self.admitted_receipts()
            bunch = fixture.bunch()
            if kind == 'malformed_unreliable':
                bunch = replace(bunch, reliable=False, channel_sequence=None, channel_name=None,
                    partial=True)
            elif kind == 'beyond_window_reliable':
                bunch = replace(bunch, channel_sequence=(fixture.seed + 256) % 1024)
            elif kind == 'unopened':
                bunch = replace(bunch, channel_index=99)
            elif kind == 'foreign_generation':
                handshake.pending[PEER] = replace(fixture.generation)
            elif kind == 'foreign_ticket':
                fixture.state().ticket = replace(fixture.ticket)
            elif kind == 'expired_admission':
                connection.admissions.revoke(fixture.ticket)
            else:
                fixture.state().client_closed = True
            with self.subTest(kind=kind):
                data = self.datagram(connection, fixture.fixture.template, (bunch,), history=(0,))
                decision = handshake.handle(data, PEER, 59.)
                self.assertNotEqual(decision.event, 'admitted_actor_reliable_packet_received')
                self.assertIsNone(decision.response)
                self.assertEqual(handshake.pending[PEER].last_valid_activity_at, .3)

    def test_admitted_receipt_cannot_refresh_a_generation_replaced_after_core_success(self):
        fixture, connection, handshake = self.admitted_receipts()
        original_handle = connection.handle
        foreign = replace(fixture.generation)

        def replace_generation(*args, **kwargs):
            result = original_handle(*args, **kwargs)
            handshake.pending[PEER] = foreign
            return result

        connection.handle = replace_generation
        data = self.datagram(connection, fixture.fixture.template, (fixture.bunch(),), history=(0,))
        decision = handshake.handle(data, PEER, 59.)
        self.assertEqual(decision.event, 'admitted_actor_reliable_packet_received')
        self.assertEqual(foreign.last_valid_activity_at, .3)

    def test_authenticated_peer_rebind_preserves_all_existing_admitted_receipt_ledgers(self):
        from dfserver.unreal_handshake_payload import decode_payload, encode_payload
        from tests.test_legacy_ds_restart_handshake import RESTART_INITIAL, PREFIX
        from tests.test_legacy_ds_pc_startup_rpc import rpc
        fixture, connection, handshake = self.admitted_receipts()
        connection._local_stage_generation_for_peer = lambda peer, state, transport: (
            handshake.pending.get(peer) if connection.control_peers.get(peer) is state and
            connection.peers.get(peer) is transport else None)
        initial = (rpc(fixture.seed, 79), fixture.bunch(),
            *(fixture.bunch(channel) for channel in (5, 12, 13)))
        result = handshake.handle(self.datagram(connection, fixture.fixture.template,
            initial, history=(0,)), PEER, .5)
        self.assertEqual(result.event, 'admitted_actor_reliable_packet_received')
        state, transport = fixture.state(), connection.peers[PEER]
        pawn_adapter, pc_ledger = state.admitted_pawn_receipt, state.pc_reliable_receipt
        extra_ledgers = dict(state.admitted_actor_receipt_ledgers)
        proofs, journal = state.actual_actor_receipts, state.admitted_actor_opaque_journal
        new_peer = (PEER[0], PEER[1] + 1)
        challenge = handshake.handle(RESTART_INITIAL, new_peer, .6)
        self.assertEqual(challenge.event, 'restart_peer_challenge_reply_prepared')
        value = decode_payload(challenge.response)
        echo = PREFIX + encode_payload(replace(value, restart=True, old_cookie=fixture.generation.cookie))
        migrated = handshake.handle(echo, new_peer, .7)
        self.assertEqual(migrated.event, 'valid_restart_peer_echo_ack_prepared')
        self.assertIs(connection.control_peers[new_peer], state)
        self.assertIs(connection.peers[new_peer], transport)
        self.assertIs(state.admitted_pawn_receipt, pawn_adapter)
        self.assertIs(state.pc_reliable_receipt, pc_ledger)
        self.assertTrue(all(state.admitted_actor_receipt_ledgers[c] is ledger
            for c, ledger in extra_ledgers.items()))
        self.assertEqual(state.admitted_actor_receipt_lease.peer, new_peer)
        self.assertEqual(pawn_adapter._binding.peer, new_peer)
        self.assertIs(state.actual_actor_receipts, proofs)
        self.assertEqual(state.admitted_actor_opaque_journal, journal)
        self.assertTrue(all(ledger.expected_sequence == (fixture.seed + 1) % 1024
            for ledger in (pawn_adapter, pc_ledger, *extra_ledgers.values())))
        bunches = (rpc((fixture.seed + 1) % 1024, 200),
            *(fixture.bunch(channel, (fixture.seed + 1) % 1024) for channel in (4, 5, 12, 13)))
        packet = replace(fixture.fixture.template, sequence=(transport.in_sequence + 1) & 16383,
            acknowledged_sequence=(transport.out_sequence - 1) & 16383,
            history=(0,), bunches=bunches)
        data = PREFIX + encode_observed_application(packet, max_packet_bytes=1024, received_by_server=True)
        decision = handshake.handle(data, new_peer, .8)
        self.assertEqual(decision.event, 'admitted_actor_reliable_packet_received')
        self.assertIsNotNone(decision.response)
        self.assertEqual(fixture.generation.last_valid_activity_at, .8)

    def test_peer_rebind_rejects_foreign_receipt_generation_or_adapter_peer_atomically(self):
        for kind in ('generation', 'adapter_peer'):
            fixture, connection, handshake = self.admitted_receipts()
            self.assertIsNotNone(fixture.send((fixture.bunch(),))[1])
            state, transport = fixture.state(), connection.peers[PEER]
            lease, adapter = state.admitted_actor_receipt_lease, state.admitted_pawn_receipt
            if kind == 'generation':
                state.admitted_actor_receipt_lease = replace(lease, generation=replace(fixture.generation))
            else:
                adapter._binding = replace(adapter._binding, peer=('127.0.0.1', 65534))
            current_lease, current_binding = state.admitted_actor_receipt_lease, adapter._binding
            new_peer = (PEER[0], PEER[1] + 1)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                connection.rebind_verified_peer(PEER, new_peer)
            self.assertIs(connection.control_peers[PEER], state)
            self.assertIs(connection.peers[PEER], transport)
            self.assertNotIn(new_peer, connection.peers)
            self.assertNotIn(new_peer, connection.control_peers)
            self.assertEqual(connection.ticket_peers[fixture.ticket.cookie], PEER)
            self.assertIs(state.admitted_actor_receipt_lease, current_lease)
            self.assertIs(adapter._binding, current_binding)


if __name__ == '__main__':
    unittest.main()
