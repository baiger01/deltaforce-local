"""Private Join-time producers; synthetic UDP delivery is not native spawn proof."""
from copy import deepcopy
from dataclasses import replace
import socket
import tempfile
import time
import unittest
from unittest.mock import PropertyMock, patch

from dfserver.game_server_probe import GameServerProbe
from dfserver.legacy_ds_bit_archive import BitReader
from dfserver.legacy_ds_control_fields import encode_message
from dfserver.legacy_ds_guid_exports import read_guid_exports
from dfserver.legacy_ds_handshake_probe import PendingChallenge
from dfserver.legacy_ds_wire_codec import decode_observed_application, encode_observed_application
from dfserver.unreal_handshake_payload import decode_payload, encode_payload
from tests import test_legacy_ds_actor_bootstrap as bootstrap
from tests import test_legacy_ds_actor_delivery as delivery
from tests.test_legacy_ds_control_connection import MAPS, login_payload
from tests.test_legacy_ds_control_probe import PEER
from tests.test_legacy_ds_restart_handshake import INITIAL, PREFIX, RESTART_INITIAL
from tests.test_legacy_ds_wire_codec import HELLO_BODIES


class BootstrapResolverBoundaryTests(unittest.TestCase):
    def setUp(self):
        fixture = delivery.ActorDeliveryTests()
        fixture.setUp()
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.server = GameServerProbe(folder.name, handshake_probe=True, packet_ack_probe=True,
            control_probe=True, expected_net_version=1077088301, control_welcome_maps=MAPS)
        self.addCleanup(self.server.close)
        self.connection, self.ticket = fixture.connection, fixture.ticket
        self.server._admissions = fixture.admissions
        self.server._handshake.packet_ack_probe = self.connection
        self.server._handshake.pending[PEER] = PendingChallenge(1.0, b'test' * 5, 0,
            echoed=True, verified_at=0, last_valid_activity_at=0)

    def register(self, resolver=None):
        with patch.object(GameServerProbe, 'listening', new_callable=PropertyMock, return_value=True):
            self.server.register_initial_actor_manifests(self.ticket, (bootstrap.manifest(),),
                resolver=resolver)
        return self.server._registered_bootstraps[self.ticket.cookie]

    def queue(self):
        with self.server._lock:
            self.server._queue_registered_bootstraps_locked()

    def assert_rejected_without_mutation(self, registration):
        state = self.connection.control_peers[PEER]
        old_fields = deepcopy(registration['actor_fields'])
        old_events = dict(self.connection.control_events)
        old_sequence = self.connection.peers[PEER].out_sequence
        self.queue()
        self.assertEqual(registration['status'], 'rejected')
        self.assertEqual(registration['actor_fields'], old_fields)
        self.assertIs(self.connection.control_peers[PEER], state)
        self.assertEqual((state.actor_opens, state.actor_exports), ({}, {}))
        self.assertEqual(dict(self.connection.control_events), old_events)
        self.assertEqual(self.connection.peers[PEER].out_sequence, old_sequence)

    def test_error_after_mutating_input_cannot_change_nested_registration(self):
        calls = []
        def resolver(ticket, fields):
            calls.append(ticket)
            fields[0]['actor_guid'] = 8
            object.__setattr__(fields[0]['exports'][0].outer, 'path', '/Changed')
            raise ValueError('Private producer rejected its local state')
        registration = self.register(resolver)
        self.assert_rejected_without_mutation(registration)
        self.queue()
        self.assertEqual(calls, [self.ticket])

    def test_non_tuple_and_malformed_dictionary_outputs_are_rejected(self):
        for resolver in (lambda ticket, fields: list(fields), lambda ticket, fields: (),
                         lambda ticket, fields: (None,), lambda ticket, fields: ({'actor_guid': 2},),
                         lambda ticket, fields: (dict(fields[0], channel_sequence=0),)):
            with self.subTest(kind=resolver):
                self.server._registered_bootstraps.clear()
                self.assert_rejected_without_mutation(self.register(resolver))

    def test_duplicate_channels_and_actor_guids_are_rejected_as_whole_set(self):
        for duplicate in ('channel', 'actor'):
            def resolver(ticket, fields):
                other = dict(fields[0], channel_index=2, actor_guid=4)
                other['channel_index' if duplicate == 'channel' else 'actor_guid'] = (
                    fields[0]['channel_index'] if duplicate == 'channel' else fields[0]['actor_guid'])
                return (fields[0], other)
            with self.subTest(duplicate=duplicate):
                self.server._registered_bootstraps.clear()
                self.assert_rejected_without_mutation(self.register(resolver))

    def test_conflicting_nested_guid_definitions_are_rejected(self):
        def resolver(ticket, fields):
            other = deepcopy(fields[0])
            other.update(channel_index=2, actor_guid=4)
            object.__setattr__(other['exports'][0].outer, 'path', '/Game/Different/Pawn')
            return fields + (other,)
        self.assert_rejected_without_mutation(self.register(resolver))

    def test_cyclic_export_is_bounded_before_cross_graph_walk(self):
        def resolver(ticket, fields):
            object.__setattr__(fields[0]['exports'][0].outer, 'outer', fields[0]['exports'][0])
            return fields
        self.assert_rejected_without_mutation(self.register(resolver))

    def test_packet_preflight_failure_rolls_back_queue_and_resolved_fields(self):
        registration = self.register(lambda ticket, fields: (
            dict(fields[0], game_replication_flags=1),))
        self.connection.max_packet_bytes = 64
        self.assert_rejected_without_mutation(registration)

    def test_late_queue_conflict_preserves_previous_delivery_and_resolved_registration(self):
        self.connection.queue_actor_open(PEER, **delivery.actor_fields())
        original = self.connection.control_peers[PEER]
        previous_delivery = original.actor_opens[1]
        events = dict(self.connection.control_events)
        registration = self.register(lambda ticket, fields: (
            dict(fields[0], channel_index=2, actor_guid=4),
            dict(fields[0], channel_index=1, actor_guid=6)))
        old_fields = deepcopy(registration['actor_fields'])
        self.queue()
        self.assertEqual(registration['status'], 'rejected')
        self.assertEqual(registration['actor_fields'], old_fields)
        self.assertIs(self.connection.control_peers[PEER], original)
        self.assertIs(original.actor_opens[1], previous_delivery)
        self.assertEqual(list(original.actor_opens), [1])
        self.assertEqual(dict(self.connection.control_events), events)

    def test_expired_ticket_and_unverified_or_unjoined_generation_never_call_resolver(self):
        calls = []
        registration = self.register(lambda ticket, fields: calls.append(ticket) or fields)
        generation = self.server._handshake.pending[PEER]
        state = self.connection.control_peers[PEER]
        generation.verified_at = None
        self.queue()
        generation.verified_at = 0
        state.client_join_observed = False
        self.queue()
        state.client_join_observed = True
        self.server._admissions._clock = lambda: self.ticket.expires_at
        self.queue()
        self.assertEqual(calls, [])
        self.assertEqual(registration['status'], 'waiting_for_join')
        self.assertEqual(self.server._registered_bootstraps, {})
        self.assertEqual(state.actor_opens, {})

    def test_expiry_during_callback_does_not_commit_any_actor(self):
        def resolver(ticket, fields):
            self.server._admissions._clock = lambda: ticket.expires_at
            return fields
        self.assert_rejected_without_mutation(self.register(resolver))

    def test_saved_output_is_detached(self):
        retained = []
        def resolver(ticket, fields):
            retained.append(fields)
            return fields
        registration = self.register(resolver)
        self.queue()
        expected = deepcopy(registration['actor_fields'])
        retained[0][0]['actor_guid'] = 8
        object.__setattr__(retained[0][0]['exports'][0].outer, 'path', '/Changed')
        self.assertEqual(registration['actor_fields'], expected)
        self.assertEqual(self.connection.control_peers[PEER].actor_opens[1].actor_guid, 2)
        self.assertEqual(registration['status'], 'queued')

    def test_none_producer_keeps_previous_fields_and_connection_owned_sequence(self):
        registration = self.register()
        fields = registration['actor_fields']
        self.queue()
        self.assertIs(registration['actor_fields'], fields)
        self.assertEqual(registration['status'], 'queued')
        actor = self.connection.control_peers[PEER].actor_opens[1]
        self.assertEqual(actor.bunch.channel_sequence, 217)

    def test_invalid_producer_is_rejected_before_profile_or_registration(self):
        with patch.object(GameServerProbe, 'listening', new_callable=PropertyMock, return_value=True):
            with self.assertRaises(ValueError):
                self.server.set_initial_actor_manifests(2201, (bootstrap.manifest(),), resolver=4)
            with self.assertRaises(ValueError):
                self.server.register_initial_actor_manifests(self.ticket, (bootstrap.manifest(),), resolver=4)
        self.assertEqual(self.server._registered_bootstraps, {})
        self.assertEqual(self.server._initial_actor_profiles, {})


class BootstrapResolverUdpTests(unittest.TestCase):
    def test_actual_join_resolves_once_and_authenticated_migration_does_not_recompute(self):
        template = decode_observed_application(HELLO_BODIES[0],
            max_packet_bytes=1024, received_by_server=True)
        calls = []
        def resolver(ticket, fields):
            calls.append(ticket)
            return (dict(fields[0], channel_index=4, game_replication_flags=1),)
        with tempfile.TemporaryDirectory() as folder, GameServerProbe(folder,
                handshake_probe=True, packet_ack_probe=True, control_probe=True,
                expected_net_version=1077088301, control_welcome_maps=MAPS) as server, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as old, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as new:
            old.settimeout(2)
            new.settimeout(2)
            address = ('127.0.0.1', server.port)
            server.set_initial_actor_manifests(2201, (bootstrap.manifest(),), resolver=resolver)
            ticket = server.issue_match_admission(player_id=101, room_id=201,
                map_id=2201, match_mode_id=142201103)
            old.sendto(INITIAL, address)
            old.sendto(PREFIX + old.recvfrom(2048)[0], address)
            cookie = decode_payload(old.recvfrom(2048)[0]).cookie
            server_seed = int.from_bytes(cookie[:2], 'little') & 16383
            client_seed = int.from_bytes(cookie[2:4], 'little') & 16383
            old_peer = ('127.0.0.1', old.getsockname()[1])
            def send(client, packet):
                client.sendto(PREFIX + encode_observed_application(packet,
                    max_packet_bytes=1024, received_by_server=True), address)
            packet = replace(template, sequence=client_seed,
                acknowledged_sequence=(server_seed - 1) & 16383,
                bunches=(replace(template.bunches[0], channel_sequence=(client_seed + 1) & 1023),))
            send(old, packet)
            old.recvfrom(2048)
            for offset, payload in ((1, login_payload(ticket)),
                                    (2, encode_message(4, 25000) + encode_message(9))):
                packet = replace(packet, sequence=(client_seed + offset) & 16383,
                    acknowledged_sequence=(server_seed + offset - 1) & 16383, history=(1,),
                    bunches=(replace(packet.bunches[0], open=False,
                        channel_sequence=(client_seed + offset + 1) & 1023,
                        payload=payload, payload_bits=len(payload) * 8),))
                send(old, packet)
                old.recvfrom(2048)
                if offset == 1:
                    self.assertEqual(calls, [])
            actor = delivery.decode(old.recvfrom(2048)[0])
            self.assertEqual(actor.bunches[0].channel_index, 4)
            reader = BitReader(actor.bunches[0].payload, bit_count=actor.bunches[0].payload_bits)
            read_guid_exports(reader)
            reader.read_payload(28)
            self.assertEqual(reader.read_bits(8), 1)
            self.assertEqual(reader.remaining, 0)
            with server._lock:
                generation = server._handshake.pending[old_peer]
                registration = server._registered_bootstraps[ticket.cookie]
                resolved_fields = registration['actor_fields']
                server._queue_registered_bootstraps_locked()
                retry = server._handshake.packet_ack_probe.poll(1.0)
                self.assertTrue(any(event.startswith('actor_open_') for _, event, _ in retry))
            new.sendto(RESTART_INITIAL, address)
            fresh = decode_payload(new.recvfrom(2048)[0])
            new.sendto(PREFIX + encode_payload(replace(fresh, restart=True, old_cookie=cookie)), address)
            self.assertEqual(decode_payload(new.recvfrom(2048)[0]).cookie, cookie)
            new_peer = ('127.0.0.1', new.getsockname()[1])
            with server._lock:
                self.assertEqual(registration['peer'], new_peer)
                self.assertIs(registration['generation'], generation)
                self.assertIs(registration['actor_fields'], resolved_fields)
                server._queue_registered_bootstraps_locked()
            self.assertEqual(calls, [ticket])
            packet = replace(packet, sequence=(client_seed + 3) & 16383,
                acknowledged_sequence=actor.sequence, history=(1,), bunches=())
            send(new, packet)
            deadline = time.monotonic() + 2
            while server.actor_transport_progress['fully_delivered_sets'] != 1 and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(server.actor_transport_progress['fully_delivered_sets'], 1)
            self.assertFalse(server.actor_transport_progress['native_spawn_verified'])
            self.assertEqual(calls, [ticket])


if __name__ == '__main__':
    unittest.main()
