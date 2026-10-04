"""Joined-ticket bootstrap transactions; synthetic metadata is not native spawn evidence."""
from dataclasses import replace
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import Mock, PropertyMock, patch

from dfserver.legacy_ds_match_admission import LocalMatchAdmissions
from dfserver.legacy_ds_control_connection import MAX_INITIAL_ACTOR_CHANNELS
from dfserver.legacy_ds_guid_exports import GuidExportNode
from dfserver.game_server_probe import GameServerProbe
from dfserver.legacy_ds_actor_manifest import ActorManifest, GuidPathBinding, CLIENT_SHA256
from dfserver.legacy_ds_bit_archive import BitReader
from dfserver.legacy_ds_guid_exports import read_guid_exports
from dfserver.legacy_ds_wire_codec import decode_observed_application, encode_observed_application
from dfserver.legacy_ds_control_fields import encode_message
from dfserver.unreal_handshake_payload import decode_payload
from dfserver.legacy_ds_handshake_probe import PendingChallenge
from tests import test_legacy_ds_actor_delivery as delivery
from tests.test_legacy_ds_control_probe import PEER
from tests.test_legacy_ds_control_connection import MAPS, login_payload
from tests.test_legacy_ds_wire_codec import HELLO_BODIES


def manifest():
    package = GuidExportNode(3, '/Game/Test/Pawn')
    klass = GuidExportNode(5, 'BP_Test_C', package)
    template = GuidExportNode(7, 'Default__BP_Test_C', package)
    level_package = GuidExportNode(25, '/Game/Test/Entry')
    level_outer = GuidExportNode(9, 'Entry', level_package)
    level = GuidExportNode(11, 'PersistentLevel', level_outer)
    bindings = (
        GuidPathBinding(3, '/Game/Test/Pawn'),
        GuidPathBinding(5, '/Game/Test/Pawn.BP_Test_C', '.'),
        GuidPathBinding(7, '/Game/Test/Pawn.Default__BP_Test_C', '.'),
        GuidPathBinding(25, '/Game/Test/Entry'),
        GuidPathBinding(9, '/Game/Test/Entry.Entry', '.'),
        GuidPathBinding(11, '/Game/Test/Entry.Entry:PersistentLevel', ':'),
    )
    return ActorManifest(CLIENT_SHA256, 'work/synthetic-fixture.json', 'a' * 64,
        5, bindings[1].full_path, 7, bindings[2].full_path,
        'named_default_object_candidate', 11, bindings[5].full_path,
        bindings, (klass, template, level), 2, 13, 13, True, 1, None, None, None)


class ActiveTicketTests(unittest.TestCase):
    def test_identity_check_neither_refreshes_nor_authorizes_a_copy(self):
        now = [10.0]
        store = LocalMatchAdmissions(ttl=5, clock=lambda: now[0])
        ticket = store.issue(101, 201, 2201, 1)
        self.assertTrue(store.is_active(ticket))
        self.assertFalse(store.is_active(replace(ticket)))
        self.assertFalse(store.is_active(None))
        self.assertFalse(LocalMatchAdmissions().is_active(ticket))
        now[0] = 14.9
        self.assertTrue(store.is_active(ticket))
        self.assertEqual(ticket.expires_at, 15.0)
        now[0] = 15.0
        self.assertFalse(store.is_active(ticket))
        self.assertFalse(store.is_active(ticket))
        self.assertEqual(store.summary()['expired_ticket_count'], 1)
        self.assertEqual(store.summary()['authorized_login_count'], 0)


class AtomicBootstrapTests(unittest.TestCase):
    def setUp(self):
        fixture = delivery.ActorDeliveryTests()
        fixture.setUp()
        self.connection = fixture.connection

    def test_complete_set_is_queued_once_with_connection_owned_sequence(self):
        self.connection.queue_actor_opens(PEER, (
            delivery.actor_fields(), delivery.actor_fields(channel_index=2, actor_guid=4)))
        packets = [delivery.decode(body) for _, _, body in self.connection.poll(0.1)]
        self.assertEqual([packet.bunches[0].channel_index for packet in packets], [1, 2])
        self.assertEqual([packet.bunches[0].channel_sequence for packet in packets], [217, 217])
        self.assertEqual(self.connection.summary()['initial_actor_channels_queued'], 2)
        self.assertFalse(self.connection.summary()['native_actor_spawn_verified'])

    def test_late_channel_conflict_rolls_back_first_actor_and_counters(self):
        original = self.connection.control_peers[PEER]
        events = dict(self.connection.control_events)
        with self.assertRaisesRegex(ValueError, 'cannot be opened twice'):
            self.connection.queue_actor_opens(PEER, (
                delivery.actor_fields(), delivery.actor_fields(actor_guid=4)))
        self.assertIs(self.connection.control_peers[PEER], original)
        self.assertEqual(original.actor_opens, {})
        self.assertEqual(original.actor_exports, {})
        self.assertEqual(dict(self.connection.control_events), events)
        self.assertEqual(self.connection.poll(1.0), [])

    def test_cross_actor_guid_definition_conflict_rolls_back_entire_set(self):
        changed = delivery.actor_fields(channel_index=2, actor_guid=4,
            exports=(GuidExportNode(3, 'DifferentFixture'), GuidExportNode(5, 'FixtureLevel')))
        with self.assertRaisesRegex(ValueError, 'conflicts'):
            self.connection.queue_actor_opens(PEER, (delivery.actor_fields(), changed))
        self.assertEqual(self.connection.control_peers[PEER].actor_opens, {})
        self.assertEqual(self.connection.summary()['initial_actor_channels_queued'], 0)

    def test_failed_set_preserves_previously_queued_actor_and_its_delivery_state(self):
        self.connection.queue_actor_open(PEER, **delivery.actor_fields())
        self.connection.poll(0.1)
        original = self.connection.control_peers[PEER]
        pending = original.actor_opens[1]
        events = dict(self.connection.control_events)
        with self.assertRaises(ValueError):
            self.connection.queue_actor_opens(PEER, (
                delivery.actor_fields(channel_index=2, actor_guid=4),
                delivery.actor_fields(channel_index=3, actor_guid=4)))
        self.assertIs(self.connection.control_peers[PEER], original)
        self.assertIs(original.actor_opens[1], pending)
        self.assertEqual(pending.transmissions, 1)
        self.assertEqual(list(original.actor_opens), [1])
        self.assertEqual(dict(self.connection.control_events), events)

    def test_empty_mutable_or_oversized_sets_never_mutate_connection(self):
        for value in ((), [], (None,), tuple(delivery.actor_fields(channel_index=n + 1,
                actor_guid=2 * n + 2) for n in range(MAX_INITIAL_ACTOR_CHANNELS + 1))):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ValueError):
                self.connection.queue_actor_opens(PEER, value)
        self.assertEqual(self.connection.control_peers[PEER].actor_opens, {})


class BootstrapLifetimeTests(unittest.TestCase):
    def setUp(self):
        fixture = delivery.ActorDeliveryTests()
        fixture.setUp()
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.server = GameServerProbe(self.folder.name, handshake_probe=True, packet_ack_probe=True,
            control_probe=True, expected_net_version=1077088301, control_welcome_maps=MAPS)
        self.addCleanup(self.server.close)
        self.server._admissions = fixture.admissions
        self.server._handshake.packet_ack_probe = fixture.connection
        self.server._handshake.pending[PEER] = PendingChallenge(1.0, b'test' * 5, 0,
            echoed=True, verified_at=0, last_valid_activity_at=0)
        self.connection, self.ticket = fixture.connection, fixture.ticket
        with patch.object(GameServerProbe, 'listening', new_callable=PropertyMock, return_value=True):
            self.server.register_initial_actor_manifests(self.ticket, (manifest(),))

    def test_waiting_set_expires_without_queue_or_identity_transfer(self):
        self.connection.control_peers[PEER].client_join_observed = False
        self.server._admissions._clock = lambda: self.ticket.expires_at
        with self.server._lock:
            self.server._queue_registered_bootstraps_locked()
        self.assertEqual(self.connection.control_peers[PEER].actor_opens, {})
        self.assertEqual(self.server._registered_bootstraps, {})
        self.assertEqual(self.server._bootstrap_events['expired_before_join'], 1)

    def test_replacement_handshake_discards_already_encoded_actor_packet(self):
        original_expire = self.server._handshake._expire
        count = [0]

        def replace_generation(now):
            original_expire(now)
            count[0] += 1
            if count[0] == 3:  # After poll encoded the Actor, before send.
                self.connection.forget_peer(PEER)
                self.server._handshake.pending[PEER] = PendingChallenge(2.0, b'new!' * 5, now)

        original_socket = self.server._udp
        self.server._udp = Mock()
        self.addCleanup(original_socket.close)
        with patch.object(self.server._handshake, '_expire', side_effect=replace_generation):
            self.server._send_control_retries()
        self.server._udp.sendto.assert_not_called()
        self.assertEqual(self.server._bootstrap_events['queued_sets'], 1)
        self.assertEqual(self.server._bootstrap_events['stale_actor_datagrams_discarded'], 1)
        self.assertEqual(self.server._actor_open_sent, 0)

    def test_expired_ticket_discards_actor_between_encoding_and_send(self):
        original_expire = self.server._handshake._expire
        count = [0]

        def expire_ticket(now):
            original_expire(now)
            count[0] += 1
            if count[0] == 3:
                self.server._admissions._clock = lambda: self.ticket.expires_at

        original_socket = self.server._udp
        self.server._udp = Mock()
        self.addCleanup(original_socket.close)
        with patch.object(self.server._handshake, '_expire', side_effect=expire_ticket):
            self.server._send_control_retries()
        self.server._udp.sendto.assert_not_called()
        self.assertEqual(self.server._bootstrap_events['stale_actor_datagrams_discarded'], 1)
        self.assertEqual(self.server._actor_open_sent, 0)


class RegisteredBootstrapUdpTests(unittest.TestCase):
    def test_configured_map_registers_future_ticket_and_sends_only_after_join(self):
        """Exercise the real loopback sockets, exact control order and delivery ACK."""
        template = decode_observed_application(HELLO_BODIES[0],
            max_packet_bytes=1024, received_by_server=True)

        def send(client, address, packet):
            client.sendto(b'opaque!!' + encode_observed_application(packet,
                max_packet_bytes=1024, received_by_server=True), address)

        with tempfile.TemporaryDirectory() as folder:
            with GameServerProbe(folder, handshake_probe=True, packet_ack_probe=True,
                    control_probe=True, expected_net_version=1077088301,
                    control_welcome_maps=MAPS, max_packets=32) as server:
                server.set_initial_actor_manifests(2201, (manifest(),))
                ticket = server.issue_match_admission(player_id=101, room_id=201,
                    map_id=2201, match_mode_id=142201103)
                with self.assertRaises(ValueError):
                    server.register_initial_actor_manifests(replace(ticket), (manifest(),))
                with self.assertRaises(ValueError):
                    server.register_initial_actor_manifests(ticket, (manifest(),))
                self.assertEqual(server._bootstrap_events['registered_sets'], 1)
                self.assertEqual(server._bootstrap_events['queued_sets'], 0)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(2)
                    address = ('127.0.0.1', server.port)
                    client.sendto(b'opaque!!' + b'\x01' + bytes(23) + b'\x08', address)
                    challenge, _ = client.recvfrom(1500)
                    client.sendto(b'opaque!!' + challenge, address)
                    acknowledged, _ = client.recvfrom(1500)
                    cookie = decode_payload(acknowledged).cookie
                    server_seed = int.from_bytes(cookie[:2], 'little') & 16383
                    client_seed = int.from_bytes(cookie[2:4], 'little') & 16383
                    packet = replace(template, sequence=client_seed,
                        acknowledged_sequence=(server_seed - 1) & 16383, bunches=(
                            replace(template.bunches[0], channel_sequence=(client_seed + 1) & 1023),))
                    send(client, address, packet)
                    client.recvfrom(1500)
                    payload = login_payload(ticket)
                    packet = replace(packet, sequence=(client_seed + 1) & 16383,
                        acknowledged_sequence=server_seed, history=(1,), bunches=(
                            replace(packet.bunches[0], open=False, channel_sequence=(client_seed + 2) & 1023,
                                    payload=payload, payload_bits=len(payload) * 8),))
                    send(client, address, packet)
                    client.recvfrom(1500)
                    with server._lock:
                        self.assertEqual(server._actor_open_sent, 0)
                        self.assertEqual(server._bootstrap_events['queued_sets'], 0)
                    payload = encode_message(4, 25000) + encode_message(9)
                    packet = replace(packet, sequence=(client_seed + 2) & 16383,
                        acknowledged_sequence=(server_seed + 1) & 16383, bunches=(
                            replace(packet.bunches[0], channel_sequence=(client_seed + 3) & 1023,
                                    payload=payload, payload_bits=len(payload) * 8),))
                    send(client, address, packet)
                    join_ack = delivery.decode(client.recvfrom(1500)[0])
                    self.assertEqual(join_ack.bunches, ())
                    actor = delivery.decode(client.recvfrom(1500)[0])
                    self.assertEqual(actor.bunches[0].channel_name.hardcoded_index, 102)
                    self.assertEqual(actor.bunches[0].channel_sequence, (server_seed + 1) & 1023)
                    reader = BitReader(actor.bunches[0].payload, bit_count=actor.bunches[0].payload_bits)
                    read_guid_exports(reader)
                    self.assertEqual(tuple(reader.read_packed_int() for _ in range(3)), (2, 7, 11))
                    self.assertEqual(tuple(reader.read_bool() for _ in range(4)), (False,) * 4)
                    self.assertEqual(reader.remaining, 0)  # No guessed property/RPC body.
                    packet = replace(packet, sequence=(client_seed + 3) & 16383,
                        acknowledged_sequence=actor.sequence, history=(1,), bunches=())
                    send(client, address, packet)
                    client.settimeout(0.7)
                    with self.assertRaises(socket.timeout):
                        client.recvfrom(1500)
                    with server._lock:
                        self.assertEqual(server._bootstrap_events['queued_sets'], 1)
                        self.assertEqual(server._actor_open_sent, 1)
                        self.assertEqual(server._handshake.packet_ack_probe.summary()['initial_actor_delivery_acks'], 1)
            report = json.loads((Path(folder) / 'report.json').read_text(encoding='utf-8'))
            self.assertEqual(report['initial_actor_open_datagrams_sent'], 1)
            self.assertEqual(report['initial_actor_bootstrap']['events']['queued_sets'], 1)
            self.assertFalse(report['initial_actor_bootstrap']['native_spawn_verified'])
            self.assertNotIn(ticket.cookie, json.dumps(report))


if __name__ == '__main__':
    unittest.main()
