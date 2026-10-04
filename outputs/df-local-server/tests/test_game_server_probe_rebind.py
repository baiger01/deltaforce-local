"""Real socket migration and queued-send ownership; delivery is not spawn proof."""
from dataclasses import replace
import socket
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from dfserver.game_server_probe import GameServerProbe
from dfserver.legacy_ds_control_fields import encode_message
from dfserver.legacy_ds_wire_codec import decode_observed_application, encode_observed_application
from dfserver.unreal_handshake_payload import decode_payload, encode_payload
from tests.test_legacy_ds_actor_bootstrap import BootstrapLifetimeTests, manifest
from tests.test_legacy_ds_control_connection import MAPS, login_payload
from tests.test_legacy_ds_control_probe import PEER
from tests.test_legacy_ds_restart_handshake import INITIAL, PREFIX, RESTART_INITIAL
from tests.test_legacy_ds_wire_codec import HELLO_BODIES


class ProbeSocketRebindTests(unittest.TestCase):
    def test_new_udp_port_keeps_registered_actor_and_accepts_its_delivery_ack(self):
        template = decode_observed_application(HELLO_BODIES[0],
            max_packet_bytes=1024, received_by_server=True)
        with tempfile.TemporaryDirectory() as folder, GameServerProbe(folder,
                handshake_probe=True, packet_ack_probe=True, control_probe=True,
                expected_net_version=1077088301, control_welcome_maps=MAPS) as server, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as old, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as new:
            old.settimeout(2)
            new.settimeout(2)
            address = ('127.0.0.1', server.port)
            server.set_initial_actor_manifests(2201, (manifest(),))
            ticket = server.issue_match_admission(player_id=101, room_id=201,
                map_id=2201, match_mode_id=142201103)
            old.sendto(INITIAL, address)
            challenge = old.recvfrom(2048)[0]
            old.sendto(PREFIX + challenge, address)
            cookie = decode_payload(old.recvfrom(2048)[0]).cookie
            server_seed = int.from_bytes(cookie[:2], 'little') & 16383
            client_seed = int.from_bytes(cookie[2:4], 'little') & 16383
            old_peer = ('127.0.0.1', old.getsockname()[1])

            def send(client, packet):
                client.sendto(PREFIX + encode_observed_application(packet,
                    max_packet_bytes=1024, received_by_server=True), address)

            packet = replace(template, sequence=client_seed,
                acknowledged_sequence=(server_seed - 1) & 16383,
                bunches=(replace(template.bunches[0],
                    channel_sequence=(client_seed + 1) & 1023),))
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
            actor = decode_observed_application(old.recvfrom(2048)[0],
                max_packet_bytes=1024, received_by_server=False)
            with server._lock:
                handshake = server._handshake
                connection = handshake.packet_ack_probe
                generation = handshake.pending[old_peer]
                state, transport = connection.control_peers[old_peer], connection.peers[old_peer]
                actor_state = next(iter(state.actor_opens.values()))
                seq_before = transport.out_sequence

            new.sendto(RESTART_INITIAL, address)
            fresh = decode_payload(new.recvfrom(2048)[0])
            new_peer = ('127.0.0.1', new.getsockname()[1])
            with server._lock:
                self.assertNotIn(new_peer, connection.peers)
                self.assertIs(handshake.pending[old_peer], generation)
            new.sendto(PREFIX + encode_payload(replace(fresh, restart=True, old_cookie=cookie)), address)
            resumed = decode_payload(new.recvfrom(2048)[0])
            self.assertEqual(resumed.cookie, cookie)
            with server._lock:
                registration = server._registered_bootstraps[ticket.cookie]
                self.assertEqual(registration['peer'], new_peer)
                self.assertIs(registration['generation'], generation)
                self.assertIs(handshake.pending[new_peer], generation)
                self.assertIs(connection.control_peers[new_peer], state)
                self.assertIs(connection.peers[new_peer], transport)
                self.assertIs(next(iter(state.actor_opens.values())), actor_state)
                self.assertEqual(transport.out_sequence, seq_before)
                self.assertNotIn(old_peer, handshake.pending)
                self.assertEqual(server._bootstrap_events['queued_sets'], 1)
            packet = replace(packet, sequence=(client_seed + 3) & 16383,
                acknowledged_sequence=actor.sequence, history=(1,), bunches=())
            send(new, packet)
            deadline = time.monotonic() + 2
            while server.actor_transport_progress['fully_delivered_sets'] != 1 and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(server.actor_transport_progress['fully_delivered_sets'], 1)
            self.assertFalse(server.actor_transport_progress['native_spawn_verified'])
            self.assertEqual(server._bootstrap_events['authenticated_peer_rebinds'], 1)


class ProbeQueuedSendRebindTests(unittest.TestCase):
    def setUp(self):
        fixture = BootstrapLifetimeTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.server, self.connection, self.ticket = fixture.server, fixture.connection, fixture.ticket
        self.new_peer = ('127.0.0.1', PEER[1] + 9)

    def migrate(self, now):
        handshake = self.server._handshake
        cookie = handshake.pending[PEER].cookie
        challenge = handshake.handle(RESTART_INITIAL, self.new_peer, now)
        self.assertIsNotNone(challenge.response)
        body = replace(decode_payload(challenge.response), restart=True, old_cookie=cookie)
        result = handshake.handle(PREFIX + encode_payload(body), self.new_peer, now + .001)
        self.assertEqual(result.rebound_from_peer, PEER)
        self.server._rebind_registered_bootstraps_locked(result.rebound_from_peer, self.new_peer)

    def test_encoded_actor_is_routed_to_authenticated_new_owner_without_reencoding(self):
        original_expire = self.server._handshake._expire
        calls = [0]

        def switch_after_encoding(now):
            original_expire(now)
            calls[0] += 1
            if calls[0] == 3:
                self.migrate(now)

        original_socket = self.server._udp
        self.server._udp = Mock()
        self.addCleanup(original_socket.close)
        self.server._udp.sendto.side_effect = lambda payload, peer: len(payload)
        with patch.object(self.server._handshake, '_expire', side_effect=switch_after_encoding):
            self.server._send_control_retries()
        self.server._udp.sendto.assert_called_once()
        self.assertEqual(self.server._udp.sendto.call_args.args[1], self.new_peer)
        self.assertEqual(self.server._bootstrap_events['queued_sets'], 1)
        self.assertEqual(self.server._bootstrap_events['authenticated_peer_rebinds'], 1)
        self.assertEqual(self.server._actor_open_sent, 1)
        self.assertEqual(self.server._bootstrap_events['stale_actor_datagrams_discarded'], 0)

    def test_address_only_and_replacement_generation_do_not_rebind_registration(self):
        with self.server._lock:
            self.server._queue_registered_bootstraps_locked()
            registration = self.server._registered_bootstraps[self.ticket.cookie]
            generation = registration['generation']
            self.server._rebind_registered_bootstraps_locked(PEER, self.new_peer)
            self.assertEqual(registration['peer'], PEER)
            self.migrate(.1)
            registration['peer'] = PEER
            registration['generation'] = replace(generation)
            self.server._rebind_registered_bootstraps_locked(PEER, self.new_peer)
            self.assertEqual(registration['peer'], PEER)


if __name__ == '__main__':
    unittest.main()
