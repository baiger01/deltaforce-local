"""Whole registered-set delivery progress; synthetic ACKs are not game spawns."""
from dataclasses import replace
import tempfile
import time
import unittest
from unittest.mock import PropertyMock, patch

from dfserver.game_server_probe import GameServerProbe
from dfserver.legacy_ds_control_fields import encode_message
from dfserver.legacy_ds_handshake_probe import PendingChallenge
from dfserver.legacy_ds_wire_codec import encode_observed_application
from tests import test_legacy_ds_actor_delivery as delivery
from tests.test_legacy_ds_actor_bootstrap import manifest
from tests.test_legacy_ds_control_connection import MAPS, login_payload
from tests.test_legacy_ds_control_probe import COOKIE, PEER
from tests.test_legacy_ds_wire_codec import HELLO_BODIES


OTHER = ('127.0.0.1', 40002)


class RegisteredSetProgressTests(unittest.TestCase):
    def setUp(self):
        fixture = delivery.ActorDeliveryTests()
        fixture.setUp()
        self.connection, self.ticket = fixture.connection, fixture.ticket
        self.template = fixture.template
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.server = GameServerProbe(self.folder.name, handshake_probe=True,
            packet_ack_probe=True, control_probe=True,
            expected_net_version=1077088301, control_welcome_maps=MAPS)
        self.addCleanup(self.server.close)
        self.server._admissions = fixture.admissions
        self.server._handshake.packet_ack_probe = self.connection
        self._generation(PEER)
        self.other_ticket = fixture.admissions.issue(102, 202, 2201, 142201103, 88000000025)
        self.connection.register_verified_echo(OTHER, COOKIE)
        self._generation(OTHER)
        self.connection.handle(b'opaque!!' + HELLO_BODIES[0], OTHER, 0)
        self._send(OTHER, 1257, 216, 234, login_payload(self.other_ticket))
        self._send(OTHER, 1258, 217, 235, encode_message(4, 25000) + encode_message(9))
        first = manifest()
        self.manifests = (first, replace(first, actor_guid=4, channel_index=2),
                          replace(first, actor_guid=6, channel_index=3))
        with patch.object(GameServerProbe, 'listening',
                new_callable=PropertyMock, return_value=True):
            self.server.register_initial_actor_manifests(self.ticket, self.manifests)
            self.server.register_initial_actor_manifests(self.other_ticket, self.manifests)
        with self.server._lock:
            self.server._queue_registered_bootstraps_locked()
        packets = self.connection.poll(0.1)
        self.assertEqual(len(packets), 6)
        self.assertEqual([delivery.decode(body).sequence for _, _, body in packets],
                         [219, 220, 221, 219, 220, 221])

    def _generation(self, peer):
        self.server._handshake.pending[peer] = PendingChallenge(
            1.0, COOKIE, 0, echoed=True, verified_at=0, last_valid_activity_at=0)

    def _send(self, peer, sequence, ack, channel_sequence=None, payload=b'', *, history=(1,)):
        bunches = () if channel_sequence is None else (
            replace(self.template.bunches[0], open=False, channel_sequence=channel_sequence,
                    payload=payload, payload_bits=len(payload) * 8),)
        packet = replace(self.template, sequence=sequence, acknowledged_sequence=ack,
                         history=history, bunches=bunches)
        return self.connection.handle(b'opaque!!' + encode_observed_application(packet,
            max_packet_bytes=1024, received_by_server=True), peer, 0.2)

    def _complete_first(self):
        event, _ = self._send(PEER, 1259, 221, history=(7,))
        self.assertEqual(event, 'control_ack_only_consumed')
        self.assertEqual(self.server.actor_transport_progress['fully_delivered_sets'], 1)

    def test_three_acks_split_across_peers_do_not_complete_one_three_actor_set(self):
        # ACK main packets219/220 and other packet221. The old global count is3,
        # but neither ticket's complete registered set has been delivered.
        self._send(PEER, 1259, 221, history=(6,))
        self._send(OTHER, 1259, 221, history=(1,))
        progress = self.server.actor_transport_progress
        self.assertEqual(progress['delivery_acks'], 3)
        self.assertEqual(progress['fully_delivered_sets'], 0)
        self.assertFalse(progress['native_spawn_verified'])
        self._send(PEER, 1260, 221, history=(7,))
        progress = self.server.actor_transport_progress
        self.assertEqual(progress['delivery_acks'], 4)
        self.assertEqual(progress['fully_delivered_sets'], 1)

    def test_complete_sets_are_counted_per_ticket_then_expiration_removes_them(self):
        self._complete_first()
        self._send(OTHER, 1259, 221, history=(7,))
        self.assertEqual(self.server.actor_transport_progress['fully_delivered_sets'], 2)
        self.server._admissions._clock = lambda: self.ticket.expires_at
        progress = self.server.actor_transport_progress
        self.assertEqual(progress['fully_delivered_sets'], 0)
        self.assertEqual(self.server._registered_bootstraps, {})

    def test_same_peer_replacement_generation_cannot_reuse_old_delivered_set(self):
        self._complete_first()
        original = self.server._handshake.pending[PEER]
        # Same values and UDP address are insufficient: this is a new generation.
        self.server._handshake.pending[PEER] = replace(original)
        self.assertEqual(self.connection.summary()['initial_actor_delivery_acks'], 3)
        self.assertEqual(self.server.actor_transport_progress['fully_delivered_sets'], 0)

    def test_expired_verified_generation_is_not_counted_before_poll_runs(self):
        self._complete_first()
        self.server._started_at = time.monotonic() - 601
        self.assertEqual(self.server.actor_transport_progress['fully_delivered_sets'], 0)
        self.assertNotIn(PEER, self.connection.control_peers)

    def test_ticket_copy_or_wrong_peer_binding_cannot_count_old_delivery(self):
        self._complete_first()
        state = self.connection.control_peers[PEER]
        state.ticket = replace(self.ticket)
        self.assertEqual(self.server.actor_transport_progress['fully_delivered_sets'], 0)
        state.ticket = self.ticket
        self.connection.ticket_peers[self.ticket.cookie] = OTHER
        self.assertEqual(self.server.actor_transport_progress['fully_delivered_sets'], 0)

    def test_missing_registered_channel_cannot_be_replaced_by_an_unrelated_ack(self):
        self.connection.queue_actor_open(PEER,
            **delivery.actor_fields(channel_index=4, actor_guid=8,
                exports=self.server._registered_bootstraps[self.ticket.cookie]['actor_fields'][0]['exports'],
                archetype_guid=7, level_guid=11))
        packets = self.connection.poll(0.11)
        self.assertEqual(len(packets), 1)
        self.assertEqual(delivery.decode(packets[0][2]).sequence, 222)
        self._send(PEER, 1259, 222, history=(13,))  # ACK222/220/219; not registered221.
        progress = self.server.actor_transport_progress
        self.assertEqual(progress['delivery_acks'], 3)
        self.assertEqual(progress['fully_delivered_sets'], 0)

    def test_absent_transport_peer_or_join_state_prevents_complete_set(self):
        self._complete_first()
        state = self.connection.control_peers[PEER]
        state.client_join_observed = False
        self.assertEqual(self.server.actor_transport_progress['fully_delivered_sets'], 0)
        state.client_join_observed = True
        del self.connection.peers[PEER]
        self.assertEqual(self.server.actor_transport_progress['fully_delivered_sets'], 0)


if __name__ == '__main__':
    unittest.main()
