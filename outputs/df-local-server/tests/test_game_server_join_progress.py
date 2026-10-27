"""Join-time observations require an active, locally authorized connection."""
from dataclasses import replace
import tempfile
import time
import unittest

from dfserver.game_server_probe import GameServerProbe
from dfserver.legacy_ds_handshake_probe import PendingChallenge
from tests import test_legacy_ds_actor_delivery as delivery
from tests.test_legacy_ds_control_connection import MAPS
from tests.test_legacy_ds_control_probe import COOKIE, PEER


class MapJoinProgressTests(unittest.TestCase):
    def setUp(self):
        fixture = delivery.ActorDeliveryTests()
        fixture.setUp()
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.server = GameServerProbe(folder.name, handshake_probe=True,
            packet_ack_probe=True, control_probe=True,
            expected_net_version=1077088301, control_welcome_maps=MAPS)
        self.addCleanup(self.server.close)
        self.connection, self.ticket = fixture.connection, fixture.ticket
        self.server._admissions = fixture.admissions
        self.server._handshake.packet_ack_probe = self.connection
        self.server._handshake.pending[PEER] = PendingChallenge(
            1.0, COOKIE, 0, echoed=True, verified_at=0, last_valid_activity_at=0)

    def test_join_is_observed_without_actor_delivery_or_spawn_claim(self):
        progress = self.server.map_join_progress
        self.assertEqual(progress['join_observed_count'], 1)
        self.assertEqual(progress['active_joined_peers'], 1)
        self.assertFalse(progress['playable_map_verified'])
        self.assertEqual(self.connection.summary()['initial_actor_delivery_acks'], 0)
        for secret in (self.ticket.cookie, str(self.ticket.player_id)):
            self.assertNotIn(secret, str(progress))

    def test_closed_unjoined_or_missing_transport_is_not_an_active_join(self):
        state = self.connection.control_peers[PEER]
        state.client_closed = True
        self.assertEqual(self.server.map_join_progress['active_joined_peers'], 0)
        state.client_closed = False
        state.client_join_observed = False
        self.assertEqual(self.server.map_join_progress['active_joined_peers'], 0)
        state.client_join_observed = True
        del self.connection.peers[PEER]
        self.assertEqual(self.server.map_join_progress['active_joined_peers'], 0)

    def test_expired_ticket_or_replaced_ticket_identity_is_not_an_active_join(self):
        state = self.connection.control_peers[PEER]
        state.ticket = replace(self.ticket)
        self.assertEqual(self.server.map_join_progress['active_joined_peers'], 0)
        state.ticket = self.ticket
        self.server._admissions._clock = lambda: self.ticket.expires_at
        self.assertEqual(self.server.map_join_progress['active_joined_peers'], 1)
        self.server._admissions._clock = lambda: self.server._admissions._joined_until[self.ticket.cookie]
        self.assertEqual(self.server.map_join_progress['active_joined_peers'], 0)

    def test_expired_handshake_is_not_counted_before_the_udp_loop_polls(self):
        self.server._started_at = time.monotonic() - 601
        self.assertEqual(self.server.map_join_progress['active_joined_peers'], 0)


if __name__ == '__main__':
    unittest.main()
