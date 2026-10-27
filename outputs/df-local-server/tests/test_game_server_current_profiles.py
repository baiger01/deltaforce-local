"""Current RPC registrations must share the Actor manifest's source build."""
from dataclasses import replace
import tempfile
import unittest

from dfserver.game_server_probe import GameServerProbe
from dfserver.legacy_ds_game_state_start import GameStateStartProfile
from tests.test_legacy_ds_current_actor_profile import qualification, current_manifest
from tests.test_legacy_ds_control_connection import MAPS


class CurrentServerProfileTests(unittest.TestCase):
    def setUp(self):
        from build_updated_minimum_actor_profile import rpc_profiles
        from dfserver.replication.legacy_ds_rotator import CompressedRotator16
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.server = GameServerProbe(self.folder.name, handshake_probe=True, packet_ack_probe=True,
            control_probe=True, expected_net_version=1077088301, control_welcome_maps=MAPS)
        self.addCleanup(self.server.close)
        self.q = qualification()
        self.pc = current_manifest('PlayerController', self.q, channel=2, actor=4)
        self.pawn = replace(current_manifest('Pawn', self.q, channel=4, actor=2),
                            rotation=CompressedRotator16((0, 0, 0)))
        self.gs = current_manifest('GameState', self.q, channel=3, actor=6)
        self.rpc = rpc_profiles()
        self.start = GameStateStartProfile(self.gs.class_path, 19, self.gs.client_sha256,
            self.gs.source_sha256, all_ready_handle=24, abseil_handle=107, map_id_handle=52,
            room_id_handle=53, real_start_handle=108, current_qualification=self.q)

    def configure(self):
        self.server.set_pc_ping_profile(2201, self.pc, self.rpc['ping'])
        self.server.set_pc_startup_profile(2201, self.pc, self.rpc['startup'])
        self.server.set_game_state_start_profile(2201, self.gs, self.start)

    def test_current_restart_registration_uses_244_and_same_current_actors(self):
        self.configure()
        self.server.set_pc_restart_profile(2201, self.pc, self.pawn, self.rpc['restart'])
        self.server.set_pc_view_target_profile(2201, self.pc, self.pawn, self.rpc['view'])
        self.server.set_pc_rotation_profile(2201, self.pc, self.pawn, self.rpc['rotation'])
        self.assertEqual(self.server._pc_restart_profiles[2201][3].exclusive_index_maximum, 244)
        self.assertEqual(self.server._pc_restart_manifests[2201], (self.pc, self.pawn))

    def test_current_and_historical_startup_or_ping_cannot_share_manifest(self):
        from tests.test_legacy_ds_pc_startup_rpc import PROFILE as old_startup
        from tests.test_legacy_ds_pc_ping_receiver import PROFILE as old_ping
        for method, old, current in ((self.server.set_pc_startup_profile, old_startup, self.rpc['startup']),
                                      (self.server.set_pc_ping_profile, old_ping, self.rpc['ping'])):
            with self.assertRaises(ValueError): method(2201, self.pc, old)
            with self.assertRaises(ValueError):
                method(2201, replace(self.pc, current_qualification=None), current)

    def test_current_restart_refuses_unqualified_pawn_and_historical_rpc(self):
        from tests.test_legacy_ds_pc_restart_rpc import PROFILE as old_restart
        self.configure()
        with self.assertRaises(ValueError):
            self.server.set_pc_restart_profile(2201, self.pc,
                replace(self.pawn, current_qualification=None), self.rpc['restart'])
        with self.assertRaises(ValueError):
            self.server.set_pc_restart_profile(2201, self.pc, self.pawn, old_restart)
        self.assertNotIn(2201, self.server._pc_restart_profiles)

    def test_current_game_state_registration_requires_same_actor_qualification(self):
        with self.assertRaises(ValueError):
            self.server.set_game_state_start_profile(2201,
                replace(self.gs, current_qualification=None), self.start)
        self.assertNotIn(2201, self.server._game_state_start_profiles)


if __name__ == '__main__':
    unittest.main()
