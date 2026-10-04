"""Independent registration-time graph-conflict regressions; synthetic only."""

from dataclasses import replace
import tempfile
import unittest
from unittest.mock import PropertyMock, patch

from dfserver.game_server_probe import GameServerProbe
from dfserver.legacy_ds_actor_manifest import preflight_actor_manifest
from dfserver.legacy_ds_guid_exports import GuidExportNode
from tests.test_legacy_ds_actor_bootstrap import manifest
from tests.test_legacy_ds_control_connection import MAPS


def conflicting_manifests():
    first = manifest()
    package = GuidExportNode(3, '/Game/Test/OtherPawn')
    cls = replace(first.exports[0], outer=package)
    template = replace(first.exports[1], outer=package)
    bindings = tuple(replace(binding, full_path=binding.full_path.replace(
        '/Game/Test/Pawn', package.path)) if binding.guid in (3, 5, 7)
        else binding for binding in first.path_bindings)
    second = replace(first, actor_guid=4, channel_index=2,
        class_path=bindings[1].full_path, archetype_path=bindings[2].full_path,
        path_bindings=bindings, exports=(cls, template, first.exports[2]))
    return first, second


class RegistrationGraphConflictReviewTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.server = GameServerProbe(folder.name, handshake_probe=True, packet_ack_probe=True,
            control_probe=True, expected_net_version=1077088301, control_welcome_maps=MAPS)
        self.addCleanup(self.server.close)
        self.listen = patch.object(GameServerProbe, 'listening',
            new_callable=PropertyMock, return_value=True)
        self.listen.start()
        self.addCleanup(self.listen.stop)
        self.manifests = conflicting_manifests()
        # Each is internally valid; the fault exists only in the combined graph.
        for item in self.manifests:
            preflight_actor_manifest(item, channel_sequence=1023, max_packet_bytes=1024)

    def test_map_profile_rejects_cross_manifest_guid_conflict_before_configuration(self):
        with self.assertRaises(ValueError):
            self.server.set_initial_actor_manifests(2201, self.manifests)
        self.assertEqual(self.server._initial_actor_profiles, {})

    def test_ticket_registration_rejects_combined_graph_before_installing_set(self):
        ticket = self.server.issue_match_admission(player_id=101, room_id=201,
            map_id=2201, match_mode_id=142201103)
        with self.assertRaises(ValueError):
            self.server.register_initial_actor_manifests(ticket, self.manifests)
        self.assertEqual(self.server._registered_bootstraps, {})
        self.assertEqual(self.server._bootstrap_events['registered_sets'], 0)
        self.assertTrue(self.server._admissions.is_active(ticket))


if __name__ == '__main__':
    unittest.main()
