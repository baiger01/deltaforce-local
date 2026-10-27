"""Current Actor plan preserves native identity and explicit activation checks."""
import importlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


class UpdatedMapPlanTests(unittest.TestCase):
    def module(self):
        spec = importlib.util.find_spec('updated_map_bootstrap')
        self.assertIsNotNone(spec, 'New declarations must be connected to an Actor plan')
        return importlib.import_module(spec.name)

    def test_five_current_manifests_preflight_without_old_build_identity(self):
        module = self.module()
        plan = module.load_plan()
        from dfserver.legacy_ds_actor_manifest import preflight_actor_manifest
        for role, manifest in plan.actors.items():
            result = preflight_actor_manifest(manifest, channel_sequence=1023, max_packet_bytes=1024)
            self.assertEqual(manifest.client_sha256, module.CURRENT_CLIENT_SHA256)
            self.assertEqual(manifest.local_player_index, 0 if role == 'PlayerController' else None)
            self.assertEqual(manifest.game_replication_flags, 0 if role == 'Pawn' else None)
            self.assertTrue(result.bunch.must_be_mapped)
            self.assertFalse(result.native_acceptance)
        self.assertEqual(plan.start.client_sha256, module.CURRENT_CLIENT_SHA256)
        movement = plan.actors['MovementReplicationActor']
        self.assertEqual(movement.class_path, '/Script/GPGameplay.MovementReplicationActor')
        self.assertEqual(movement.current_qualification.entry_qualification,
                         plan.actors['PlayerController'].current_qualification)

    def test_no_expired_observation_can_enable_the_plan(self):
        plan = self.module().load_plan()
        with self.assertRaisesRegex(ValueError, 'live receiver'):
            plan.install(None)
        with self.assertRaisesRegex(ValueError, 'live receiver'):
            plan.install(None, receiver_guard=lambda: False)

    def test_map_plan_contains_explicit_property_relationships_and_mode(self):
        plan = self.module().load_plan()
        self.assertEqual(len(plan.contents), 3)
        self.assertEqual(plan.summary()['actor_count'], 5)
        self.assertFalse(plan.summary()['native_gameplay_acceptance'])
        self.assertFalse(plan.summary()['random_spawn_activated'])
        self.assertFalse(plan.summary()['loot_or_mandel_activated'])

    def test_current_plan_registers_a_ticket_on_the_existing_local_driver(self):
        module = self.module()
        plan = module.load_plan()
        from dfserver.game_server_probe import GameServerProbe
        control = json.loads((module.ROOT/'outputs/df-local-server/protocol/native_ds_control_profile_79fb7b10.json').read_bytes())
        maps = {int(key): value for key, value in control['control_welcome_maps'].items()}
        with tempfile.TemporaryDirectory() as folder:
            probe = GameServerProbe(Path(folder), handshake_probe=True, packet_ack_probe=True,
                control_probe=True, expected_net_version=control['hello_net_version'],
                control_welcome_maps=maps, require_initial_actor_profile=True).start()
            lease = None
            try:
                lease = plan.install(probe, receiver_guard=lambda: True)
                # Local UID with exact current suit ownership; no native acceptance claim.
                ticket = probe.issue_match_admission(player_id=123, room_id=456, map_id=2201,
                    match_mode_id=1, selected_hero_id=88000000030, selected_fashion_id=30000020005)
                self.assertEqual(ticket.map_id, 2201)
                self.assertIn(ticket.cookie, probe._registered_bootstraps)
                self.assertEqual(len(probe._registered_bootstraps[ticket.cookie]['actor_fields']), 5)
                factory = probe._initial_actor_profiles[2201]['admission_content_factory']
                blocks = factory(123, 88000000030, 30000020005, ())
                block = blocks[0]['content_blocks'][0]
                from dfserver.legacy_ds_bit_archive import BitReader
                reader = BitReader(block.payload, bit_count=block.payload_bit_count)
                self.assertFalse(reader.read_bool())
                decoded = {}
                while (handle := reader.read_packed_int()):
                    decoded[handle] = reader.read_bits(64)
                fields = plan.profile['actors']['PlayerState']['properties']
                self.assertEqual(decoded, {fields[name]['relative_handle']: value for name, value in
                    dict(Uin=123, HeroID=88000000030, CurrSameTeamAvatarId=30000020005,
                         CurrDiffTeamAvatarId=30000020005).items()})
                self.assertEqual(reader.remaining, 0)
                with self.assertRaisesRegex(ValueError, 'selected native operator'):
                    factory(123, 88000000033, 30000020005, ())
            finally:
                probe.close()
                if lease is not None:
                    lease.close()

    def test_all_current_readiness_and_camera_tail_messages_can_be_built(self):
        plan = self.module().load_plan()
        from dfserver.legacy_ds_pc_startup_rpc import build_pc_ready_ack
        from dfserver.legacy_ds_pc_restart_rpc import build_pc_restart
        from dfserver.legacy_ds_pc_view_target_rpc import build_pc_view_target
        from dfserver.legacy_ds_game_state_start import (build_game_state_start,
            build_game_state_all_ready, build_game_state_abseil, build_game_state_real_start,
            build_game_state_match_info)
        pc, pawn, gs = (plan.actors[r] for r in ('PlayerController', 'Pawn', 'GameState'))
        stages = [fn(channel_index=gs.channel_index, channel_sequence=1, profile=plan.start)
            for fn in (build_game_state_start, build_game_state_all_ready,
                       build_game_state_abseil, build_game_state_real_start)]
        stages.append(build_game_state_match_info(channel_index=gs.channel_index, channel_sequence=1,
            profile=plan.start, map_id=2201, room_id=456))
        stages.append(build_pc_ready_ack(channel_index=pc.channel_index, channel_sequence=1,
            profile=plan.rpc['startup']))
        stages.append(build_pc_restart(channel_index=pc.channel_index, channel_sequence=1,
            profile=plan.rpc['restart'], pawn_guid=pawn.actor_guid,
            reference_resolved=True, exports_acknowledged=True))
        stages.append(build_pc_view_target(channel_index=pc.channel_index, channel_sequence=1,
            profile=plan.rpc['view'], actor_guid=pawn.actor_guid,
            reference_resolved=True, exports_acknowledged=True))
        self.assertTrue(all(message.reliable and message.payload_bits > 0 for message in stages))


if __name__ == '__main__':
    unittest.main()
