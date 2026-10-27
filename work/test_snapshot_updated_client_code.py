"""Focused checks for the updated client's isolated code observation."""
import mmap
from pathlib import Path
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import snapshot_updated_client_code as updated


GAME = Path('F:/deltaforce-local-shadow')


class UpdatedClientPlanTests(unittest.TestCase):
    def test_current_disk_plan_has_new_identity_and_no_protocol_claim(self):
        plan = updated.validate_plan(GAME)
        self.assertEqual(plan['client_sha256'],
            '79fb7b105170141ed863331d36833a73062e66bf5291b2364fe3a64c18336203')
        self.assertEqual(plan['maximum_code_bytes'], 349562715)
        self.assertEqual([row['index'] for row in plan['sections']], [0, 8])
        self.assertFalse(plan['native_protocol_compatibility_verified'])
        self.assertEqual(plan['historical_comparison_scope'], 'comparison_only_not_current_layout_qualification')

    def test_changed_disk_byte_is_rejected_without_modifying_the_file(self):
        path = GAME / updated.EXECUTABLE_RELATIVE
        with path.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_COPY) as raw:
            raw[0x2000] ^= 1
            with self.assertRaisesRegex(ValueError, 'SHA'):
                updated.plan_from_image(raw)

    def test_original_installation_cannot_be_collected(self):
        with patch.dict('os.environ', DF_LOCAL_SOURCE_GAME='F:/WeGameApps/rail_apps/DeltaForce(2001918)',
                DF_LOCAL_SHADOW_GAME=str(GAME)):
            with self.assertRaisesRegex(ValueError, 'shadow'):
                updated.collect(Path('F:/WeGameApps/rail_apps/DeltaForce(2001918)'),
                    Path('work/native-code-cache/invalid-source-test'), 1, 1.0)

    def test_invalid_process_identity_is_rejected_before_any_process_read(self):
        with self.assertRaises(ValueError):
            updated.collect(GAME, Path('work/native-code-cache/invalid-process-test'), True, float('nan'))

    def test_update_mode_accepts_only_an_explicit_shadow_lobby_observation(self):
        args = SimpleNamespace(updated_client_code_observation=True, entry='shipping',
            wire_business_bootstrap_probe=True)
        qualified = updated.qualify_launch(args, GAME, GAME)
        self.assertEqual(qualified['client_sha256'], updated.SOURCE_SHA)
        self.assertIn('work/snapshot_updated_client_code.py', qualified['source_pins'])

    def test_update_mode_rejects_old_map_or_metadata_features(self):
        for option in ('game_server_probe', 'replication_metadata_export',
                'ds_control_probe', 'portable_map_bootstrap', 'connection_binding_observation'):
            with self.subTest(option=option):
                args = SimpleNamespace(updated_client_code_observation=True, entry='shipping',
                    wire_business_bootstrap_probe=True, **{option: True})
                with self.assertRaises(ValueError):
                    updated.qualify_launch(args, GAME, GAME)

    def test_old_mode_is_not_silently_approved_for_the_updated_client(self):
        self.assertIsNone(updated.qualify_launch(SimpleNamespace(
            updated_client_code_observation=False), GAME, GAME))

    def test_explicit_updated_metadata_mode_has_separate_proven_scope(self):
        args = SimpleNamespace(updated_client_metadata_observation=True, entry='shipping',
            wire_business_bootstrap_probe=True)
        qualified = updated.qualify_launch(args, GAME, GAME)
        self.assertEqual(qualified['mode'], 'updated_class_metadata')
        self.assertIn('work/updated_client_metadata.py', qualified['source_pins'])
        self.assertFalse(qualified['native_protocol_compatibility_verified'])

    def test_code_and_metadata_cannot_be_requested_as_one_ambiguous_mode(self):
        args = SimpleNamespace(updated_client_code_observation=True,
            updated_client_metadata_observation=True, entry='shipping', wire_business_bootstrap_probe=True)
        with self.assertRaisesRegex(ValueError, 'mode'):
            updated.qualify_launch(args, GAME, GAME)

    def test_transport_observation_permits_only_handshake_and_packet_capture(self):
        args = SimpleNamespace(updated_client_transport_observation=True, entry='shipping',
            wire_business_bootstrap_probe=True, game_server_probe=True,
            ds_handshake_probe=True, ds_packet_ack_probe=True, ds_join_after_ready=True, ds_map_id=2201)
        result = updated.qualify_launch(args, GAME, GAME)
        self.assertEqual(result['mode'], 'updated_transport_capture')
        self.assertFalse(result['native_protocol_compatibility_verified'])
        args.ds_control_probe = True
        with self.assertRaises(ValueError):
            updated.qualify_launch(args, GAME, GAME)

    def test_transport_observation_requires_its_explicit_lower_layers(self):
        args = SimpleNamespace(updated_client_transport_observation=True, entry='shipping',
            wire_business_bootstrap_probe=True, game_server_probe=True, ds_handshake_probe=True)
        with self.assertRaisesRegex(ValueError, 'transport'):
            updated.qualify_launch(args, GAME, GAME)

    def test_updated_control_requires_current_source_qualified_profile(self):
        shadow = Path('F:/deltaforce-local-shadow-build-79fb7b10')
        profile = updated.ROOT/'outputs/df-local-server/protocol/native_ds_control_profile_79fb7b10.json'
        args = SimpleNamespace(updated_client_transport_observation=True, entry='shipping',
            wire_business_bootstrap_probe=True, game_server_probe=True,
            ds_handshake_probe=True, ds_packet_ack_probe=True, ds_join_after_ready=True,
            ds_map_id=2201, ds_control_probe=True, ds_control_profile=profile,
            disable_device_seamless=True, disable_dynamic_address_switch=True,
            enable_sol_map_entry_loading=True)
        result = updated.qualify_launch(args, shadow, shadow)
        self.assertEqual(result['mode'], 'updated_control_capture')
        self.assertIn(profile.relative_to(updated.ROOT).as_posix(), result['source_pins'])
        self.assertFalse(result['native_protocol_compatibility_verified'])
        args.ds_initial_actor_bootstrap = True
        with self.assertRaises(ValueError):
            updated.qualify_launch(args, shadow, shadow)

    def test_updated_control_cannot_use_the_historical_profile(self):
        args = SimpleNamespace(updated_client_transport_observation=True, entry='shipping',
            wire_business_bootstrap_probe=True, game_server_probe=True,
            ds_handshake_probe=True, ds_packet_ack_probe=True, ds_join_after_ready=True,
            ds_map_id=2201, ds_control_probe=True, disable_device_seamless=True,
            ds_control_profile=updated.ROOT/'outputs/df-local-server/protocol/native_ds_wire_profile.json')
        with self.assertRaises(ValueError):
            updated.qualify_launch(args, GAME, GAME)

    def test_current_metadata_can_be_explicitly_bound_to_control_after_map_load(self):
        shadow = Path('F:/deltaforce-local-shadow-build-79fb7b10')
        args = SimpleNamespace(updated_client_transport_observation=True,
            updated_client_metadata_observation=True, entry='shipping',
            wire_business_bootstrap_probe=True, game_server_probe=True,
            ds_handshake_probe=True, ds_packet_ack_probe=True, ds_join_after_ready=True,
            ds_map_id=2201, ds_control_probe=True, disable_device_seamless=True,
            ds_control_profile=updated.ROOT/'outputs/df-local-server/protocol/native_ds_control_profile_79fb7b10.json')
        result = updated.qualify_launch(args, shadow, shadow)
        self.assertEqual(result['mode'], 'updated_control_metadata_capture')
        self.assertIn('work/observe_updated_client_metadata.py', result['source_pins'])
        args.ds_control_probe = False
        with self.assertRaises(ValueError):
            updated.qualify_launch(args, shadow, shadow)

    def test_worker_environment_handoff_matches_wrapper_qualified_scope(self):
        shadow = Path('F:/deltaforce-local-shadow-build-79fb7b10')
        args = SimpleNamespace(updated_client_transport_observation=True,
            updated_client_metadata_observation=True, entry='shipping',
            wire_business_bootstrap_probe=True, game_server_probe=True,
            ds_handshake_probe=True, ds_packet_ack_probe=True, ds_control_probe=True,
            disable_device_seamless=True,
            ds_control_profile=updated.ROOT/'outputs/df-local-server/protocol/native_ds_control_profile_79fb7b10.json')
        with patch.dict('os.environ', DF_LOCAL_DS_JOIN_PROBE_AFTER_READY='1', DF_LOCAL_DS_MAP_ID='2201'):
            worker = updated.qualify_launch(args, shadow, shadow)
        args.ds_join_after_ready, args.ds_map_id = True, 2201
        wrapper = updated.qualify_launch(args, shadow, shadow)
        self.assertEqual(worker, wrapper)


if __name__ == '__main__':
    unittest.main()
