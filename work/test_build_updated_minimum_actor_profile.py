"""Current minimum compilation must preserve build and transmission boundaries."""
import copy
import importlib
import importlib.util
from pathlib import Path
import unittest


class CurrentMinimumProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = importlib.util.find_spec('build_updated_minimum_actor_profile')
        cls.module = importlib.import_module(cls.spec.name) if cls.spec else None
        cls.root = Path(__file__).resolve().parents[1]

    def compiler(self):
        self.assertIsNotNone(self.module, 'Current source reports need a minimum Actor profile compiler')
        return self.module

    def test_compiles_four_roles_with_current_cache_maximum(self):
        module = self.compiler()
        profile = module.compile_profile(self.root)
        self.assertEqual(set(profile['actors']), {'PlayerController', 'GameState', 'Pawn', 'PlayerState'})
        self.assertEqual(profile['actors']['PlayerController']['exclusive_cache_index_maximum'], 244)
        self.assertEqual(sum(len(a['properties']) for a in profile['actors'].values()), 17)
        self.assertEqual(len(profile['rpc_declarations']), 12)
        self.assertFalse(profile['actor_transmission_enabled'])
        self.assertFalse(profile['native_acceptance_verified'])
        self.assertFalse(profile['runtime_native_cache_observed'])

    def test_preserves_current_prefixes_and_distinguishes_handle_from_cache_index(self):
        module = self.compiler()
        profile = module.compile_profile(self.root)
        pc = profile['actors']['PlayerController']
        pawn = pc['properties']['Pawn']
        self.assertEqual(pawn['relative_handle'], 18)
        prefix = pc['command_prefix']
        self.assertEqual(prefix[pawn['command_index']]['name'], 'Pawn')
        self.assertEqual(prefix[pawn['command_index']]['scope'], [])
        self.assertNotEqual(pawn['relative_handle'], pawn['property_cache_index'])

    def test_enum_widths_are_bits_and_cooked_cdo_belongs_to_selected_class(self):
        profile = self.compiler().compile_profile(self.root)
        pawn = profile['actors']['Pawn']
        self.assertEqual(pawn['properties']['Role']['enum_serialized_bit_width'], 2)
        self.assertEqual(profile['actors']['GameState']['properties']['DFMGamePlayerMode']['enum_serialized_bit_width'], 4)
        for actor in profile['actors'].values():
            self.assertEqual(actor['archetype_path'], actor['package_path'] + '.Default__' +
                actor['class_path'].rsplit('.', 1)[-1])

    def test_source_profile_does_not_select_historical_spawn_coordinates(self):
        profile = self.compiler().compile_profile(self.root)
        for actor in profile['actors'].values():
            self.assertNotIn('location', actor)
            self.assertNotIn('level_path', actor)
            self.assertFalse(actor['constructor_offsets_are_native_runtime_offsets'])

    def test_reuses_qualified_current_restart_recipe(self):
        module = self.compiler()
        profiles = module.rpc_profiles(self.root)
        from dfserver.legacy_ds_pc_restart_rpc import encode_pawn_parameter, decode_pawn_parameter
        raw, bits = encode_pawn_parameter(pawn_guid=2, profile=profiles['restart'],
            reference_resolved=True, exports_acknowledged=True)
        self.assertEqual(decode_pawn_parameter(raw, bits, expected_pawn_guid=2), 2)
        self.assertEqual(profiles['startup'].exclusive_index_maximum, 244)

    def test_modified_source_bytes_are_rejected(self):
        module = self.compiler()
        blobs = module.source_blobs(self.root)
        blobs[module.READINESS_PATH] += b' '
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            module.compile_sources(blobs)

    def test_compiled_document_cannot_be_promoted_or_mixed_with_historical_build(self):
        module = self.compiler()
        good = module.compile_profile(self.root)
        for key, value in (('actor_transmission_enabled', True),
                           ('runtime_native_cache_observed', True),
                           ('client_sha256', '4254' + '0' * 60)):
            changed = copy.deepcopy(good)
            changed[key] = value
            with self.assertRaises(ValueError):
                module.validate_profile(changed, root=self.root)


if __name__ == '__main__':
    unittest.main()
