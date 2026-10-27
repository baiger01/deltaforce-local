"""Use current cooked ownership, never an inferred UE Level name."""
import importlib
import importlib.util
import unittest


class UpdatedMapSceneTests(unittest.TestCase):
    def module(self):
        spec = importlib.util.find_spec('updated_map_scene')
        self.assertIsNotNone(spec, 'Current Actor bootstrap needs its current scene contract')
        return importlib.import_module(spec.name)

    def test_world_level_chain_comes_from_current_export_records(self):
        scene = self.module().scene_context()
        self.assertEqual(scene['level_path'], '/Game/Maps/Iris_Entry/Iris_Entry.Iris_Entry:PersistentLevel')
        self.assertEqual((scene['world_export']['index'], scene['level_export']['index']), (25, 15))
        self.assertEqual(scene['level_export']['outer_index'], scene['world_export']['index'])
        self.assertEqual(scene['verified_archive_count'], 257)
        self.assertFalse(scene['runtime_world_origin_observed'])
        self.assertNotIn('world_origin', scene)

    def test_modified_map_payload_is_rejected(self):
        module = self.module()
        blobs = module.scene_sources()
        key = next(path for path in blobs if path.endswith('.uexp'))
        blobs[key] = blobs[key][:-1] + bytes([blobs[key][-1] ^ 1])
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            module.derive_scene(blobs)


if __name__ == '__main__':
    unittest.main()
