"""Current PAK identities must precede admission appearance replication."""
import importlib
import importlib.util
import unittest


class UpdatedPlayerAppearanceTests(unittest.TestCase):
    def module(self):
        spec = importlib.util.find_spec('updated_player_appearance')
        self.assertIsNotNone(spec, 'Admission needs current Fashion/Avatar source binding')
        return importlib.import_module(spec.name)

    def test_current_tables_resolve_both_views_without_historical_name_maps(self):
        module = self.module()
        current = module.appearance_context()
        self.assertEqual(current['verified_archive_count'], 257)
        self.assertEqual(current['fashion_row_count'], 61)
        self.assertEqual(current['avatar_row_count'], 252)
        self.assertEqual(module.avatar_ids(current, 88000000030, 30000020005),
                         (88000000030, 30000020005, 30000020005))
        self.assertEqual(current['unmapped_fashion_ids'], ['30000020001', '30000040003'])

    def test_wrong_operator_or_unmapped_suit_is_not_redirected(self):
        module = self.module()
        current = module.appearance_context()
        with self.assertRaisesRegex(ValueError, 'selected native operator'):
            module.avatar_ids(current, 88000000033, 30000020005)
        with self.assertRaisesRegex(ValueError, 'native human avatar'):
            module.avatar_ids(current, 88000000033, 30000020001)

    def test_changed_payload_cannot_qualify_as_current(self):
        module = self.module()
        blobs = module.appearance_sources()
        payload = next(path for path in blobs if path.endswith('CharacterAvatarData.uexp'))
        blobs[payload] = blobs[payload][:-1] + bytes([blobs[payload][-1] ^ 1])
        with self.assertRaisesRegex(ValueError, 'payload SHA256'):
            module.derive_appearance(blobs)


if __name__ == '__main__':
    unittest.main()
