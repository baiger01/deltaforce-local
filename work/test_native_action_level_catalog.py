import copy
import json
import unittest

from extract_native_action_level_catalog import EXPECTED_TABLE, OUTPUT, validate_rows


class NativeActionLevelCatalogTests(unittest.TestCase):
    def setUp(self):
        self.catalog = json.loads(OUTPUT.read_text(encoding='utf-8'))
        self.rows = copy.deepcopy(self.catalog['levels'])

    def test_saved_curve_retains_the_complete_original_native_schema_and_source(self):
        validate_rows(self.rows)
        self.assertEqual(self.catalog['source']['sha256'], EXPECTED_TABLE)
        self.assertEqual(self.catalog['source']['pak_offset'], 50371705)
        self.assertEqual(self.catalog['source']['native']['struct'], 'SeasonLevel')
        self.assertEqual([(row['name'], row['kind']) for row in self.catalog['source']['native']['columns']],
                         [('Level', 'int32'), ('Experience', 'FString'), ('LevelPrize', 'FString'),
                          ('Unlock1', 'FString'), ('Unlock2', 'FString')])
        self.assertEqual((self.rows[0]['Experience'], self.rows[1]['Experience'],
                          self.rows[-1]['Experience']), ('2000', '2500', '0'))

    def test_missing_duplicate_or_reordered_source_levels_are_rejected(self):
        for corrupted in (self.rows[:-1], [self.rows[0], *self.rows], list(reversed(self.rows))):
            with self.subTest(count=len(corrupted)), self.assertRaises(ValueError):
                validate_rows(corrupted)

    def test_interior_zero_and_non_decimal_experience_are_rejected(self):
        for value in ('0', '-1', '1.5', '', '100;200'):
            changed = copy.deepcopy(self.rows)
            changed[15]['Experience'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_rows(changed)

    def test_changed_terminal_level_or_unhandled_reward_columns_are_rejected(self):
        changed = copy.deepcopy(self.rows)
        changed[-1]['Experience'] = '42000'
        with self.assertRaises(ValueError):
            validate_rows(changed)
        for name in ('LevelPrize', 'Unlock1', 'Unlock2'):
            changed = copy.deepcopy(self.rows)
            changed[0][name] = 'diagnostic-unrecovered-value'
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_rows(changed)


if __name__ == '__main__':
    unittest.main()
