"""Service checks; every numeric reputation curve below is a synthetic fixture."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from dfserver import native_department_queries as queries, native_departments, native_quests
from dfserver.core import Backend
from dfserver.handshake_diagnostic import _candidate_codec

ROOT = Path(__file__).resolve().parent.parent


def synthetic_curve_rows():
    """Algorithm-only widths, deliberately unrelated to installed client values."""
    return [{'level': level, 'score': 20 if level < 20 else 30 if level < 50 else 40}
            for level in range(1, 80)] + [{'level': 80, 'score': 0}]


class ReputationCurveTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(queries, 'Department query service is not implemented')

    def test_synthetic_baseline_and_maximum_keep_cumulative_value_semantics(self):
        curve = queries.RepLevelCurve(synthetic_curve_rows())
        self.assertEqual(curve.max_level, 80)
        for value, expected in ((0, 1), (19, 1), (20, 2), (2480, 80), (2**63 - 1, 80)):
            with self.subTest(value=value):
                self.assertEqual(curve.level_for(value), expected)

    def test_synthetic_19_to_20_49_to_50_and_79_to_80_boundaries(self):
        curve = queries.RepLevelCurve(synthetic_curve_rows())
        for threshold, previous in ((380, 19), (1280, 49), (2480, 79)):
            with self.subTest(threshold=threshold):
                self.assertEqual(curve.level_for(threshold - 1), previous)
                self.assertEqual(curve.level_for(threshold), previous + 1)

    def test_terminal_score_does_not_create_an_extra_level(self):
        rows = [{'level': 1, 'score': 2}, {'level': 2, 'score': 500}]
        curve = queries.RepLevelCurve(rows)
        self.assertEqual(curve.level_for(501), 2)
        self.assertEqual(curve.level_for(502), 2)
        self.assertEqual(curve.configs(), rows)

    def test_unrecovered_terminal_score_is_omitted_without_changing_maximum(self):
        rows = [{'level': 1, 'score': 2}, {'level': 2, 'score': 3},
                {'level': 3, 'score': 5}, {'level': 4, 'score': None}]
        curve = queries.RepLevelCurve(rows)
        self.assertEqual(curve.level_for(9), 3)
        self.assertEqual(curve.level_for(10), 4)
        self.assertEqual(curve.level_for(1000), 4)
        self.assertEqual(curve.configs()[-1], {'level': 4})

    def test_curve_requires_unique_contiguous_levels_and_positive_normal_widths(self):
        invalid = ([], [{'level': 2, 'score': 1}],
                   [{'level': 1, 'score': 1}, {'level': 1, 'score': 0}],
                   [{'level': 1, 'score': 1}, {'level': 3, 'score': 0}],
                   [{'level': 1, 'score': 0}, {'level': 2, 'score': 0}],
                   [{'level': 1, 'score': -1}], [{'level': True, 'score': 0}],
                   [{'level': 1, 'score': None}, {'level': 2, 'score': 0}],
                   [{'level': 1, 'score': False}], [{'level': 1, 'score': 1.5}],
                   [{'level': 1, 'score': 2**63}],
                   [{'level': 1, 'score': 2**63 - 1}, {'level': 2, 'score': 1},
                    {'level': 3, 'score': 0}])
        for rows in invalid:
            with self.subTest(rows=rows):
                with self.assertRaises(ValueError):
                    queries.RepLevelCurve(rows)

    def test_invalid_cumulative_values_are_rejected(self):
        curve = queries.RepLevelCurve(synthetic_curve_rows())
        for value in (-1, True, 1.5, '20', 2**63):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    curve.level_for(value)

    def test_configs_cannot_mutate_the_validated_curve(self):
        rows = synthetic_curve_rows()
        curve = queries.RepLevelCurve(rows)
        rows[0]['score'] = 999
        returned = curve.configs()
        returned[0]['score'] = 999
        self.assertEqual(curve.level_for(20), 2)
        self.assertEqual(curve.configs()[0]['score'], 20)

    def test_path_loader_requires_a_verified_source_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'synthetic-curve-fixture.json'
            fixture = {'mapping_status': 'synthetic_test_fixture',
                       'levels': synthetic_curve_rows(),
                       'sources': {'fixture': {'url': 'https://example.invalid/synthetic-fixture',
                           'scope': 'Algorithm test only; not original client evidence'}}}
            path.write_text(json.dumps(fixture), encoding='utf-8')
            with self.assertRaises(ValueError):
                queries.load_curve(path)
            # A marker is tested as a loader contract, not evidence of client data.
            fixture['mapping_status'] = 'verified_recorded_native_client_progress'
            path.write_text(json.dumps(fixture), encoding='utf-8')
            self.assertEqual(queries.load_curve(path).max_level, 80)

    def test_loader_requires_source_references_and_unknown_terminal_marker(self):
        fixture = {'mapping_status': 'verified_recorded_native_client_progress',
                   'levels': [{'level': 1, 'score': 2}, {'level': 2, 'score': None}],
                   'terminal_score_unrecovered': True,
                   'sources': {'fixture': {'sha256': '0' * 64,
                       'scope': 'Synthetic algorithm fixture, not client evidence'}}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'synthetic-unknown-terminal.json'
            path.write_text(json.dumps(fixture), encoding='utf-8')
            self.assertEqual(queries.load_curve(path).configs()[-1], {'level': 2})
            fixture['terminal_score_unrecovered'] = False
            path.write_text(json.dumps(fixture), encoding='utf-8')
            with self.assertRaises(ValueError):
                queries.load_curve(path)
            fixture['terminal_score_unrecovered'] = 1
            path.write_text(json.dumps(fixture), encoding='utf-8')
            with self.assertRaises(ValueError):
                queries.load_curve(path)
            fixture['terminal_score_unrecovered'] = True
            fixture['sources'] = {'fixture': 'No URL or hash reference'}
            path.write_text(json.dumps(fixture), encoding='utf-8')
            with self.assertRaises(ValueError):
                queries.load_curve(path)

    def test_line_open_policy_checks_season_level_and_all_completion_limits(self):
        line = {'OpenLevel': 5, 'OpenLimits': [11001, 11002]}
        self.assertFalse(queries.line_is_open(line, 4, {11001, 11002}))
        self.assertFalse(queries.line_is_open(line, 5, {11001}))
        self.assertTrue(queries.line_is_open(line, 5, {11001, 11002}))


class NativeDepartmentQueryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.codec = _candidate_codec()

    def setUp(self):
        self.assertIsNotNone(queries, 'Department query service is not implemented')
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.backend = Backend(Path(self.directory.name) / 'save.sqlite3', ROOT / 'definitions.json')
        self.token = self.backend.register('department-owner', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=1, currencies={}, props=[])
        with self.backend.connection() as connection:
            connection.executescript(native_departments.SCHEMA + native_quests.SCHEMA)
            self.player_id = self.backend._authorize(connection, self.token)
        self.curve = queries.RepLevelCurve(synthetic_curve_rows())

    def request(self, name, *, curve=True, token=None, **options):
        request = self.codec.decode(self.codec.encode(name, {}, sequence=31))
        if curve:
            options['curve'] = self.curve
        result = queries.response_fields(request, self.backend, token or self.token, **options)
        self.codec.decode(self.codec.response(request, result))
        return result

    def test_baseline_contains_five_active_cards_with_independent_levels(self):
        result = self.request('CSAttrGetAllQualityReq')
        cards = {row['card_id']: row for row in result['all_quality']}
        self.assertEqual(result['result'], 0)
        self.assertEqual(set(cards), {100001, 100002, 100003, 100004, 100006})
        self.assertEqual({key for key, row in cards.items() if row['is_unlock']}, {100002, 100004})
        for row in cards.values():
            self.assertEqual(row['quality_value'], 0)
            self.assertEqual(row['level'], 1)
            self.assertNotIn('unlock_time', row)
            self.assertNotIn('is_disabled', row)

    def test_native_config_uses_line_ids_and_original_assets_without_guessed_usages(self):
        result = self.request('CSGetRoleQualityConfigReq', curve=False)
        self.assertEqual(result['result'], 0)
        self.assertEqual(len(result['configs']), 5)
        for config, source in zip(result['configs'], native_departments.CATALOG['departments']):
            self.assertEqual(config, {'quality_id': source['card_id'], 'name': '',
                'quest_id': source['quest_line_id'], 'img_path': source['ImgPath'],
                'sprite_path': source['SpritePath'], 'cover_img_path': source['CoverImgPath'],
                'quality_usages': []})
            self.assertNotEqual(config['quest_id'], source['root_quest_id'])

    def test_attribute_config_returns_complete_synthetic_curve_and_no_load_row_guesses(self):
        result = self.request('CSAttributeGetConfigReq')
        self.assertEqual(result, {'result': 0, 'load_configs': [],
                                  'rep_level_configs': synthetic_curve_rows()})

    def test_attribute_config_can_omit_an_explicitly_unrecovered_terminal_score(self):
        fixture = {'mapping_status': 'verified_recorded_native_client_progress',
            'levels': [{'level': 1, 'score': 2}, {'level': 2, 'score': None}],
            'terminal_score_unrecovered': True,
            'sources': {'fixture': {'url': 'https://example.invalid/synthetic-fixture'}}}
        request = self.codec.decode(self.codec.encode('CSAttributeGetConfigReq', {}, sequence=31))
        result = queries.response_fields(request, self.backend, self.token, curve=fixture)
        self.codec.decode(self.codec.response(request, result))
        self.assertEqual(result, {'result': 0, 'load_configs': [], 'rep_level_configs': [
            {'level': 1, 'score': 2}, {'level': 2}]})

    def test_missing_curve_is_an_error_instead_of_empty_success_or_maximum_cards(self):
        with patch.object(queries, 'reputation_curve', side_effect=FileNotFoundError('missing curve')):
            for name in ('CSAttributeGetConfigReq', 'CSAttrGetAllQualityReq'):
                with self.subTest(name=name):
                    result = self.request(name, curve=False)
                    self.assertEqual(result, {'result': 109002})

    def test_packaged_evidence_curve_restores_numeric_department_queries(self):
        config = self.request('CSAttributeGetConfigReq', curve=False)
        self.assertEqual(config['result'], 0)
        self.assertEqual(config['rep_level_configs'], [
            {'level': 1, 'score': 20}, {'level': 2, 'score': 30},
            {'level': 3, 'score': 30}, {'level': 4}])
        result = self.request('CSAttrGetAllQualityReq', curve=False)
        self.assertEqual(result['result'], 0)
        self.assertEqual([row['level'] for row in result['all_quality']], [1] * 5)

    def test_invalid_curve_is_an_explicit_failure(self):
        result = self.request('CSAttributeGetConfigReq', curve=False,
                              curve_path=Path(self.directory.name) / 'missing-curve.json')
        self.assertEqual(result, {'result': 109002})

    def test_unlock_policy_reads_current_owned_level_without_persisting_cards(self):
        self.request('CSAttrGetAllQualityReq')
        self.backend.set_native_lobby_profile(self.token, level=16, currencies={}, props=[])
        cards = self.request('CSAttrGetAllQualityReq')['all_quality']
        self.assertTrue(all(row['is_unlock'] for row in cards))
        self.assertTrue(all(row['level'] == 1 for row in cards))
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute(
                'SELECT COUNT(*) FROM native_lobby_department_values').fetchone()[0], 0)

    def test_rewarded_cumulative_value_survives_restart_and_is_scoped_to_owner(self):
        source = next(iter(native_departments.QUALITY_REWARDS.values()))
        with self.backend.connection() as connection:
            native_departments.grant_reward(connection, self.player_id, source['quest_id'],
                {'RewardID': source['reward_id'], 'ItemID': source['item_id'], 'Number': source['amount']})
            connection.commit()
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        cards = self.request('CSAttrGetAllQualityReq')['all_quality']
        owned = next(row for row in cards if row['card_id'] == source['quality_id'])
        self.assertEqual(owned['quality_value'], source['amount'])
        self.assertEqual(owned['level'], self.curve.level_for(source['amount']))
        other = self.backend.register('department-other', 'local-password-123')['session']
        self.assertTrue(all(row['quality_value'] == 0
            for row in self.request('CSAttrGetAllQualityReq', token=other)['all_quality']))

    def test_saved_value_at_maximum_is_preserved_without_clamping_reward_balance(self):
        with self.backend.connection() as connection:
            connection.execute('INSERT INTO native_lobby_department_values VALUES (?,?,?)',
                               (self.player_id, 100002, 2**63 - 1))
            connection.commit()
        owned = next(row for row in self.request('CSAttrGetAllQualityReq')['all_quality']
                     if row['card_id'] == 100002)
        self.assertEqual((owned['level'], owned['quality_value']), (80, 2**63 - 1))

    def test_every_query_requires_authentication(self):
        for name in queries.SUPPORTED_REQUESTS:
            with self.subTest(name=name):
                result = self.request(name, token='invalid-local-session')
                self.assertNotEqual(result['result'], 0)
                self.assertEqual(set(result), {'result'})

    def test_unrelated_query_is_left_to_its_existing_handler(self):
        request = self.codec.decode(self.codec.encode('CSMallGetUnlockDepartmentReq', {}, sequence=31))
        self.assertIsNone(queries.response_fields(request, self.backend, self.token, curve=self.curve))


if __name__ == '__main__':
    unittest.main()
