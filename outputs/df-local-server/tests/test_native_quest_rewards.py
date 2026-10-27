import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from dfserver import native_quests
from dfserver.core import Backend
from dfserver.handshake_diagnostic import _candidate_codec


ROOT = Path(__file__).resolve().parent.parent


class NativeQuestRewardTests(unittest.TestCase):
    def setUp(self):
        from dfserver import native_department_queries as queries
        from test_native_departments import synthetic_curve_rows
        curve_patch = patch.object(queries, 'reputation_curve',
                                  return_value=queries.RepLevelCurve(synthetic_curve_rows()))
        curve_patch.start()
        self.addCleanup(curve_patch.stop)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.database = Path(directory.name) / 'save.sqlite3'
        self.config = Path(directory.name) / 'completion.json'
        self.config.write_text(json.dumps({'enabled': True, 'complete_all': False,
            'complete_quest_ids': [11001, 21001, 49001]}), encoding='utf-8')
        self.backend = Backend(self.database, ROOT / 'definitions.json',
                               quest_completion_config=self.config)
        self.token = self.backend.register('reward-owner', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[])
        self.codec = _candidate_codec()
        self.request('CSQuestGetPlayerDataReq')

    def request(self, name, fields=None, changes=None):
        request = self.codec.decode(self.codec.encode(name, fields or {}, sequence=73))
        result = native_quests.response_fields(request, self.backend, self.token, changes=changes)
        if result is not None:
            self.codec.decode(self.codec.response(request, result))
        return result

    def test_claim_grants_all_source_rewards_once_and_survives_restart(self):
        changes = {}
        result = self.request('CSQuestGetRewardReq', {'quest_id': 11001}, changes)
        self.assertIsNotNone(result)
        self.assertEqual(result['result'], 0)
        self.assertEqual(result['quest_state'], 7)
        self.assertEqual(changes['currency_changes'], [{'currency_id': 17020000010,
                          'delta': 15000, 'current_num': 15000}])
        profile = self.backend.native_lobby_profile(self.token)
        self.assertEqual(len(profile['props']), 1)
        weapon = profile['props'][0]
        # Original GunPreset10010001050 root is receiver18010000031.
        self.assertEqual(weapon['template_id'], 18010000031)
        self.assertEqual(weapon['quantity'], 1)
        self.assertEqual(weapon['bind_type'], 0)
        self.assertTrue(weapon['components'])
        self.assertEqual(result['deposit_change']['currency_changes'], changes['currency_changes'])
        self.assertEqual(changes['quest_notification']['player_quests'][0]['quest_state'], 7)
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT xp FROM players').fetchone()[0], 1200)
            self.assertEqual(connection.execute('SELECT quality_id,value FROM native_lobby_department_values').fetchone()[:],
                             (100002, 1))
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_quest_reward_receipts').fetchone()[0], 4)
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        changes = {}
        self.assertEqual(self.request('CSQuestGetRewardReq', {'quest_id': 11001}, changes)['result'], 122005)
        self.assertEqual(changes, {})
        self.assertEqual(self.backend.native_lobby_profile(self.token)['props'], profile['props'])

    def test_claim_failure_rolls_back_grants_score_and_reward_state(self):
        with self.backend.connection() as connection:
            connection.execute('CREATE TRIGGER reject_reward BEFORE UPDATE ON native_lobby_quest_progress '
                'WHEN NEW.state=7 BEGIN SELECT RAISE(ABORT, "simulated reward persistence failure"); END')
            connection.commit()
        changes = {}
        result = self.request('CSQuestGetRewardReq', {'quest_id': 11001}, changes)
        self.assertIsNotNone(result)
        self.assertNotEqual(result['result'], 0)
        self.assertEqual(changes, {})
        self.assertEqual(self.backend.native_lobby_profile(self.token)['props'], [])
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT xp FROM players').fetchone()[0], 0)
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_action_progress').fetchone()[0], 0)
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_department_values').fetchone()[0], 0)
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_currencies').fetchone()[0], 0)
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_quest_reward_receipts').fetchone()[0], 0)
            self.assertEqual(connection.execute('SELECT state FROM native_lobby_quest_progress '
                                               'WHERE quest_id=11001').fetchone()[0], 6)

    def test_claim_requires_this_accounts_completed_quest(self):
        self.token = self.backend.register('reward-other', 'local-password-123')['session']
        changes = {}
        result = self.request('CSQuestGetRewardReq', {'quest_id': 11001}, changes)
        self.assertIsNotNone(result)
        self.assertNotEqual(result['result'], 0)
        self.assertEqual(changes, {})
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT SUM(xp) FROM players').fetchone()[0], 0)

    def test_medical_physical_reward_uses_real_template_count_and_binding(self):
        result = self.request('CSQuestGetRewardReq', {'quest_id': 21001})
        self.assertIsNotNone(result)
        self.assertEqual(result['result'], 0)
        props = self.backend.native_lobby_profile(self.token)['props']
        self.assertEqual(sum(row['quantity'] for row in props if row['template_id'] == 14020000004), 2)
        self.assertTrue(all(row['bind_type'] == 0 for row in props))

    def test_full_warehouse_does_not_consume_the_claim(self):
        from dfserver.premium_shop import ITEMS
        from dfserver.native_warehouse_extensions import warehouse_grid
        with self.backend.connection() as connection:
            columns, rows = warehouse_grid(connection, self.backend._authorize(connection, self.token), 2)
        item_id = next(int(key) for key, row in ITEMS.items() if
            row['length'] == row['width'] == 1 and row['max_stack_count'] == 1 and
            not row['is_currency'] and int(key) != 14020000004)
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[
            {'gid': 10000 + y * columns + x, 'template_id': item_id, 'quantity': 1,
             'grid_page_id': 2, 'x': x, 'y': y, 'length': 1, 'width': 1}
            for y in range(rows) for x in range(columns)])
        changes = {}
        result = self.request('CSQuestGetRewardReq', {'quest_id': 21001}, changes)
        self.assertEqual(result['result'], 122006)
        self.assertEqual(changes, {})
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_props').fetchone()[0], columns * rows)
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_quest_reward_receipts').fetchone()[0], 0)
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_department_values').fetchone()[0], 0)
            self.assertEqual(connection.execute('SELECT xp FROM players').fetchone()[0], 0)

    def test_unresolved_quality_context_cannot_partially_reward(self):
        self.config.write_text(json.dumps({'enabled': True, 'complete_all': False,
            'complete_quest_ids': [60001]}), encoding='utf-8')
        self.backend = Backend(self.database, ROOT / 'definitions.json', quest_completion_config=self.config)
        self.request('CSQuestGetPlayerDataReq')
        changes = {}
        result = self.request('CSQuestGetRewardReq', {'quest_id': 60001}, changes)
        self.assertEqual(result['result'], 122037)
        self.assertEqual(changes, {})
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_quest_reward_receipts').fetchone()[0], 0)
            self.assertEqual(connection.execute('SELECT xp FROM players').fetchone()[0], 0)

    def test_hero_reward_is_the_original_watch_and_updates_cosmetic_ownership(self):
        from dfserver import hero_customization
        watch_id = 38070040001
        hero_id = min(hero_customization.BASES)
        before = hero_customization.hero_records(self.backend, self.token, [hero_id])[0]
        self.assertFalse(next(row for row in before['accessories'] if
                              row['item']['prop_id'] == watch_id)['is_unlock'])
        self.config.write_text(json.dumps({'enabled': True, 'complete_all': False,
            'complete_quest_ids': [41907]}), encoding='utf-8')
        self.backend = Backend(self.database, ROOT / 'definitions.json', quest_completion_config=self.config)
        self.request('CSQuestGetPlayerDataReq')
        changes = {}
        result = self.request('CSQuestGetRewardReq', {'quest_id': 41907}, changes)
        self.assertEqual(result['result'], 0)
        after = hero_customization.hero_records(self.backend, self.token, [hero_id])[0]
        self.assertTrue(next(row for row in after['accessories'] if
                             row['item']['prop_id'] == watch_id)['is_unlock'])
        self.assertIn(after, changes['hero_notification']['heros'])


if __name__ == '__main__':
    unittest.main()
