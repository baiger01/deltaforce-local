"""Standing evaluation uses synthetic curve widths, never production data."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from dfserver import native_quests, native_department_queries as departments
from dfserver.core import Backend
from dfserver.handshake_diagnostic import _candidate_codec


ROOT = Path(__file__).resolve().parent.parent


class NativeQuestConditionTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.backend = Backend(Path(directory.name) / 'save.sqlite3', ROOT / 'definitions.json')
        self.token = self.backend.register('standing-owner', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[])
        self.codec = _candidate_codec()
        self.curve = departments.RepLevelCurve([{'level': 1, 'score': 7},
            {'level': 2, 'score': 11}, {'level': 3, 'score': 13}, {'level': 4, 'score': None}])
        mocked = patch.object(departments, 'reputation_curve', return_value=self.curve)
        mocked.start()
        self.addCleanup(mocked.stop)
        with self.backend.connection() as connection:
            self.player_id = self.backend._authorize(connection, self.token)

    def accept_fixture(self, *quest_ids):
        # Persist accepted source objectives directly to isolate standing evaluation
        # from prerequisite chains; this fixture does not grant production progress.
        with self.backend.connection() as connection:
            for quest_id in quest_ids:
                records = [{'quest_objective_id': value, 'value': 0, 'has_completed': False}
                           for value in native_quests.QUESTS[quest_id]['ObjectiveList']]
                connection.execute('INSERT INTO native_lobby_quest_progress '
                    '(player_id,quest_id,state,accept_time,objectives_json) VALUES (?,?,3,1,?)',
                    (self.player_id, quest_id, json.dumps(records)))
            connection.commit()

    def request(self, name, fields=None):
        request = self.codec.decode(self.codec.encode(name, fields or {}, sequence=73))
        changes = {}
        response = native_quests.response_fields(request, self.backend, self.token, changes=changes)
        self.codec.decode(self.codec.response(request, response))
        return response, changes

    def test_watch_requires_all_five_owned_department_levels_and_repeated_query_is_quiet(self):
        self.accept_fixture(41907)
        with self.backend.connection() as connection:
            connection.executemany('INSERT INTO native_lobby_department_values VALUES (?,?,?)',
                [(self.player_id, ident, 31 if ident != 100006 else 30)
                 for ident in (100001, 100002, 100003, 100004, 100006)])
            connection.commit()
        response, changes = self.request('CSQuestGetPlayerDataReq')
        watch = next(row for row in response['player_quests'] if row['quest_id'] == 41907)
        self.assertEqual(watch['quest_state'], 3)
        self.assertEqual([row['value'] for row in watch['quest_objectives']], [4, 4, 4, 4, 3])
        self.assertEqual(changes['quest_notification']['player_quests'], [watch])
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_department_values SET value=31 '
                'WHERE player_id=? AND quality_id=100006', (self.player_id,))
            connection.commit()
        response, changes = self.request('CSQuestCompleteReq', {'quest_id': 41907})
        self.assertEqual(response['result'], 0)
        self.assertEqual(response['quest_state'], 6)
        self.assertEqual(changes['quest_notification']['player_quests'][0]['quest_state'], 6)
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        response, changes = self.request('CSQuestGetPlayerDataReq')
        self.assertEqual(next(row for row in response['player_quests'] if row['quest_id'] == 41907)['quest_state'], 6)
        self.assertNotIn('quest_notification', changes)
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_quest_reward_receipts').fetchone()[0], 0)

    def test_owned_facility_levels_complete_only_accepted_source_objectives(self):
        self.accept_fixture(39002, 39004, 11001)
        self.backend.set_native_lobby_devices(self.token, {1005: 1, 1006: 1, 1007: 1})
        response, _ = self.request('CSQuestGetPlayerDataReq')
        states = {row['quest_id']: row for row in response['player_quests']}
        self.assertEqual(states[39002]['quest_state'], 6)
        self.assertEqual(states[39004]['quest_state'], 3)
        self.assertEqual([row['value'] for row in states[39004]['quest_objectives']], [1, 1, 0])
        self.assertEqual(states[11001]['quest_state'], 3)
        self.assertFalse(any(row.get('has_completed') for row in states[11001]['quest_objectives']))

    def test_cash_objectives_use_the_owned_wallet_without_spending_or_creating_items(self):
        self.accept_fixture(49001, 49002, 49003, 49004, 49005)
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={17020000010: 100284911}, props=[])
        response, changes = self.request('CSQuestGetPlayerDataReq')
        cash = [row for row in response['player_quests'] if 49001 <= row['quest_id'] <= 49005]
        self.assertEqual(len(cash), 5)
        for row in cash:
            self.assertEqual(row['quest_state'], 6)
            self.assertEqual(row['quest_objectives'][0]['value'], 100284911)
            self.assertTrue(row['quest_objectives'][0]['has_completed'])
        self.assertEqual(len(changes['quest_notification']['player_quests']), 5)
        self.assertNotIn('currency_changes', changes)
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT amount FROM native_lobby_currencies').fetchone()[0], 100284911)
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_props').fetchone()[0], 0)
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_quest_reward_receipts').fetchone()[0], 0)

    def test_cash_tracks_partial_wallet_and_reaches_threshold_after_restart(self):
        self.accept_fixture(49001)
        for amount, state in ((0, 3), (499999, 3), (500000, 6)):
            self.backend.set_native_lobby_profile(self.token, level=60,
                currencies={17020000010: amount}, props=[])
            self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
            response, _ = self.request('CSQuestGetPlayerDataReq')
            row = next(row for row in response['player_quests'] if row['quest_id'] == 49001)
            self.assertEqual(row['quest_state'], state)
            self.assertEqual(row['quest_objectives'][0]['value'], amount)

    def test_incomplete_cash_goal_rejects_manual_submission_without_debit(self):
        from dfserver.client_errors import error_code
        self.accept_fixture(49001)
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={17020000010: 400000}, props=[])
        response, changes = self.request('CSQuestSubmitPropReq', {'quest_id': 49001,
            'submit_list': [{'obj_id': 4900101, 'submit_props': [{'id': 17020000010, 'num': 100}]}]})
        self.assertEqual(response['result'], error_code('QuestObjectiveConfigInvalid'))
        self.assertEqual(changes, {})
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT amount FROM native_lobby_currencies').fetchone()[0], 400000)

    def test_failed_standing_persistence_rolls_back_and_exposes_no_notification(self):
        self.accept_fixture(39002)
        self.backend.set_native_lobby_devices(self.token, {1005: 1})
        with self.backend.connection() as connection:
            connection.execute('CREATE TRIGGER reject_standing BEFORE UPDATE ON native_lobby_quest_progress '
                'BEGIN SELECT RAISE(ABORT, "standing fixture failure"); END')
            connection.commit()
        response, changes = self.request('CSQuestGetPlayerDataReq')
        self.assertNotEqual(response['result'], 0)
        self.assertEqual(changes, {})
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT state FROM native_lobby_quest_progress '
                'WHERE player_id=? AND quest_id=39002', (self.player_id,)).fetchone()[0], 3)

    def test_another_accounts_standing_cannot_complete_owned_objectives(self):
        self.accept_fixture(41907, 39002)
        other_token = self.backend.register('standing-other', 'local-password-123')['session']
        self.backend.set_native_lobby_devices(other_token, {1005: 1})
        with self.backend.connection() as connection:
            other_id = self.backend._authorize(connection, other_token)
            connection.executemany('INSERT INTO native_lobby_department_values VALUES (?,?,?)',
                [(other_id, ident, 31) for ident in (100001, 100002, 100003, 100004, 100006)])
            connection.commit()
        response, _ = self.request('CSQuestGetPlayerDataReq')
        owned = {row['quest_id']: row for row in response['player_quests']}
        self.assertEqual(owned[41907]['quest_state'], 3)
        self.assertTrue(all(row['value'] == 1 for row in owned[41907]['quest_objectives']))
        self.assertEqual(owned[39002]['quest_state'], 3)
        self.assertEqual(owned[39002]['quest_objectives'][0]['value'], 0)

    def test_unavailable_curve_keeps_all_pending_progress_and_emits_no_success(self):
        self.accept_fixture(41907)
        with patch.object(departments, 'reputation_curve', side_effect=ValueError('unavailable fixture')):
            response, changes = self.request('CSQuestGetPlayerDataReq')
        self.assertNotEqual(response['result'], 0)
        self.assertEqual(changes, {})
        with self.backend.connection() as connection:
            saved = connection.execute('SELECT state,objectives_json FROM native_lobby_quest_progress '
                'WHERE player_id=? AND quest_id=41907', (self.player_id,)).fetchone()
            self.assertEqual(saved['state'], 3)
            self.assertTrue(all(row['value'] == 0 for row in json.loads(saved['objectives_json'])))


if __name__ == '__main__':
    unittest.main()
