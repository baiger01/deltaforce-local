"""Wallet refresh operates on committed balances in disposable accounts only."""

import importlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from dfserver import native_quests
from dfserver.core import Backend
from dfserver.handshake_diagnostic import _candidate_codec
from dfserver.premium_shop import currency_change


ROOT = Path(__file__).resolve().parent.parent
HAF = 17020000010


class NativeQuestWalletTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.backend = Backend(Path(directory.name) / 'save.sqlite3', ROOT / 'definitions.json')
        self.token = self.backend.register('wallet-owner', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[])
        self.codec = _candidate_codec()
        with self.backend.connection() as connection:
            self.player_id = self.backend._authorize(connection, self.token)

    def records(self, quest_id):
        return [{'quest_objective_id': value, 'value': 0, 'has_completed': False}
                for value in native_quests.QUESTS[quest_id]['ObjectiveList']]

    def accept_fixture(self, *quest_ids, player_id=None):
        # Isolate evaluation from prerequisite chains using temporary test data.
        with self.backend.connection() as connection:
            for quest_id in quest_ids:
                connection.execute('INSERT INTO native_lobby_quest_progress '
                    '(player_id,quest_id,state,accept_time,objectives_json) VALUES (?,?,3,1,?)',
                    (player_id or self.player_id, quest_id, json.dumps(self.records(quest_id))))
            connection.commit()

    def commit_currency(self, delta, player_id=None):
        with self.backend.connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            result = currency_change(connection, player_id or self.player_id, HAF, delta)
            connection.commit()
        return result

    def refresh(self, *, token=None, diagnostic=None):
        self.assertIsNotNone(importlib.util.find_spec('dfserver.native_quest_wallet'),
                             'The committed-wallet quest refresh is not implemented')
        module = importlib.import_module('dfserver.native_quest_wallet')
        notice = module.refresh_committed(self.backend, token or self.token, diagnostic=diagnostic)
        if notice:
            self.codec.decode(self.codec.encode('CSQuestDataChangeNtf', notice, sequence=71))
        return notice

    def saved(self, quest_id=49001, player_id=None):
        with self.backend.connection() as connection:
            row = dict(connection.execute('SELECT * FROM native_lobby_quest_progress '
                'WHERE player_id=? AND quest_id=?', (player_id or self.player_id, quest_id)).fetchone())
        row['objectives'] = json.loads(row['objectives_json'])
        return row

    def query(self):
        request = self.codec.decode(self.codec.encode('CSQuestGetPlayerDataReq', {}, sequence=72))
        changes = {}
        result = native_quests.response_fields(request, self.backend, self.token, changes=changes)
        self.codec.decode(self.codec.response(request, result))
        return result, changes

    def test_committed_credit_reaches_threshold_without_spending_or_granting_rewards(self):
        self.accept_fixture(49001)
        self.assertEqual(self.commit_currency(499999)['current_num'], 499999)
        partial = self.refresh()
        self.assertEqual(partial['player_quests'][0]['quest_objectives'][0]['value'], 499999)
        self.assertEqual(partial['player_quests'][0]['quest_state'], native_quests.ACCEPTED)
        self.assertEqual(self.commit_currency(1)['current_num'], 500000)
        notice = self.refresh()
        completed = notice['player_quests'][0]
        self.assertEqual(completed['quest_state'], native_quests.COMPLETED)
        self.assertEqual(completed['quest_objectives'][0]['value'], 500000)
        self.assertTrue(completed['quest_objectives'][0]['has_completed'])
        self.assertEqual(notice['quest_data_pre'][0]['quest_objectives'][0]['value'], 499999)
        self.assertGreater(completed['complete_time'], 0)
        self.assertEqual(completed['reward_time'], 0)
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT amount FROM native_lobby_currencies '
                'WHERE player_id=? AND currency_id=?', (self.player_id, HAF)).fetchone()[0], 500000)
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_props').fetchone()[0], 0)
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_quest_reward_receipts').fetchone()[0], 0)
            self.assertEqual(connection.execute('SELECT money,xp FROM players WHERE id=?',
                (self.player_id,)).fetchone()[:], (0, 0))

    def test_committed_cost_lowers_incomplete_progress_instead_of_accumulating_earnings(self):
        self.accept_fixture(49001)
        self.commit_currency(400000)
        self.refresh()
        self.commit_currency(-100000)
        notice = self.refresh()
        self.assertEqual(notice['quest_data_pre'][0]['quest_objectives'][0]['value'], 400000)
        self.assertEqual(notice['player_quests'][0]['quest_objectives'][0]['value'], 300000)
        self.assertEqual(self.saved()['state'], native_quests.ACCEPTED)

    def test_only_authenticated_accounts_actual_wallet_updates_its_accepted_cash_quests(self):
        self.accept_fixture(49001, 11001)
        other = self.backend.register('wallet-other', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(other, level=60, currencies={}, props=[])
        with self.backend.connection() as connection:
            other_id = self.backend._authorize(connection, other)
            connection.execute('UPDATE players SET money=2000000000 WHERE id=?', (self.player_id,))
            connection.commit()
        self.accept_fixture(49001, player_id=other_id)
        self.commit_currency(500000, player_id=other_id)
        self.commit_currency(123)
        notice = self.refresh()
        self.assertEqual([row['quest_id'] for row in notice['player_quests']], [49001])
        self.assertEqual(self.saved()['objectives'][0]['value'], 123)
        self.assertEqual(self.saved(player_id=other_id)['objectives'][0]['value'], 0)
        self.assertEqual(self.saved(11001)['objectives'], self.records(11001))

    def test_repeated_refresh_is_quiet_and_committed_progress_survives_reopen(self):
        self.accept_fixture(49001)
        self.commit_currency(500000)
        completed = self.refresh()['player_quests'][0]
        self.assertIsNone(self.refresh())
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        self.assertIsNone(self.refresh())
        response, changes = self.query()
        self.assertEqual(next(row for row in response['player_quests'] if row['quest_id'] == 49001), completed)
        self.assertNotIn('quest_notification', changes)

    def test_local_policy_keeps_uncapped_completion_value_after_later_spending(self):
        self.accept_fixture(49001)
        self.commit_currency(100284911)
        completed = self.refresh()['player_quests'][0]
        self.assertEqual(completed['quest_objectives'][0]['value'], 100284911)
        self.assertEqual(completed['quest_state'], native_quests.COMPLETED)
        self.commit_currency(-100000000)
        self.assertIsNone(self.refresh())
        response, changes = self.query()
        self.assertEqual(next(row for row in response['player_quests'] if row['quest_id'] == 49001), completed)
        self.assertNotIn('quest_notification', changes)
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT amount FROM native_lobby_currencies '
                'WHERE player_id=? AND currency_id=?', (self.player_id, HAF)).fetchone()[0], 284911)

    def test_no_acceptance_override_facility_completion_or_unrelated_objective_update(self):
        self.accept_fixture(39002, 41907)
        self.backend.set_native_lobby_devices(self.token, {})
        self.backend.quest_completion = {'enabled': True, 'complete_all': True, 'complete_quest_ids': []}
        with self.backend.connection() as connection:
            connection.execute('INSERT INTO native_lobby_safehouse_upgrades VALUES (?,?,?,?,?)',
                               (self.player_id, 1005, 1, 1, 2))
            connection.commit()
        self.commit_currency(50000000)
        self.assertIsNone(self.refresh())
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_devices '
                'WHERE player_id=?', (self.player_id,)).fetchone()[0], 0)
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_safehouse_upgrades').fetchone()[0], 1)
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_quest_progress').fetchone()[0], 2)
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_quest_completion_overrides').fetchone()[0], 0)
        self.assertEqual(self.saved(39002)['objectives'], self.records(39002))
        self.assertEqual(self.saved(41907)['objectives'], self.records(41907))

    def test_refresh_failure_rolls_back_derived_progress_but_preserves_committed_money_and_query_recovers(self):
        self.accept_fixture(49001, 49002)
        self.commit_currency(2000000)
        with self.backend.connection() as connection:
            connection.execute('CREATE TRIGGER reject_wallet_quest BEFORE UPDATE ON native_lobby_quest_progress '
                'WHEN NEW.quest_id=49002 BEGIN SELECT RAISE(ABORT, "wallet fixture failure"); END')
            connection.commit()
        diagnostic = {}
        self.assertIsNone(self.refresh(diagnostic=diagnostic))
        self.assertEqual(diagnostic['local_wallet_quest_error']['code'], 'IntegrityError')
        for quest_id in (49001, 49002):
            self.assertEqual(self.saved(quest_id)['state'], native_quests.ACCEPTED)
            self.assertEqual(self.saved(quest_id)['objectives'][0]['value'], 0)
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT amount FROM native_lobby_currencies '
                'WHERE player_id=? AND currency_id=?', (self.player_id, HAF)).fetchone()[0], 2000000)
            connection.execute('DROP TRIGGER reject_wallet_quest')
            connection.commit()
        response, changes = self.query()
        self.assertEqual(response['result'], 0)
        self.assertEqual({row['quest_id'] for row in changes['quest_notification']['player_quests']}, {49001, 49002})
        for quest_id in (49001, 49002):
            self.assertEqual(self.saved(quest_id)['state'], native_quests.COMPLETED)

    def test_invalid_session_is_contained_without_token_disclosure_or_account_updates(self):
        self.accept_fixture(49001)
        self.commit_currency(500000)
        diagnostic = {}
        token = 'invalid-private-session-token'
        self.assertIsNone(self.refresh(token=token, diagnostic=diagnostic))
        self.assertIn('local_wallet_quest_error', diagnostic)
        self.assertNotIn(token, json.dumps(diagnostic))
        self.assertEqual(self.saved()['objectives'][0]['value'], 0)
        self.assertIsNone(self.refresh(token=token))

    def test_malformed_saved_objectives_fail_without_notification_or_wallet_change(self):
        self.accept_fixture(49001)
        self.commit_currency(500000)
        for value in ('not-json', '[]'):
            with self.subTest(objectives_json=value):
                with self.backend.connection() as connection:
                    connection.execute('UPDATE native_lobby_quest_progress SET objectives_json=? '
                        'WHERE player_id=? AND quest_id=49001', (value, self.player_id))
                    connection.commit()
                diagnostic = {}
                self.assertIsNone(self.refresh(diagnostic=diagnostic))
                self.assertIn('local_wallet_quest_error', diagnostic)
                with self.backend.connection() as connection:
                    self.assertEqual(connection.execute('SELECT amount FROM native_lobby_currencies '
                        'WHERE player_id=? AND currency_id=?', (self.player_id, HAF)).fetchone()[0], 500000)


if __name__ == '__main__':
    unittest.main()
