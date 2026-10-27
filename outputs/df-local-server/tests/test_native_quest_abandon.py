from pathlib import Path
import json
import sqlite3
import tempfile
import unittest

from dfserver import native_quests
from dfserver.core import Backend, DomainError
from dfserver.handshake_diagnostic import _candidate_codec
from dfserver.native_quest_abandon import give_up
from dfserver.premium_shop import ITEMS


ROOT = Path(__file__).resolve().parent.parent


class NativeQuestAbandonTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.backend = Backend(Path(self.directory.name) / 'save.sqlite3', ROOT / 'definitions.json')
        self.token = self.backend.register('abandon', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=16,
                                             currencies={17020000010: 400000}, props=[])
        self.codec = _candidate_codec()

    def request(self, name, fields=None):
        request = self.codec.decode(self.codec.encode(name, fields or {}, sequence=19))
        return native_quests.response_fields(request, self.backend, self.token)

    def saved(self, quest_id=49001):
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            return native_quests._progress(connection, player_id).get(quest_id)

    def abandon(self, quest_id=49001, changes=None):
        with self.backend.connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            player_id = self.backend._authorize(connection, self.token)
            saved = native_quests._progress(connection, player_id).get(quest_id)
            result = give_up(connection, player_id, native_quests.QUESTS[quest_id],
                             saved, 1234567890, changes if changes is not None else {})
            connection.commit()
            return result

    def test_manual_branch_abandon_uses_native_response_and_clears_progress(self):
        self.assertEqual(self.request('CSQuestAcceptReq', {'quest_id': 49001})['result'], 0)
        before = self.saved()
        changes = {}
        result = self.abandon(changes=changes)
        self.assertEqual(result, {'res': 0, 'remove_quest_id': 49001})
        wire = self.codec.decode(self.codec.encode('CSQuestGiveUpRes', result, sequence=20))
        self.assertEqual(wire.fields, {'res': 0, 'remove_quest_id': '49001'})
        saved = self.saved()
        self.assertEqual((saved['state'], saved['accept_time']), (native_quests.UNACCEPTED, 0))
        self.assertEqual(json.loads(saved['objectives_json'])[0]['value'], 0)
        notification = changes['quest_notification']
        self.assertEqual(notification['quest_data_pre'], [native_quests._data(49001, 3, before)])
        self.assertEqual(notification['player_quests'], [native_quests._data(49001, 2, saved)])
        self.codec.decode(self.codec.encode('CSQuestDataChangeNtf', notification, sequence=21))

    def test_partial_physical_submission_is_reset_without_refund_on_abandon_and_reaccept(self):
        item = ITEMS['15060080003']
        self.backend.set_native_lobby_profile(self.token, level=16, currencies={}, props=[
            {'gid': 9001, 'template_id': 15060080003, 'quantity': 1, 'bind_type': 1,
             'grid_page_id': 2, 'x': 0, 'y': 0, 'width': item['width'], 'length': item['length']}])
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.execute('INSERT INTO native_lobby_quest_progress '
                '(player_id,quest_id,state,reward_time) VALUES (?,20004,7,100)', (player_id,))
            connection.commit()
        self.assertEqual(self.request('CSQuestAcceptReq', {'quest_id': 20904})['result'], 0)
        submitted = self.request('CSQuestSubmitPropReq', {'quest_id': 20904, 'submit_list': [
            {'obj_id': 2090401, 'submit_props': [{'id': 15060080003, 'gid': 9001, 'num': 1}]}]})
        self.assertEqual(submitted['result'], 0)
        self.assertEqual(submitted['quest_state'], native_quests.ACCEPTED)
        self.assertEqual(json.loads(self.saved(20904)['objectives_json'])[0]['value'], 1)
        self.abandon(20904)
        with self.backend.connection() as connection:
            self.assertIsNone(connection.execute('SELECT gid FROM native_lobby_props WHERE gid=9001').fetchone())
        self.assertTrue(all(row['value'] == 0 and not row['has_completed']
                            for row in json.loads(self.saved(20904)['objectives_json'])))
        self.assertEqual(self.request('CSQuestAcceptReq', {'quest_id': 20904})['result'], 0)
        self.assertTrue(all(row['value'] == 0 and not row['has_completed']
                            for row in json.loads(self.saved(20904)['objectives_json'])))
        self.assertEqual(self.backend.native_lobby_profile(self.token)['props'], [])

    def test_abandoning_wallet_condition_does_not_spend_its_balance(self):
        self.assertEqual(self.request('CSQuestAcceptReq', {'quest_id': 49001})['result'], 0)
        self.assertEqual(json.loads(self.saved()['objectives_json'])[0]['value'], 400000)
        self.abandon()
        self.assertEqual(json.loads(self.saved()['objectives_json'])[0]['value'], 0)
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT amount FROM native_lobby_currencies '
                'WHERE currency_id=17020000010').fetchone()[0], 400000)
        self.assertEqual(self.request('CSQuestAcceptReq', {'quest_id': 49001})['result'], 0)
        self.assertEqual(json.loads(self.saved()['objectives_json'])[0]['value'], 400000)

    def test_abandon_persists_across_restart_and_is_absent_from_map_query(self):
        self.request('CSQuestAcceptReq', {'quest_id': 49001})
        self.abandon()
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        self.assertEqual(self.saved()['state'], native_quests.UNACCEPTED)
        self.assertEqual(self.request('CSQuestGetAcceptedQuestsReq'), {'result': 0, 'accepted_quests': []})
        self.assertEqual(self.request('CSQuestAcceptReq', {'quest_id': 49001})['result'], 0)
        self.assertEqual(len(self.request('CSQuestGetAcceptedQuestsReq')['accepted_quests']), 1)

    def test_reacceptance_still_enforces_owned_level_prerequisite(self):
        self.request('CSQuestAcceptReq', {'quest_id': 49001})
        self.abandon()
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_levels SET level=1')
            connection.commit()
        self.assertEqual(self.request('CSQuestAcceptReq', {'quest_id': 49001})['result'], 122018)
        self.assertEqual(self.saved()['state'], native_quests.UNACCEPTED)

    def test_mission_abandon_preserves_other_progress_and_reacceptance_checks_predecessor(self):
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.execute('INSERT INTO native_lobby_quest_progress '
                '(player_id,quest_id,state,reward_time) VALUES (?,11001,7,100)', (player_id,))
            connection.commit()
        predecessor = self.saved(11001)
        self.assertEqual(self.request('CSQuestAcceptReq', {'quest_id': 11002})['result'], 0)
        self.assertEqual(self.abandon(11002), {'res': 0, 'remove_quest_id': 11002})
        self.assertEqual(self.saved(11001), predecessor)
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_quest_progress SET state=6 WHERE quest_id=11001')
            connection.commit()
        self.assertEqual(self.request('CSQuestAcceptReq', {'quest_id': 11002})['result'], 122020)
        self.assertEqual(self.saved(11002)['state'], native_quests.UNACCEPTED)

    def test_unaccepted_completed_rewarded_and_repeated_abandon_are_rejected(self):
        with self.assertRaises(DomainError) as error:
            self.abandon()
        self.assertEqual(error.exception.code, 'QuestNotAccepted')
        self.request('CSQuestAcceptReq', {'quest_id': 49001})
        for state in (native_quests.COMPLETED, native_quests.REWARDED):
            with self.subTest(state=state):
                with self.backend.connection() as connection:
                    connection.execute('UPDATE native_lobby_quest_progress SET state=?', (state,))
                    connection.commit()
                with self.assertRaises(DomainError) as error:
                    self.abandon()
                self.assertEqual(error.exception.code, 'QuestAlreadyCompleted')
                self.assertEqual(self.saved()['state'], state)
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_quest_progress SET state=3')
            connection.commit()
        self.abandon()
        with self.assertRaises(DomainError) as error:
            self.abandon()
        self.assertEqual(error.exception.code, 'QuestStateInvalid')

    def test_wrong_account_cannot_abandon_another_players_saved_quest(self):
        self.request('CSQuestAcceptReq', {'quest_id': 49001})
        owners_saved = self.saved()
        other = self.backend.register('abandon-other', 'local-password-123')['session']
        changes = {}
        with self.backend.connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            player_id = self.backend._authorize(connection, other)
            with self.assertRaises(DomainError) as error:
                give_up(connection, player_id, native_quests.QUESTS[49001], owners_saved,
                        1234567890, changes)
        self.assertEqual(error.exception.code, 'QuestNotAccepted')
        self.assertEqual(changes, {})
        self.assertEqual(self.saved(), owners_saved)

    def test_autoaccepted_root_and_specialised_quests_are_explicitly_rejected(self):
        self.request('CSQuestAcceptReq', {'quest_id': 11001})
        with self.assertRaises(DomainError) as error:
            self.abandon(11001)
        self.assertEqual(error.exception.code, 'QuestCheckFailed')
        self.assertEqual(self.saved(11001)['state'], native_quests.ACCEPTED)
        self.request('CSQuestAcceptReq', {'quest_id': 49001})
        for change in ({'QuestType': native_quests.QUESTS[90001]['QuestType']},
                       {'IsContract': 1}, {'SpecialType': 1}, {'QuestLifeType': 1}):
            with self.subTest(change=change):
                with self.backend.connection() as connection:
                    connection.execute('BEGIN IMMEDIATE')
                    player_id = self.backend._authorize(connection, self.token)
                    with self.assertRaises(DomainError) as error:
                        give_up(connection, player_id, dict(native_quests.QUESTS[49001], **change),
                                self.saved(), 1234567890, {})
                self.assertEqual(error.exception.code, 'QuestCheckFailed')

    def test_reset_retains_native_nonprogress_objective_fields(self):
        self.request('CSQuestAcceptReq', {'quest_id': 49001})
        objectives = json.loads(self.saved()['objectives_json'])
        objectives[0].update(value=7, has_marked=True, spent_seconds=31, choice=2)
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_quest_progress SET objectives_json=?',
                               (json.dumps(objectives),))
            connection.commit()
        self.abandon()
        after = json.loads(self.saved()['objectives_json'])[0]
        self.assertEqual((after['value'], after['has_completed']), (0, False))
        self.assertEqual((after['has_marked'], after['spent_seconds'], after['choice']), (True, 31, 2))

    def test_persistence_failure_rolls_back_without_notification(self):
        self.request('CSQuestAcceptReq', {'quest_id': 49001})
        before = self.saved()
        with self.backend.connection() as connection:
            connection.execute('CREATE TRIGGER reject_abandon BEFORE UPDATE ON native_lobby_quest_progress '
                               'BEGIN SELECT RAISE(ABORT, "simulated abandonment failure"); END')
            connection.commit()
        changes = {}
        with self.assertRaises(sqlite3.DatabaseError):
            self.abandon(changes=changes)
        self.assertEqual(changes, {})
        self.assertEqual(self.saved(), before)


if __name__ == '__main__':
    unittest.main()
