from pathlib import Path
import json
import tempfile
import unittest

from dfserver import native_quests
from dfserver.core import Backend
from dfserver.handshake_diagnostic import _candidate_codec


ROOT = Path(__file__).resolve().parent.parent


class NativeQuestTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.backend = Backend(Path(self.directory.name) / 'save.sqlite3', ROOT / 'definitions.json')
        self.token = self.backend.register('quests', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=1, currencies={}, props=[])
        with self.backend.connection() as connection:
            connection.executescript(native_quests.SCHEMA)
        self.codec = _candidate_codec()

    def request(self, name, fields=None, changes=None):
        request = self.codec.decode(self.codec.encode(name, fields or {}, sequence=31))
        result = native_quests.response_fields(request, self.backend, self.token, changes=changes)
        self.codec.decode(self.codec.response(request, result))
        if changes and changes.get('quest_notification'):
            self.codec.decode(self.codec.encode('CSQuestDataChangeNtf', changes['quest_notification'], sequence=32))
        return result

    def test_real_root_acceptance_persists_and_emits_native_objectives(self):
        changes = {}
        result = self.request('CSQuestAcceptReq', {'quest_id': 11001}, changes)
        self.assertEqual(result, {'result': 0, 'quest_id': 11001, 'quest_state': 3})
        changed = changes['quest_notification']['player_quests'][0]
        self.assertEqual(changed['quest_state'], 3)
        self.assertGreater(changed['quest_accept_time'], 0)
        self.assertEqual(changed['quest_objectives'], [{'quest_objective_id': 1100101,
            'has_completed': False, 'value': 0, 'has_marked': False, 'spent_seconds': 0, 'choice': 0}])
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        query = self.request('CSQuestGetPlayerDataReq')
        saved = next(row for row in query['player_quests'] if row['quest_id'] == 11001)
        self.assertEqual(saved, changed)
        self.assertEqual(self.request('CSQuestAcceptReq', {'quest_id': 11001})['result'], 122008)

    def test_native_level_and_rewarded_prerequisites_are_enforced(self):
        self.assertEqual(self.request('CSQuestAcceptReq', {'quest_id': 31001})['result'], 122018)
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_levels SET level=2')
            connection.commit()
        self.assertEqual(self.request('CSQuestAcceptReq', {'quest_id': 11002})['result'], 122020)
        self.request('CSQuestAcceptReq', {'quest_id': 11001})
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_quest_progress SET state=6 WHERE quest_id=11001')
            connection.commit()
        self.assertEqual(self.request('CSQuestAcceptReq', {'quest_id': 11002})['result'], 122020)
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_quest_progress SET state=7 WHERE quest_id=11001')
            connection.execute('UPDATE native_lobby_levels SET level=2')
            connection.commit()
        self.assertEqual(self.request('CSQuestAcceptReq', {'quest_id': 11002})['result'], 0)

    def test_department_branch_acceptance_survives_restart_and_map_query(self):
        self.assertEqual(self.request('CSQuestAcceptReq', {'quest_id': 49001})['result'], 122018)
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_levels SET level=16')
            connection.commit()
        changes = {}
        result = self.request('CSQuestAcceptReq', {'quest_id': 49001}, changes)
        self.assertEqual(result, {'result': 0, 'quest_id': 49001, 'quest_state': 3})
        changed = changes['quest_notification']['player_quests'][0]
        self.assertEqual([row['quest_objective_id'] for row in changed['quest_objectives']], [4900101])
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        self.assertEqual(self.request('CSQuestGetAcceptedQuestsReq', {'hero_id': 88000000025}),
                         {'result': 0, 'accepted_quests': [changed]})
        self.assertEqual(self.request('CSQuestAcceptReq', {'quest_id': 49001})['result'], 122008)

    def test_department_branch_query_requires_ownership_and_excludes_finished_quests(self):
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_levels SET level=60')
            connection.commit()
        self.assertEqual(self.request('CSQuestAcceptReq', {'quest_id': 49001})['result'], 0)
        owner_token = self.token
        self.token = self.backend.register('branch-other', 'local-password-123')['session']
        self.assertEqual(self.request('CSQuestGetAcceptedQuestsReq'),
                         {'result': 0, 'accepted_quests': []})
        self.token = owner_token
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_quest_progress SET state=6 WHERE quest_id=49001')
            connection.commit()
        self.assertEqual(self.request('CSQuestGetAcceptedQuestsReq'),
                         {'result': 0, 'accepted_quests': []})

    def test_unknown_and_unverified_specialised_types_are_explicit_failures(self):
        for quest_id in (2**63 - 1, 90001):
            changes = {}
            self.assertNotEqual(self.request('CSQuestAcceptReq', {'quest_id': quest_id}, changes)['result'], 0)
            self.assertEqual(changes, {})
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_quest_progress').fetchone()[0], 0)

    def test_query_and_acceptance_are_scoped_to_authenticated_local_player(self):
        self.request('CSQuestAcceptReq', {'quest_id': 11001})
        other = self.backend.register('other', 'local-password-123')['session']
        self.token = other
        result = self.request('CSQuestGetPlayerDataReq')
        self.assertNotEqual(next(row for row in result['player_quests'] if row['quest_id'] == 11001)['quest_state'], 3)
        self.assertEqual(self.request('CSQuestAcceptReq', {'quest_id': 11001})['result'], 0)

    def test_match_accepted_query_returns_saved_mission_objectives_after_restart(self):
        changes = {}
        self.request('CSQuestAcceptReq', {'quest_id': 11001}, changes)
        with self.backend.connection() as connection:
            connection.execute('INSERT INTO native_lobby_quest_progress '
                '(player_id,quest_id,state) SELECT player_id,11002,6 '
                'FROM native_lobby_quest_progress WHERE quest_id=11001')
            connection.execute('INSERT INTO native_lobby_quest_progress '
                '(player_id,quest_id,state) SELECT player_id,90001,3 '
                'FROM native_lobby_quest_progress WHERE quest_id=11001')
            connection.execute('INSERT INTO native_lobby_quest_progress '
                '(player_id,quest_id,state) SELECT player_id,999999999,3 '
                'FROM native_lobby_quest_progress WHERE quest_id=11001')
            connection.commit()
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        result = self.request('CSQuestGetAcceptedQuestsReq', {'hero_id': 88000000025})
        self.assertEqual(result, {'result': 0,
            'accepted_quests': changes['quest_notification']['player_quests']})

    def test_match_accepted_query_is_empty_for_another_authenticated_player(self):
        self.request('CSQuestAcceptReq', {'quest_id': 11001})
        self.token = self.backend.register('match-other', 'local-password-123')['session']
        self.assertEqual(self.request('CSQuestGetAcceptedQuestsReq', {'hero_id': 88000000025}),
                         {'result': 0, 'accepted_quests': []})

    def test_match_accepted_query_rejects_an_invalid_session(self):
        self.request('CSQuestAcceptReq', {'quest_id': 11001})
        self.token = 'invalid-local-session'
        result = self.request('CSQuestGetAcceptedQuestsReq', {'hero_id': 88000000025})
        self.assertNotEqual(result['result'], 0)
        self.assertNotIn('accepted_quests', result)

    def test_database_failure_rolls_back_acceptance_without_notification(self):
        with self.backend.connection() as connection:
            connection.execute('CREATE TRIGGER reject_quest_accept BEFORE INSERT ON native_lobby_quest_progress '
                               'BEGIN SELECT RAISE(ABORT, "simulated durable write failure"); END')
            connection.commit()
        changes = {}
        result = self.request('CSQuestAcceptReq', {'quest_id': 11001}, changes)
        self.assertNotEqual(result['result'], 0)
        self.assertEqual(changes, {})
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_quest_progress').fetchone()[0], 0)

    def configured_backend(self, settings):
        path = Path(self.directory.name) / 'quest-completion.json'
        path.write_text(json.dumps(settings), encoding='utf-8')
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json',
                               quest_completion_config=path)

    def test_completion_configuration_is_disabled_by_default(self):
        self.configured_backend({'enabled': False, 'complete_all': True, 'complete_quest_ids': [11001]})
        self.request('CSQuestGetPlayerDataReq')
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_quest_progress').fetchone()[0], 0)

    def test_individual_completion_is_durable_idempotent_and_does_not_grant_rewards(self):
        self.request('CSQuestAcceptReq', {'quest_id': 11001})
        self.configured_backend({'enabled': True, 'complete_all': False, 'complete_quest_ids': [11001]})
        changes = {}
        result = self.request('CSQuestGetPlayerDataReq', changes=changes)
        completed = next(row for row in result['player_quests'] if row['quest_id'] == 11001)
        self.assertEqual(completed['quest_state'], 6)
        self.assertGreater(completed['complete_time'], 0)
        self.assertTrue(all(row['has_completed'] for row in completed['quest_objectives']))
        self.assertEqual(completed['quest_objectives'][0]['value'], 5)
        self.assertEqual(completed['reward_time'], 0)
        self.assertEqual(changes['quest_notification']['player_quests'], [completed])
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        changes = {}
        repeated = self.request('CSQuestGetPlayerDataReq', changes=changes)
        self.assertEqual(next(row for row in repeated['player_quests'] if row['quest_id'] == 11001), completed)
        self.assertFalse(changes.get('quest_notification'))
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_quest_progress').fetchone()[0], 1)
            self.assertEqual(connection.execute('SELECT money,xp FROM players').fetchone()[:], (0, 0))

    def test_all_completion_preserves_rewarded_records_and_other_accounts(self):
        self.request('CSQuestAcceptReq', {'quest_id': 11001})
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_quest_progress SET state=7,reward_time=123 WHERE quest_id=11001')
            before = dict(connection.execute('SELECT * FROM native_lobby_quest_progress').fetchone())
            connection.commit()
        other = self.backend.register('completion-other', 'local-password-123')['session']
        self.configured_backend({'enabled': True, 'complete_all': True, 'complete_quest_ids': []})
        self.request('CSQuestGetPlayerDataReq')
        self.request('CSQuestGetPlayerDataReq')
        with self.backend.connection() as connection:
            owner = self.backend._authorize(connection, self.token)
            other_id = self.backend._authorize(connection, other)
            self.assertEqual(dict(connection.execute('SELECT * FROM native_lobby_quest_progress '
                'WHERE player_id=? AND quest_id=11001', (owner,)).fetchone()), before)
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_quest_progress '
                'WHERE player_id=?', (owner,)).fetchone()[0], len(native_quests.QUESTS))
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_quest_progress '
                'WHERE player_id=?', (other_id,)).fetchone()[0], 0)

    def test_invalid_completion_configuration_fails_before_mutating_save(self):
        for settings in (
                {'enabled': True, 'complete_all': False, 'complete_quest_ids': [999999999]},
                {'enabled': 'false', 'complete_all': False, 'complete_quest_ids': []},
                {'enabled': True, 'complete_all': False, 'complete_quest_ids': [11001, 11001]},
                {'enabled': True, 'complete_all': False, 'complete_quest_ids': [True]},
                {'enabled': True, 'complete_all': False, 'complete_quest_ids': [], 'typo': True}):
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                self.configured_backend(settings)
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_quest_progress').fetchone()[0], 0)

    def test_invalid_session_cannot_apply_completion_configuration(self):
        self.configured_backend({'enabled': True, 'complete_all': True, 'complete_quest_ids': []})
        self.token = 'invalid-session'
        changes = {}
        self.assertNotEqual(self.request('CSQuestGetPlayerDataReq', changes=changes)['result'], 0)
        self.assertEqual(changes, {})
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_quest_progress').fetchone()[0], 0)

    def test_completion_configuration_rolls_back_entire_batch(self):
        self.configured_backend({'enabled': True, 'complete_all': False, 'complete_quest_ids': [11001, 21001]})
        with self.backend.connection() as connection:
            connection.execute('CREATE TRIGGER reject_completion BEFORE INSERT ON native_lobby_quest_progress '
                'WHEN NEW.quest_id=21001 BEGIN SELECT RAISE(ABORT, "simulated completion failure"); END')
            connection.commit()
        changes = {}
        self.assertNotEqual(self.request('CSQuestGetPlayerDataReq', changes=changes)['result'], 0)
        self.assertEqual(changes, {})
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_quest_progress').fetchone()[0], 0)

    def prepare_native_submission(self, quest_id, *, quantity=1, required_parts=True):
        from dfserver.premium_shop import ITEMS
        item = ITEMS['18010000010']
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={17020000010: 600000}, props=[{'gid': 9001, 'template_id': 18010000010,
            'quantity': quantity, 'grid_page_id': 2, 'x': 0, 'y': 0,
            'length': item['length'], 'width': item['width']}])
        if required_parts and quest_id == 50001:
            from dfserver.native_safehouse import QUEST_WEAPON_PRESETS
            source = next(row for row in QUEST_WEAPON_PRESETS['10010000037']['prop']['components']
                          if row['prop_data']['id'] == 13110000044)
            self.backend.native_lobby_profile(self.token)
            with self.backend.connection() as connection:
                connection.execute('INSERT INTO native_lobby_weapon_parts VALUES (?,?,?,?,?)',
                    (self.backend._next_native_prop_gid(connection), 9001, 9001,
                     source['slot'], source['prop_data']['id']))
                connection.commit()
        self.assertEqual(self.request('CSQuestAcceptReq', {'quest_id': quest_id})['result'], 0)

    def test_source_gunsmith_submission_requires_owned_parts_not_client_preview(self):
        self.prepare_native_submission(50001, required_parts=False)
        fields = {'quest_id': 50001, 'submit_list': [{'obj_id': 5000101, 'submit_props': [
            {'id': 18010000010, 'gid': 9001, 'num': 1,
             'components': [{'slot': 11, 'prop_data': {'id': 13110000044, 'num': 1}}]}]}]}
        changes = {}
        self.assertNotEqual(self.request('CSQuestSubmitPropReq', fields, changes)['result'], 0)
        self.assertEqual(changes, {})
        self.assertEqual(len(self.backend.native_lobby_profile(self.token)['props']), 1)

    def test_owned_item_submission_completes_source_objective_and_persists(self):
        self.prepare_native_submission(50001)
        changes = {}
        fields = {'quest_id': 50001, 'submit_list': [{'obj_id': 5000101,
                  'submit_props': [{'id': 18010000010, 'gid': 9001, 'num': 1}]}]}
        result = self.request('CSQuestSubmitPropReq', fields, changes)
        self.assertEqual(result['result'], 0)
        self.assertEqual(result['quest_state'], 6)
        objective = result['player_quest']['quest_objectives'][0]
        self.assertEqual((objective['value'], objective['has_completed']), (1, True))
        self.assertEqual(len(changes['inventory_moves']), 1)
        self.assertIsNone(changes['inventory_moves'][0]['after'])
        self.assertEqual(changes['quest_notification']['player_quests'], [result['player_quest']])
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        saved = next(row for row in self.request('CSQuestGetPlayerDataReq')['player_quests'] if row['quest_id'] == 50001)
        self.assertEqual(saved, result['player_quest'])
        changes = {}
        self.assertNotEqual(self.request('CSQuestSubmitPropReq', fields, changes)['result'], 0)
        self.assertEqual(changes, {})

    def test_currency_objective_cannot_be_submitted_or_spend_the_actual_wallet(self):
        self.prepare_native_submission(49001)
        fields = {'quest_id': 49001, 'submit_list': [{'obj_id': 4900101,
                  'submit_props': [{'id': 17020000010, 'num': 500000}]}]}
        changes = {}
        result = self.request('CSQuestSubmitPropReq', fields, changes)
        self.assertNotEqual(result['result'], 0)
        self.assertEqual(changes, {})
        self.assertNotEqual(self.request('CSQuestSubmitPropReq', fields)['result'], 0)
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT amount FROM native_lobby_currencies').fetchone()[0], 600000)

    def test_item_submission_rejects_wrong_identity_quantity_or_duplicate_entry_atomically(self):
        self.prepare_native_submission(50001)
        valid = {'id': 18010000010, 'gid': 9001, 'num': 1}
        variants = [
            [{'obj_id': 5000101, 'submit_props': [{**valid, 'id': 18010000002}]}],
            [{'obj_id': 5000101, 'submit_props': [{**valid, 'num': 2}]}],
            [{'obj_id': 5000101, 'submit_props': [{**valid, 'num': 0}]}],
            [{'obj_id': 5000101, 'submit_props': [valid, valid]}],
            [{'obj_id': 5000101, 'submit_props': [valid]}, {'obj_id': 5000101, 'submit_props': [valid]}],
            [{'obj_id': 1100101, 'submit_props': [valid]}],
            [{'obj_id': 5000101, 'submit_props': [{**valid, 'position': 103}]}],
            [{'obj_id': 5000101, 'submit_props': [{**valid, 'gid': 2**64 - 1}]}],
        ]
        for entries in variants:
            with self.subTest(entries=entries):
                changes = {}
                self.assertNotEqual(self.request('CSQuestSubmitPropReq',
                    {'quest_id': 50001, 'submit_list': entries}, changes)['result'], 0)
                self.assertEqual(changes, {})
                with self.backend.connection() as connection:
                    self.assertEqual(connection.execute('SELECT quantity FROM native_lobby_props WHERE gid=9001').fetchone()[0], 1)
                    self.assertEqual(connection.execute('SELECT state FROM native_lobby_quest_progress').fetchone()[0], 3)

    def test_item_submission_cannot_consume_another_accounts_instance(self):
        self.prepare_native_submission(50001)
        self.token = self.backend.register('submit-other', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[])
        self.request('CSQuestAcceptReq', {'quest_id': 50001})
        self.assertNotEqual(self.request('CSQuestSubmitPropReq', {'quest_id': 50001,
            'submit_list': [{'obj_id': 5000101, 'submit_props': [{'id': 18010000010, 'gid': 9001, 'num': 1}]}]})['result'], 0)
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT quantity FROM native_lobby_props WHERE gid=9001').fetchone()[0], 1)

    def test_submit_persistence_failure_restores_item_and_objective(self):
        self.prepare_native_submission(50001)
        with self.backend.connection() as connection:
            connection.execute('CREATE TRIGGER reject_submit BEFORE UPDATE ON native_lobby_quest_progress '
                'BEGIN SELECT RAISE(ABORT, "simulated objective persistence failure"); END')
            connection.commit()
        changes = {}
        result = self.request('CSQuestSubmitPropReq', {'quest_id': 50001, 'submit_list': [
            {'obj_id': 5000101, 'submit_props': [{'id': 18010000010, 'gid': 9001, 'num': 1}]}]}, changes)
        self.assertNotEqual(result['result'], 0)
        self.assertEqual(changes, {})
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT quantity FROM native_lobby_props WHERE gid=9001').fetchone()[0], 1)
            self.assertEqual(connection.execute('SELECT state FROM native_lobby_quest_progress').fetchone()[0], 3)

    def test_completion_requires_persisted_objective_proof(self):
        self.request('CSQuestAcceptReq', {'quest_id': 11001})
        self.assertNotEqual(self.request('CSQuestCompleteReq', {'quest_id': 11001})['result'], 0)
        with self.backend.connection() as connection:
            objective = [{'quest_objective_id': 1100101, 'value': 5, 'has_completed': True,
                          'has_marked': False, 'spent_seconds': 0, 'choice': 0}]
            connection.execute('UPDATE native_lobby_quest_progress SET objectives_json=?', (json.dumps(objective),))
            connection.commit()
        changes = {}
        result = self.request('CSQuestCompleteReq', {'quest_id': 11001}, changes)
        self.assertEqual(result['result'], 0)
        self.assertEqual(result['quest_state'], 6)
        self.assertEqual(changes['quest_notification']['player_quests'][0]['quest_state'], 6)

    def test_submission_uses_owned_binding_instead_of_requested_binding(self):
        from dfserver.premium_shop import ITEMS
        quest_id, objective_id, item_id = 20904, 2090401, 15060080003
        item = ITEMS[str(item_id)]
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[
            {'gid': 9001, 'template_id': item_id, 'quantity': 1, 'bind_type': 0,
             'grid_page_id': 2, 'x': 0, 'y': 0, 'length': item['length'], 'width': item['width']},
            {'gid': 9002, 'template_id': item_id, 'quantity': 1,
             'grid_page_id': 2, 'x': item['length'], 'y': 0,
             'length': item['length'], 'width': item['width']}])
        objectives = [{'quest_objective_id': value, 'value': 0, 'has_completed': False,
            'has_marked': False, 'spent_seconds': 0, 'choice': 0}
            for value in native_quests.QUESTS[quest_id]['ObjectiveList']]
        with self.backend.connection() as connection:
            player = self.backend._authorize(connection, self.token)
            connection.execute('INSERT INTO native_lobby_quest_progress '
                '(player_id,quest_id,state,objectives_json) VALUES (?,?,3,?)',
                (player, quest_id, json.dumps(objectives)))
            connection.commit()
        fields = {'quest_id': quest_id, 'submit_list': [{'obj_id': objective_id,
            'submit_props': [{'id': item_id, 'gid': 9001, 'num': 1, 'bind_type': 1}]}]}
        self.assertNotEqual(self.request('CSQuestSubmitPropReq', fields)['result'], 0)
        fields['submit_list'][0]['submit_props'][0]['gid'] = 9002
        result = self.request('CSQuestSubmitPropReq', fields)
        self.assertEqual(result['result'], 0)
        self.assertEqual(result['quest_state'], 3)
        self.assertEqual(result['player_quest']['quest_objectives'][0]['value'], 1)
        self.assertEqual([row['gid'] for row in self.backend.native_lobby_profile(self.token)['props']], [9001])


if __name__ == '__main__':
    unittest.main()
