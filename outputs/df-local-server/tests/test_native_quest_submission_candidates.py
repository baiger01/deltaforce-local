from pathlib import Path
import tempfile
import unittest

from dfserver import native_quests
from dfserver.core import Backend
from dfserver.handshake_diagnostic import _candidate_codec
from dfserver.native_safehouse import QUEST_WEAPON_PRESETS
from dfserver.premium_shop import ITEMS


ROOT = Path(__file__).resolve().parent.parent


class NativeQuestSubmissionCandidateTests(unittest.TestCase):
    def test_one_required_gun_consumes_only_selected_owned_root_and_its_parts(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        backend = Backend(Path(directory.name) / 'save.sqlite3', ROOT / 'definitions.json')
        token = backend.register('submission-candidates', 'local-password-123')['session']
        codec = _candidate_codec()
        quest = native_quests.QUESTS[50001]
        objective_id = quest['ObjectiveList'][0]
        objective = native_quests.OBJECTIVES[objective_id]
        receiver = int(objective['Param1'])
        metadata = ITEMS[str(receiver)]
        self.assertEqual(objective['RequiredCount'], 1)
        required_parts = set(objective['ListParam'])
        preset = next(row for row in QUEST_WEAPON_PRESETS.values()
                      if row['receiver_id'] == receiver and required_parts.issubset(
                          part['prop_data']['id'] for part in row['prop']['components']))
        backend.set_native_lobby_profile(token, level=60, currencies={}, props=[
            {'gid': gid, 'template_id': receiver, 'quantity': 1, 'grid_page_id': 2,
             'x': 0, 'y': index * metadata['width'],
             'length': metadata['length'], 'width': metadata['width']}
            for index, gid in enumerate((9001, 9002))])
        backend.native_lobby_profile(token)
        with backend.connection() as connection:
            for gid in (9001, 9002):
                for part in preset['prop']['components']:
                    if part['prop_data']['id'] in required_parts:
                        connection.execute('INSERT INTO native_lobby_weapon_parts VALUES (?,?,?,?,?)',
                            (backend._next_native_prop_gid(connection), gid, gid,
                             part['slot'], part['prop_data']['id']))
            connection.commit()
        before = {prop['gid']: prop for prop in backend.native_lobby_profile(token)['props']}
        self.assertEqual(set(before), {9001, 9002})
        untouched = before[9002]

        def request(name, fields, changes=None):
            decoded = codec.decode(codec.encode(name, fields, sequence=23))
            result = native_quests.response_fields(decoded, backend, token, changes=changes)
            codec.decode(codec.response(decoded, result))
            return result

        self.assertEqual(request('CSQuestAcceptReq', {'quest_id': quest['QuestID']})['result'], 0)
        changes = {}
        result = request('CSQuestSubmitPropReq', {'quest_id': quest['QuestID'], 'submit_list': [
            {'obj_id': objective_id, 'submit_props': [{'id': receiver, 'gid': 9001, 'num': 1}]}]}, changes)
        self.assertEqual((result['result'], result['quest_state']), (0, native_quests.COMPLETED))
        self.assertEqual(result['player_quest']['quest_objectives'][0]['value'], 1)
        self.assertEqual(len(changes['inventory_moves']), 1)
        self.assertEqual(changes['inventory_moves'][0]['before']['gid'], 9001)
        self.assertIsNone(changes['inventory_moves'][0]['after'])
        after = {prop['gid']: prop for prop in backend.native_lobby_profile(token)['props']}
        self.assertEqual(after, {9002: untouched})
        with backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_weapon_parts '
                'WHERE weapon_gid=9001').fetchone()[0], 0)
            remaining_parts = {row[0] for row in connection.execute(
                'SELECT template_id FROM native_lobby_weapon_parts WHERE weapon_gid=9002')}
        self.assertTrue(required_parts.issubset(remaining_parts))

        repeated_changes = {}
        repeated = request('CSQuestSubmitPropReq', {'quest_id': quest['QuestID'], 'submit_list': [
            {'obj_id': objective_id, 'submit_props': [{'id': receiver, 'gid': 9002, 'num': 1}]}]},
            repeated_changes)
        self.assertNotEqual(repeated['result'], 0)
        self.assertEqual(repeated_changes, {})
        self.assertEqual(backend.native_lobby_profile(token)['props'], [untouched])


if __name__ == '__main__':
    unittest.main()
