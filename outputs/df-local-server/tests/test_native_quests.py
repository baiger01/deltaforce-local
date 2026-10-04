from pathlib import Path
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


if __name__ == '__main__':
    unittest.main()
