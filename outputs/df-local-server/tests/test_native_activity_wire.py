import struct
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from dfserver import handshake_diagnostic as wire
from dfserver.gcp_data import decode_data_frame
from dfserver.core import Backend


class NativeActivityWireTests(unittest.TestCase):
    def fixture(self, *, production=False):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        backend = Backend(Path(directory.name) / 'save.sqlite3', Path(__file__).resolve().parent.parent / 'definitions.json')
        token = backend.register('activity', 'local-password-123')['session']
        backend.set_native_lobby_profile(token, level=60 if production else 1, currencies={}, props=[
            {'gid': 7001, 'template_id': 15020010028, 'quantity': 3, 'grid_page_id': 2,
             'x': 0, 'y': 0, 'length': 1, 'width': 1},
            {'gid': 7002, 'template_id': 15080050023, 'quantity': 1, 'grid_page_id': 2,
             'x': 1, 'y': 0, 'length': 1, 'width': 1}] if production else [])
        if production:
            backend.set_native_lobby_devices(token, {1007: 1})
        from types import SimpleNamespace
        return SimpleNamespace(backend=backend, token=token, codec=wire._candidate_codec())

    def transact(self, fixture, name, fields):
        key = bytes(range(16))
        request = struct.pack('<I', 0) + fixture.codec.encode(name, fields, sequence=451)
        entry = {}
        response = wire._candidate_local_activity_response(request, fixture.backend, fixture.token, key,
            header_word4=17, header_word9=81, diagnostic_entry=entry)
        frames = wire._candidate_local_activity_response_frames(response, key, entry)
        decoded = [fixture.codec.decode(decode_data_frame(frame, key, direction='server_to_client',
                                                         compression_method=1).messages[0])
                   for frame in frames]
        self.assertEqual([frame.header_word9 for frame in frames], list(range(81, 81 + len(frames))))
        self.assertEqual(decoded[-1].sequence, 451)
        self.assertNotIn('_local_activity_changes', entry)
        return decoded, entry

    def test_quest_notification_precedes_accept_callback_and_reconnect_restores(self):
        fixture = self.fixture()
        messages, entry = self.transact(fixture, 'CSQuestAcceptReq', {'quest_id': 11001})
        self.assertEqual([message.name for message in messages], ['CSQuestDataChangeNtf', 'CSQuestAcceptRes'])
        self.assertEqual(int(messages[0].fields['player_quests'][0]['quest_state']), 3)
        self.assertEqual(entry['local_activity_request'], {'quest_id': 11001})
        messages, _ = self.transact(fixture, 'CSQuestGetPlayerDataReq', {})
        saved = next(row for row in messages[0].fields['player_quests'] if int(row['quest_id']) == 11001)
        self.assertEqual(int(saved['quest_state']), 3)

    def test_production_consumption_notification_and_query_use_same_persisted_line(self):
        fixture = self.fixture(production=True)
        with patch('dfserver.native_safehouse.time.time', return_value=10000000):
            messages, entry = self.transact(fixture, 'CSSafehouseProduceReq', {
                'device_id': 1007, 'formula_id': 372830001, 'mobile_push_token': 'must-not-be-logged'})
        self.assertEqual([message.name for message in messages], ['CSDepositChangeNtf', 'CSSafehouseProduceRes'])
        self.assertEqual(entry['local_activity_request'], {'device_id': 1007, 'formula_id': 372830001})
        self.assertEqual(len(messages[0].fields['deposit_change']['prop_changes']), 2)
        queried, _ = self.transact(fixture, 'CSSafehouseGetInfoReq', {})
        self.assertEqual(queried[0].fields['devices'][0]['produce_line'], messages[1].fields['produce_info'])

    def test_failed_acceptance_sends_no_success_notification(self):
        fixture = self.fixture()
        messages, entry = self.transact(fixture, 'CSQuestAcceptReq', {'quest_id': 90001})
        self.assertEqual(len(messages), 1)
        self.assertNotEqual(int(messages[0].fields['result']), 0)
        self.assertEqual(entry['local_activity_result'], int(messages[0].fields['result']))


if __name__ == '__main__':
    unittest.main()
