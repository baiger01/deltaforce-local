import copy
import json
from pathlib import Path
import tempfile
import unittest

from dfserver import local_chat
from dfserver.business_envelope import BusinessEnvelope
from dfserver.candidate_schema import compile_candidate_descriptors
from dfserver.core import Backend, DomainError
from dfserver.handshake_diagnostic import _candidate_codec


ROOT = Path(__file__).resolve().parent.parent


class LocalChatTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.backend = Backend(Path(self.directory.name) / 'save.sqlite3', ROOT / 'definitions.json')
        self.token = self.backend.register('chat-local', 'local-password-123')['session']
        self.codec = _candidate_codec()

    def request(self, name, fields=None, token=None):
        request = self.codec.decode(self.codec.encode(name, fields or {}, sequence=23))
        result = local_chat.response_fields(request, self.backend, token or self.token)
        response = self.codec.decode(self.codec.response(request, result))
        self.assertEqual(response.sequence, 23)
        return result, response.fields

    def test_empty_world_load_uses_native_zero_sentinels_without_moving_cursor(self):
        before = self.backend.native_lobby_profile(self.token)
        for cursor in (0, 37, (1 << 63) - 1):
            result, decoded = self.request('CSChatWorldLoadTReq',
                {'worldchat_room_id': 0, 'read_msg_index': cursor})
            self.assertEqual(result, {'result': 0, 'msg_list': [], 'new_rooom_id': 0,
                'new_room_id': 0, 'load_msg_interval': 0, 'rm_speech_playerid_list': [],
                'rolling_notices': []})
            self.assertEqual(decoded['load_msg_interval'], 0)
            self.assertNotIn('rolling_notice', decoded)
            self.assertNotIn('read_msg_index', decoded)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)
        self.assertEqual(local_chat.CLIENT_DEFAULT_INTERVAL_SECONDS, 20)

    def test_initial_room_and_summary_queries_return_actual_offline_empty_state(self):
        result, decoded = self.request('CSWorldChatGetRoomIDReq', {'only_ask_college_room': True})
        self.assertEqual(result, {'result': 0, 'room_id': 0, 'is_student': False, 'college_room_id': 0})
        self.assertEqual(decoded['room_id'], '0')
        self.assertEqual(self.request('CSChatGetMsgSumyAllChannelReq', {'team_id': 0})[0],
            {'result': 0, 'private_chat_sumys': [], 'group_chat_sumys': [],
             'private_chat_msgs_unread': [], 'team_chat_msgs_unread': []})

    def test_invalid_cursor_and_unauthorized_account_have_native_error_responses(self):
        self.assertEqual(self.request('CSChatWorldLoadTReq', {'read_msg_index': -1})[0]['result'], 124031)
        self.assertEqual(self.request('CSChatWorldLoadTReq', token='invalid-local-session')[0]['result'], 124038)

    def test_pc_mark_all_private_read_acknowledges_the_empty_local_history(self):
        before = self.backend.native_lobby_profile(self.token)
        for fields in ({}, {'last_msg_index': 0, 'target_player_id': 0}):
            result, decoded = self.request('CSChatPrivateReadStatUpdateReq', fields)
            self.assertEqual(result, {'result': 0})
            self.assertEqual(decoded, result)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)
        self.assertEqual(self.request('CSChatPrivateReadStatUpdateReq',
            token='invalid-local-session')[0]['result'], 124038)

    def test_private_read_does_not_acknowledge_a_cursor_absent_from_local_history(self):
        before = self.backend.native_lobby_profile(self.token)
        for fields in ({'last_msg_index': -1}, {'last_msg_index': 1},
                       {'target_player_id': 1},
                       {'last_msg_index': 37, 'target_player_id': 42}):
            with self.subTest(fields=fields):
                self.assertNotEqual(self.request('CSChatPrivateReadStatUpdateReq', fields)[0]['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_rolling_notice_occurrences_are_rejected_on_send_and_receive(self):
        for fields in ({'rolling_notice': {}}, {'rolling_notices': [{}]},
                       {'rolling_notice': {'content': 'not-an-offline-record'}},
                       {'rolling_notices': [{'game_mode': 1}]}):
            with self.subTest(fields=fields), self.assertRaises(DomainError):
                self.codec.encode('CSChatWorldLoadTRes', fields, sequence=23)
        for body in (b'\x3a\x00', b'\x42\x00', b'\x3a\x02\x28\x01'):
            envelope = BusinessEnvelope(body, {'name': 'CSChatWorldLoadTRes',
                'service': 'chat', 'client_sequence_id': 23}).encode()
            with self.subTest(body=body), self.assertRaises(DomainError):
                self.codec.decode(envelope)

    def test_rolling_notice_exception_only_matches_observed_source_signature(self):
        recovery = json.loads((ROOT / 'protocol/generated_codec_fields.json').read_text())
        notice = next(message for message in recovery['messages'] if message['name'] == 'RollingNotice')
        _, report = compile_candidate_descriptors({'messages': [notice]})
        self.assertNotIn('RollingNotice', report['excluded_messages'])
        self.assertIn('RollingNotice', report['empty_only_types'])
        for change in ('name', 'source', 'source_sha256', 'field_number', 'unpaired_helper'):
            changed = copy.deepcopy(notice)
            if change == 'name':
                changed['name'] = 'AnotherIncompleteType'
            elif change == 'source':
                changed['source'] = '@different_source.lua'
            elif change == 'source_sha256':
                changed['source_sha256'] = '0' * 64
            elif change == 'field_number':
                changed['fields'][0]['number'] = 9
            else:
                changed['unpaired_encode_calls'][0]['helper'] = 'addstr'
            _, mutated_report = compile_candidate_descriptors({'messages': [changed]})
            self.assertIn(changed['name'], mutated_report['excluded_messages'])


if __name__ == '__main__':
    unittest.main()
