"""Live map diagnostics preserve stages without copying session credentials."""

import contextlib
import io
import json
import unittest

from dfserver.handshake_diagnostic import _log_request_progress


class MapRequestProgressTests(unittest.TestCase):
    def test_live_progress_includes_the_selected_mode_and_handoff_stages(self):
        entry = {
            'request_name': 'CSRoomMatchStartAllocReq',
            'local_match_mode_info': {'map_id': 2201, 'match_mode_id': 142201103},
            'local_match_alloc_result': 0,
            'local_match_prepare_probe_sent': True,
            'local_game_server_join_probe_sent': True,
            'session_token': 'private-session',
        }
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            _log_request_progress(entry, 'processed')
        event = json.loads(stream.getvalue())
        self.assertEqual(event['local_match_mode_info'], entry['local_match_mode_info'])
        self.assertEqual(event['local_match_alloc_result'], 0)
        self.assertTrue(event['local_match_prepare_probe_sent'])
        self.assertTrue(event['local_game_server_join_probe_sent'])
        self.assertNotIn('private-session', stream.getvalue())

    def test_live_progress_records_the_accepted_quest_count_without_quest_payloads(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            _log_request_progress({
                'request_name': 'CSQuestGetAcceptedQuestsReq',
                'local_activity_result': 0,
                'local_activity_accepted_quest_count': 1,
                'accepted_quests': [{'private_payload': 'must-not-be-logged'}],
            }, 'processed')
        event = json.loads(stream.getvalue())
        self.assertEqual(event['local_activity_accepted_quest_count'], 1)
        self.assertNotIn('must-not-be-logged', stream.getvalue())


if __name__ == '__main__':
    unittest.main()
