"""Verify difficulty choices through the native map-board wire contract."""

import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from dfserver.gcp_data import decode_data_frame
from dfserver.handshake_diagnostic import (
    _candidate_codec, _candidate_local_map_board_catalog,
    _candidate_local_prepare_map_response, _candidate_local_room_mode_response,
)


class NativeMapBoardDifficultyTests(unittest.TestCase):
    def setUp(self):
        self.codec = _candidate_codec()
        self.key = b'0123456789abcdef'
        self.backend = SimpleNamespace(native_lobby_profile=lambda _: {'level': 60})
        _candidate_local_map_board_catalog.cache_clear()
        self.addCleanup(_candidate_local_map_board_catalog.cache_clear)

    def decode(self, frame):
        payload = decode_data_frame(frame, self.key, direction='server_to_client',
                                    compression_method=1).messages[0]
        return self.codec.decode(payload).fields

    def board(self):
        message = b'ABCD' + self.codec.encode('CSPrepareMapBoardReq', {}, sequence=9)
        observation = {}
        response = self.decode(_candidate_local_prepare_map_response(
            message, self.backend, None, self.key, header_word4=12,
            header_word9=9, observation=observation))
        self.assertEqual(observation['response_fields'], response)
        return response['board_info_array']

    def test_default_board_exposes_real_difficulties_instead_of_default_zero(self):
        rows = self.board()
        self.assertEqual({row.get('difficulty', 0) for row in rows}, {1, 2, 3})
        expected_submodes = {1: 10, 2: 11, 3: 12}
        for row in rows:
            self.assertEqual(row['mode']['sub_mode'],
                             expected_submodes[row['difficulty']])
        # GameModeServer.HandleMapBoardInfo indexes difficulty choices using
        # match_mode_type=3; the ordinary mode entries must also stay available.
        for mode_type in (1, 3):
            choices = [row for row in rows if row['match_mode_type'] == mode_type]
            self.assertEqual({row['difficulty'] for row in choices}, {1, 2, 3})

    def test_dam_has_normal_and_confidential_without_a_fabricated_top_secret_mode(self):
        choices = {(row.get('difficulty', 0), row['mode']['map_id'],
                    row['mode']['match_mode_id']) for row in self.board()
                   if row['point_id'] == 1}
        self.assertEqual(choices, {(1, 2201, '142201103'), (2, 2202, '142202113')})

    def test_room_mode_list_preserves_the_selected_difficulty_mode(self):
        expected = {row['mode']['match_mode_id']: row['mode'] for row in self.board()}
        message = b'ABCD' + self.codec.encode(
            'CSRoomGetMatchModeListReq', {'game_mode': 1}, sequence=10)
        response = self.decode(_candidate_local_room_mode_response(
            message, self.key, header_word4=12, header_word9=10))
        actual = {row['mode_info']['match_mode_id']: row['mode_info']
                  for row in response['mode_info_list']}
        self.assertEqual(actual, expected)
        self.assertIn('143902123', actual)
        self.assertEqual(actual['143902123']['sub_mode'], 12)

    def test_catalog_rejects_invalid_difficulty_before_serializing(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'board.json'
            for difficulty in (-1, 4, True, '2'):
                with self.subTest(difficulty=difficulty):
                    path.write_text(json.dumps({'operations': [{
                        'point_id': 1, 'map_id': 2201, 'match_mode_id': 142201103,
                        'min_level': 1, 'difficulty': difficulty,
                    }]}), encoding='utf-8')
                    with patch.dict('os.environ', {'DF_LOCAL_MAP_BOARD_CATALOG': str(path)}):
                        _candidate_local_map_board_catalog.cache_clear()
                        with self.assertRaisesRegex(ValueError, 'difficulty'):
                            _candidate_local_map_board_catalog()


if __name__ == '__main__':
    unittest.main()
