"""SOL room records preserve owned cosmetics already equipped in the lobby."""

from pathlib import Path
import tempfile
import unittest

from dfserver.core import Backend
from dfserver import hero_customization as hero
from dfserver.handshake_diagnostic import (
    _candidate_codec, _candidate_local_solo_room_team_response,
    _candidate_local_solo_room_hero_response,
)
from dfserver.gcp_data import decode_data_frame


ROOT = Path(__file__).resolve().parent.parent
HERO = 88000000025
FASHION = 30000050013
VOICE = 38050050066


class SoloRoomCosmeticTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.backend = Backend(Path(folder.name) / 'save.sqlite3', ROOT / 'definitions.json')
        self.token = self.backend.register('room-cosmetics', 'local-password-123')['session']
        self.backend.set_native_selected_hero(self.token, HERO)
        self.player_id = int(self.backend.native_identity(self.token)['native_id'])
        self.codec = _candidate_codec()
        self.key = b'0123456789abcdef'
        self.mode = {'game_mode': 1, 'map_id': 2201, 'match_mode_id': 142201103}
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            for item_id in (FASHION, VOICE):
                connection.execute('INSERT INTO native_lobby_collection_props '
                    '(player_id,template_id,quantity) VALUES (?,?,1)', (player_id, item_id))
            connection.commit()
        self.assertEqual(hero.equip_hero(self.backend, self.token, HERO,
            [{'slot': 0, 'id': FASHION}])['result'], 0)
        self.assertEqual(hero.select_accessory(self.backend, self.token, {
            'hero_id': HERO, 'accessory_item': {'prop_id': VOICE, 'slot': 2}})['result'], 0)

    def decode(self, frame):
        return self.codec.decode(decode_data_frame(frame, self.key,
            direction='server_to_client', compression_method=1,
            max_output=1024 * 1024).messages[0]).fields

    def assert_cosmetics(self, record):
        self.assertEqual(int(record['hero_id']), HERO)
        self.assertEqual(int(record['fashion_equipped'][0]['id']), FASHION)
        selected_voice = next(row for row in record['accessories']
                              if int(row['item']['prop_id']) == VOICE)
        self.assertTrue(selected_voice['is_selected'])
        self.assertEqual(int(selected_voice['item']['slot']), 2)

    def test_initial_room_inherits_saved_lobby_cosmetics_after_restart(self):
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        request = b'ABCD' + self.codec.encode('CSMatchRoomGetSolRoomTeamTReq',
            {'room_id': self.player_id}, sequence=20)
        frame = _candidate_local_solo_room_team_response(request, self.backend,
            self.token, self.mode, self.key, header_word4=12, header_word9=20)
        self.assert_cosmetics(self.decode(frame)['player_info_array'][0]['hero_info'])

    def test_change_hero_notice_preserves_the_selected_heroes_cosmetics(self):
        self.backend.set_native_selected_hero(self.token, 88000000047)
        request = b'ABCD' + self.codec.encode('CSMatchRoomSetSolRoomHeroTReq',
            {'room_id': self.player_id, 'hero_id': HERO}, sequence=21)
        response, notice = _candidate_local_solo_room_hero_response(request,
            self.backend, self.token, self.mode, self.key,
            header_word4=12, header_word9=21)
        self.assertEqual(self.decode(response)['result'], 0)
        self.assert_cosmetics(self.decode(notice)['hero_info'])

    def test_preview_does_not_reset_the_current_equipped_fashion(self):
        request = b'ABCD' + self.codec.encode('CSMatchRoomSetPreSelectedHeroTReq',
            {'room_id': self.player_id, 'pre_selected_hero_id': 88000000047}, sequence=22)
        response, notice = _candidate_local_solo_room_hero_response(request,
            self.backend, self.token, self.mode, self.key,
            header_word4=12, header_word9=22)
        self.assertEqual(self.decode(response)['result'], 0)
        self.assert_cosmetics(self.decode(notice)['hero_info'])
        self.assertEqual(self.backend.native_lobby_profile(self.token)['selected_hero_id'], HERO)


if __name__ == '__main__':
    unittest.main()
