from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from dfserver.core import Backend
from dfserver import hero_customization
from dfserver.local_commerce import response_fields
from dfserver.handshake_diagnostic import (
    _candidate_codec, _candidate_local_collection_response_frames,
    _candidate_local_hero_response, _candidate_operator_base_fashions)
from dfserver.gcp_data import decode_data_frame, encode_data_frame


ROOT = Path(__file__).resolve().parent.parent


class NativeCustomizationFlowTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.backend = Backend(Path(directory.name) / 'save.sqlite3', ROOT / 'definitions.json')
        self.token = self.backend.register('native-cosmetic-flow', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=60, props=[],
            currencies={17888808889: 100000})
        self.codec = _candidate_codec()
        self.key = b'0123456789abcdef'

    def request(self, name, fields):
        request = self.codec.decode(self.codec.encode(name, fields, sequence=27))
        result = response_fields(request, self.backend, self.token)
        self.assertIsNotNone(result, name)
        self.codec.response(request, result)
        return request, result

    def load(self):
        request = b'ABCD' + self.codec.encode('CSHeroLoadHeroListReq', {}, sequence=29)
        frame = _candidate_local_hero_response(request, self.backend, self.token, self.key,
            header_word4=12, header_word9=29)
        return self.codec.decode(decode_data_frame(frame, self.key,
            direction='server_to_client', compression_method=1, max_output=1024 * 1024).messages[0]).fields

    def test_all_native_heroes_keep_their_verified_base_and_locked_catalog(self):
        loaded = self.load()
        bases = _candidate_operator_base_fashions()
        self.assertEqual(len(loaded['heros']), len(bases))
        for record in loaded['heros']:
            hero_id = int(record['hero_id'])
            self.assertEqual(int(record['fashion_equipped'][0]['id']), bases[hero_id])
            self.assertEqual(int(record['fashion_list'][0]['fashion']['id']), bases[hero_id])
            self.assertTrue(record['accessories'])
        self.assertTrue(any(not a['is_unlock'] for r in loaded['heros'] for a in r['accessories']))
        self.assertEqual(self.backend.native_lobby_profile(self.token)['collection_props'], [])

    def test_research_reward_refreshes_hero_and_can_be_worn_after_restart(self):
        with patch('dfserver.premium_shop.secrets.randbelow', return_value=0):
            request, result = self.request('CSShopOpenLotteryItemReq', {
                'lottery_id': 20300008, 'round': 1, 'buy_prop': {
                    'item_id': 32370000001, 'num': 1,
                    'currency_type': 17888808889, 'price': 100}})
        self.assertEqual(result['result'], 0)
        frame = encode_data_frame((self.codec.response(request, result),), self.key,
            direction='server_to_client', opaque_flag=64, header_word4=12, header_word9=27)
        frames = _candidate_local_collection_response_frames(frame, self.key, self.backend, self.token)
        messages = [self.codec.decode(decode_data_frame(f, self.key,
            direction='server_to_client', compression_method=1, max_output=1024 * 1024).messages[0]) for f in frames]
        self.assertEqual([m.name for m in messages], [
            'CSCollectionPropChangeNtf', 'CSHeroUnlockNtf', 'CSShopOpenLotteryItemRes'])
        hero_id, fashion_id = 88000000029, 30000060010
        target = next(r for r in messages[1].fields['heros'] if int(r['hero_id']) == hero_id)
        self.assertTrue(next(r for r in target['fashion_list']
            if int(r['fashion']['id']) == fashion_id)['is_unlock'])
        watches = [r for r in target['accessories'] if r['is_unlock'] and
            hero_customization.ACCESSORIES[int(r['item']['prop_id'])]['subtype'] == 7]
        granted = {r['prop']['id'] for r in result['change']['prop_changes']}
        watch_id = next(int(r['item']['prop_id']) for r in watches if int(r['item']['prop_id']) in granted)
        self.assertEqual(self.request('CSHeroEquipFashionReq', {'hero_id': hero_id,
            'new_fashions': [{'id': fashion_id, 'slot': 0}]})[1]['result'], 0)
        self.assertEqual(self.request('CSHeroSelectAccessoryReq', {'hero_id': hero_id,
            'accessory_item': {'prop_id': watch_id, 'slot': 0}})[1]['result'], 0)
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        record = next(r for r in self.load()['heros'] if int(r['hero_id']) == hero_id)
        self.assertEqual(int(record['fashion_equipped'][0]['id']), fashion_id)
        self.assertTrue(next(r for r in record['accessories']
            if int(r['item']['prop_id']) == watch_id)['is_selected'])


if __name__ == '__main__':
    unittest.main()
