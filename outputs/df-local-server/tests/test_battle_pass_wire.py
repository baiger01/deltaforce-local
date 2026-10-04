from pathlib import Path
import tempfile
import unittest

from dfserver import battle_pass
from dfserver import weapon_pendants
from dfserver.core import Backend
from dfserver.gcp_data import decode_data_frame
from dfserver.handshake_diagnostic import (
    _candidate_codec, _candidate_local_commerce_response,
    _candidate_local_battle_pass_notifications)


ROOT = Path(__file__).resolve().parent.parent


class BattlePassWireTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.backend = Backend(Path(temporary.name) / 'save.sqlite3', ROOT / 'definitions.json')
        self.token = self.backend.register('battlepass-wire', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=60, props=[],
            currencies={17888808888: 100000, 17888808889: 100000})
        self.codec, self.key = _candidate_codec(), b'0123456789abcdef'

    def decode(self, frame):
        payload = decode_data_frame(frame, self.key, direction='server_to_client',
                                    compression_method=1).messages[0]
        return self.codec.decode(payload)

    def reply(self, name, fields):
        entry = {}
        payload = b'ABCD' + self.codec.encode(name, fields, sequence=91)
        response = _candidate_local_commerce_response(payload, self.backend, self.token,
            self.key, header_word4=12, header_word9=91, diagnostic_entry=entry)
        notifications = _candidate_local_battle_pass_notifications(entry, self.key,
            header_word4=12, header_word9=91)
        self.assertNotIn('_battle_pass_changes', entry)
        self.assertEqual(_candidate_local_battle_pass_notifications(entry, self.key,
            header_word4=12, header_word9=91), [])
        return self.decode(response), notifications

    def test_membership_purchase_sends_committed_balance_and_all_collection_rewards_once(self):
        with self.subTest(mapping=battle_pass.CATALOG['mapping_status']):
            self.assertTrue(battle_pass.mutations_enabled())
            response, frames = self.reply('CSBattlePassBuyReq',
                {'buy_type': 4, 'binded_delta_coin': 720})
            self.assertEqual(response.fields['result'], 0)
            self.assertEqual(response.fields['info']['type'], 4)
            self.assertEqual([frame.header_word9 for frame in frames], [92, 93])
            notices = {message.name: message.fields for message in map(self.decode, frames)}
            currency = notices['CSDepositChangeNtf']['deposit_change']['currency_changes']
            self.assertEqual(sum(int(row['delta']) for row in currency), -560)
            rewards = notices['CSCollectionPropChangeNtf']['data_change']
            self.assertEqual({int(row['prop']['id']) for row in rewards},
                             {28011350012, 32300000132, 41001140097})
            self.assertTrue(all(int(row['after_num']) == 1 and int(row['delta_num']) == 1
                                for row in rewards))
            before = self.backend.native_lobby_profile(self.token)
            response, frames = self.reply('CSBattlePassBuyReq',
                {'buy_type': 4, 'binded_delta_coin': 720})
            self.assertEqual(response.fields['result'], 170004)
            self.assertEqual(frames, [])
            self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_invalid_quote_and_queries_never_publish_uncommitted_changes(self):
        with self.subTest(mapping=battle_pass.CATALOG['mapping_status']):
            before = self.backend.native_lobby_profile(self.token)
            response, frames = self.reply('CSBattlePassBuyReq',
                {'buy_type': 4, 'binded_delta_coin': 1})
            self.assertEqual(response.fields['result'], 170003)
            self.assertEqual(frames, [])
            self.assertEqual(self.backend.native_lobby_profile(self.token), before)
            response, frames = self.reply('CSBattlePassGetInfoReq', {'get_info_type': 1})
            self.assertEqual(response.fields['result'], 0)
            self.assertEqual(frames, [])

    def test_level_sixty_pendant_goes_to_owned_collection_and_survives_restart(self):
        response, _ = self.reply('CSBattlePassBuyReq', {'buy_type': 4, 'binded_delta_coin': 720})
        self.assertEqual(response.fields['result'], 0)
        response, frames = self.reply('CSBattlePassBuyLevelReq', {'level': 59, 'binded_delta_coin': 5900})
        self.assertEqual(response.fields['result'], 0)
        self.assertEqual(response.fields['info']['main_line']['level_info']['curr_level'], 60)
        notices = {message.name: message.fields for message in map(self.decode, frames)}
        rewards = notices['CSCollectionPropChangeNtf']['data_change']
        reward = next(row for row in rewards if int(row['prop']['id']) == 13460040086)
        self.assertEqual((int(reward['delta_num']), int(reward['after_num'])), (1, 1))
        profile = self.backend.native_lobby_profile(self.token)
        self.assertFalse(any(row['template_id'] == 13460040086 for row in profile['props']))
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        owned = weapon_pendants.collection(self.backend, self.token)
        pendant = next(row for row in owned if row['id'] == 13460040086)
        self.assertEqual((pendant['gid'], pendant['num']), (0, 1))


if __name__ == '__main__':
    unittest.main()
