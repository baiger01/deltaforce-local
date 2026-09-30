import json
from collections import deque
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from dfserver.candidate_business import CandidateMessage
from dfserver.core import Backend
from dfserver.handshake_diagnostic import (
    _candidate_codec, _candidate_local_collection_response,
    _candidate_local_commerce_response, _candidate_local_inventory_change_notification,
    _candidate_local_collection_change_notification, _continue_character_creation)
from dfserver.gcp_data import decode_data_frame, encode_data_frame
from dfserver.gcp_framing import StreamDecoder
from dfserver.local_commerce import response_fields


ROOT = Path(__file__).resolve().parent.parent


class NativeCosmeticsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.backend = Backend(Path(self.directory.name) / 'save.sqlite3',
                               ROOT / 'definitions.json')
        self.token = self.backend.register('cosmetics', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={17888808888: 10000, 32320000001: 10}, props=[{
                'gid': 1001, 'template_id': 18050000002, 'quantity': 1,
                'grid_page_id': 111, 'x': 0, 'y': 0, 'length': 4, 'width': 2}])
        self.codec = _candidate_codec()

    def request(self, name, fields=None):
        return CandidateMessage(name, self.codec.services[name], 19, fields or {})

    def response(self, name, fields=None):
        request = self.request(name, fields)
        response = response_fields(request, self.backend, self.token)
        self.assertIsNotNone(response, name)
        self.codec.response(request, response)
        return response

    def test_collection_provisions_only_open_ordinary_gun_skins(self):
        key = b'0123456789abcdef'
        frame = _candidate_local_collection_response(
            b'ABCD' + self.codec.encode('CSCollectionLoadPropsReq', {}, sequence=17),
            self.backend, self.token, key, header_word4=12, header_word9=17)
        response = self.codec.decode(decode_data_frame(
            frame, key, direction='server_to_client', compression_method=1).messages[0])
        owned = {int(row['id']) for row in response.fields['weapon_skin_props']}
        catalog = json.loads((ROOT / 'protocol/gun_skin_catalog.json').read_text())
        ordinary = {row['skin_id'] for row in catalog['rows']
                    if row['open_collection'] and not row['is_mystical']}
        self.assertTrue(ordinary <= owned)
        self.assertNotIn(28010030002, owned)
        self.assertEqual(len(owned), len(response.fields['weapon_skin_props']))

    def test_skin_apply_persists_and_preserves_weapon_state(self):
        before = self.backend.native_lobby_profile(self.token)['props'][0]
        response = self.response('CSWAssemblyApplySkinReq', {'data_type': 0, 'cmds': [{
            'weapon_id': 18050000002, 'weapon_gid': 1001,
            'skin_id': 28050220002, 'skin_gid': 0, 'apply_all': False}]})
        self.assertEqual(response['result'], 0)
        self.assertEqual(response['changes']['prop_changes'][0]['change_type'], 3)
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        after = self.backend.native_lobby_profile(self.token)['props'][0]
        self.assertEqual(after['weapon']['skin_id'], 28050220002)
        self.assertEqual(after['components'], before['components'])
        self.assertEqual(after['weapon']['load_bullets'], before['weapon']['load_bullets'])
        self.assertEqual(after['weapon']['magazine_capacity'], before['weapon']['magazine_capacity'])

    def test_skin_wrong_gun_or_foreign_gid_rejects_whole_batch(self):
        for bad in ({'weapon_id': 18050000002, 'weapon_gid': 1001, 'skin_id': 28010020001},
                    {'weapon_id': 18050000002, 'weapon_gid': 999999, 'skin_id': 28050220002}):
            before = self.backend.native_lobby_profile(self.token)
            response = self.response('CSWAssemblyApplySkinReq', {'data_type': 0, 'cmds': [
                {'weapon_id': 18050000002, 'weapon_gid': 1001, 'skin_id': 28050220002}, bad]})
            self.assertNotEqual(response['result'], 0)
            self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_shop_bootstrap_links_real_bricks_and_special_key_offer(self):
        response = self.response('CSShopNewGetConfigReq')
        offers = {int(row['lottery_id']): row for row in response['lottery_item_descs']}
        self.assertEqual(int(offers[20100001]['mandel_item_id']), 16110000014)
        self.assertEqual(offers[20100001]['lottery_key_id'], 32320000001)
        key = next(row for row in response['special_item_list']
                   if row['present_item_id'] == 32320000001)
        self.assertEqual((key['buy_item_id'], key['currency_type'], key['price'], key['present_num']),
                         (32210000004, 17888808888, 60, 1))

    def test_shop_does_not_overwrite_native_localized_names(self):
        self.assertEqual(self.response('CSShopGetGameItemConfigReq')['descs'], [])

    def test_mandel_box_contains_real_reward_groups(self):
        response = self.response('CSGetBoxInfoReq', {'id_list': [42010000014], 'source': 1})
        box = response['info_list'][0]
        self.assertEqual(box['box_id'], 42010000014)
        self.assertEqual(box['show_id1'], 28010050271)
        groups = {row['group_id']: row for row in box['group_list']}
        self.assertTrue(groups[2010001401]['core_flag'])
        self.assertEqual(groups[2010001401]['prop_list'][0]['prop_id'], 28010050271)
        self.assertGreater(len(groups[2010001402]['prop_list']), 10)

    def test_special_key_purchase_debits_exact_total_and_survives_restart(self):
        request = {'buy_props': [{'item_id': 32320000001, 'num': 10,
                    'currency_type': 17888808888, 'price': 600,
                    'currency_type_substitute': 0, 'price_substitute': 0}]}
        before = self.backend.native_lobby_profile(self.token)
        response = self.response('CSShopBuyLotteryItemReq', request)
        self.assertEqual(response['result'], 0)
        self.assertEqual(response['change']['currency_changes'], [
            {'currency_id': 17888808888, 'delta': -600, 'current_num': 9400}])
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        amounts = {row['currency_id']: row['amount']
                   for row in self.backend.native_lobby_profile(self.token)['currencies']}
        self.assertNotIn(32320000001, amounts)
        self.assertEqual(response['change']['prop_changes'][0]['prop']['id'], 32210000004)
        self.assertEqual(self.backend.native_lobby_profile(self.token)['collection_props'],
                         [{'template_id': 32210000004, 'quantity': 10},
                          {'template_id': 32320000001, 'quantity': 20}])
        invalid = self.response('CSShopBuyLotteryItemReq', {'buy_props': [
            {**request['buy_props'][0], 'price': 1}]})
        self.assertNotEqual(invalid['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token)['props'], before['props'])

    def test_brick_and_paid_keys_purchase_commits_three_grants_atomically(self):
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={17888808887: 500000, 17888808888: 10000}, props=[])
        request = {'buy_props': [
            {'item_id': 16110000022, 'num': 10, 'currency_type': 17888808887, 'price': 20000},
            {'item_id': 32320000001, 'num': 10, 'currency_type': 17888808888, 'price': 600}]}
        response = self.response('CSShopBuyLotteryItemReq', request)
        self.assertEqual(response['result'], 0)
        state = self.backend.native_lobby_profile(self.token)
        self.assertEqual({row['currency_id']: row['amount'] for row in state['currencies']},
                         {17888808887: 300000, 17888808888: 9400})
        self.assertEqual(state['collection_props'], [
            {'template_id': 16110000022, 'quantity': 10},
            {'template_id': 32210000004, 'quantity': 10},
            {'template_id': 32320000001, 'quantity': 10}])
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={17888808887: 500000, 17888808888: 1}, props=[])
        before = self.backend.native_lobby_profile(self.token)
        self.assertNotEqual(self.response('CSShopBuyLotteryItemReq', request)['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_draw_consumes_owned_brick_and_key_and_persists_real_skin_instance(self):
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={17888808887: 500000, 17888808888: 10000}, props=[])
        self.response('CSShopBuyLotteryItemReq', {'buy_props': [
            {'item_id': 16110000026, 'num': 1, 'currency_type': 17888808887, 'price': 20000},
            {'item_id': 32320000001, 'num': 1, 'currency_type': 17888808888, 'price': 60}]})
        with patch('dfserver.mandel.secrets.randbelow', return_value=0):
            response = self.response('CSLotteryBlindBoxDrawReq', {'box_list': [{
                'box_id': 101018, 'num': 1, 'opened_prop_id': 16110000026,
                'opened_prop_gid': 0, 'opened_prop_num': 1}]})
        self.assertEqual(response['result'], 0)
        rewards = [row['prop'] for row in response['data_change']['prop_changes']
                   if row['change_type'] == 1]
        self.assertEqual(len(rewards), 1)
        self.assertEqual(rewards[0]['id'], 28020050003)
        self.assertGreater(rewards[0]['gid'], 0)
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        owned = self.response('CSCollectionLoadMysticalSkinPropsReq')['mystical_skin_props']
        self.assertEqual(owned, rewards)
        state = self.backend.native_lobby_profile(self.token)
        self.assertEqual(state['collection_props'], [{'template_id': 32210000004, 'quantity': 1}])
        self.assertFalse(any(row['currency_id'] == 32320000001 for row in state['currencies']))
        info = self.response('CSGetBoxInfoReq', {'id_list': [101018]})
        self.assertEqual(info['info_list'][0]['open_count'], 1)
        self.assertEqual(info['open_lottery_records'][0]['add_props'], rewards)

    def test_draw_invalid_link_or_missing_key_preserves_entire_save(self):
        before = self.backend.native_lobby_profile(self.token)
        for box_id, item_id in ((101018, 16110000022), (101018, 16110000026)):
            response = self.response('CSLotteryBlindBoxDrawReq', {'box_list': [{
                'box_id': box_id, 'num': 1, 'opened_prop_id': item_id, 'opened_prop_num': 1}]})
            self.assertNotEqual(response['result'], 0)
            self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_draw_pushes_skin_instance_and_brick_deletion_to_collection_only(self):
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={17888808887: 500000, 32320000001: 10}, props=[])
        self.response('CSShopBuyLotteryItemReq', {'buy_props': [
            {'item_id': 16110000026, 'num': 1, 'currency_type': 17888808887, 'price': 20000}]})
        key = b'0123456789abcdef'
        with patch('dfserver.mandel.secrets.randbelow', return_value=0):
            response = _candidate_local_commerce_response(b'ABCD' + self.codec.encode(
                'CSLotteryBlindBoxDrawReq', {'box_list': [{'box_id': 101018, 'num': 1,
                    'opened_prop_id': 16110000026, 'opened_prop_num': 1}]}, sequence=17),
                self.backend, self.token, key, header_word4=12, header_word9=17)
        self.assertIsNone(_candidate_local_inventory_change_notification(response, key,
                      header_word4=12, header_word9=18))
        frame = _candidate_local_collection_change_notification(response, key,
                      header_word4=12, header_word9=19)
        pushed = self.codec.decode(decode_data_frame(frame, key,
                    direction='server_to_client', compression_method=1).messages[0])
        changes = pushed.fields['data_change']
        self.assertEqual([row['change_type'] for row in changes], [1, 2, 3])
        self.assertGreater(int(changes[0]['prop']['gid']), 0)
        self.assertEqual(int(changes[1]['prop']['num']), 0)
        self.assertEqual(int(changes[1]['delta_num']), -1)
        self.assertEqual(int(changes[2]['prop']['id']), 32320000001)
        self.assertEqual(int(changes[2]['prop']['num']), 9)

    def test_legacy_key_currency_migrates_once_without_charging_or_duplication(self):
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.execute('INSERT INTO native_lobby_currencies VALUES (?,?,?) '
                'ON CONFLICT(player_id,currency_id) DO UPDATE SET amount=excluded.amount',
                (player_id, 32320000001, 73))
            connection.commit()
        for _ in range(2):
            self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        state = self.backend.native_lobby_profile(self.token)
        self.assertEqual(state['collection_props'], [{'template_id': 32320000001, 'quantity': 83}])
        self.assertEqual(state['currencies'], [{'currency_id': 17888808888, 'amount': 10000}])

    def reconnect_frames(self, name, fields):
        key = b'0123456789abcdef'
        request = encode_data_frame((b'ABCD' + self.codec.encode(name, fields, sequence=23),),
                                    key, direction='client_to_server',
                                    header_word4=13, header_word9=23)

        class ClosedConnection:
            def __init__(self):
                self.sent = []

            def sendall(self, payload):
                self.sent.append(payload)

            def recv(self, _size):
                return b''

        connection = ClosedConnection()
        _continue_character_creation(connection, StreamDecoder(), deque(), request,
            SimpleNamespace(session_key=key), {}, self.backend, self.token, 23, {},
            continuation_seconds=1)
        frames = [StreamDecoder().feed(payload)[0] for payload in connection.sent]
        messages = [self.codec.decode(decode_data_frame(frame, key,
            direction='server_to_client', compression_method=1).messages[0]) for frame in frames]
        self.assertEqual([frame.header_word9 for frame in frames],
                         sorted({frame.header_word9 for frame in frames}))
        return messages

    def test_purchase_updates_collection_before_callback_can_repeat_purchase(self):
        messages = self.reconnect_frames('CSShopBuyLotteryItemReq', {'buy_props': [
            {'item_id': 32320000001, 'num': 10, 'currency_type': 17888808888, 'price': 600}]})
        self.assertEqual([message.name for message in messages], [
            'CSCollectionPropChangeNtf', 'CSShopBuyLotteryItemRes', 'CSDepositChangeNtf'])
        self.assertEqual(messages[1].sequence, 23)
        additions = {int(row['prop']['id']): int(row['prop']['num'])
                     for row in messages[0].fields['data_change']}
        self.assertEqual(additions, {32210000004: 10, 32320000001: 10})

    def test_ten_draw_animation_receives_ten_rewards_and_no_consumed_stacks(self):
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={17888808887: 500000, 32320000001: 20}, props=[])
        self.response('CSShopBuyLotteryItemReq', {'buy_props': [
            {'item_id': 16110000023, 'num': 20, 'currency_type': 17888808887, 'price': 20000}]})
        messages = self.reconnect_frames('CSLotteryBlindBoxDrawReq', {'box_list': [{
            'box_id': 101011, 'num': 10, 'opened_prop_id': 16110000023, 'opened_prop_num': 10}]})
        response = next(message for message in messages if message.name == 'CSLotteryBlindBoxDrawRes')
        # RewardServer.lua 0.17.0 treats every Add/Modify with prop.num>0 as an animation reward.
        displayed = [row['prop'] for row in response.fields['data_change']['prop_changes']
                     if int(row['change_type']) in (1, 3) and int(row['prop']['num']) > 0]
        self.assertEqual(len(displayed), 10)
        self.assertFalse({16110000023, 32320000001} & {int(row['id']) for row in displayed})
        self.assertEqual([message.name for message in messages], [
            'CSCollectionPropChangeNtf', 'CSLotteryBlindBoxDrawRes'])
        quantities = {int(row['prop']['id']): int(row['prop']['num'])
                      for row in messages[0].fields['data_change'] if int(row['change_type']) == 3}
        self.assertEqual(quantities, {16110000023: 10, 32320000001: 10})
        self.assertEqual(response.sequence, 23)

    def test_pool_display_probabilities_sum_to_one_after_skin_bootstrap(self):
        self.response('CSWAssemblySkinInfoGetReq')
        info = self.response('CSGetBoxInfoReq', {'id_list': [101018]})['info_list'][0]
        self.assertAlmostEqual(sum(row['real_prob'] for group in info['group_list']
                                   for row in group['prop_list']), 1)
        self.assertTrue(all(row['prop_info']['id'] == row['prop_id']
                            for group in info['group_list'] for row in group['prop_list']))

    def test_local_draw_guarantee_and_display_share_persisted_counter(self):
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={17888808887: 500000, 32320000001: 10}, props=[])
        self.response('CSShopBuyLotteryItemReq', {'buy_props': [
            {'item_id': 16110000026, 'num': 1, 'currency_type': 17888808887, 'price': 20000}]})
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.execute('INSERT INTO native_lobby_lottery_state VALUES (?,?,?,?)',
                               (player_id, 101018, 74, 74))
            connection.commit()
        info = self.response('CSGetBoxInfoReq', {'id_list': [101018]})['info_list'][0]
        core = next(group for group in info['group_list'] if group['core_flag'])
        self.assertEqual((core['real_prob'], core['time_assured']), (1, 1))
        response = self.response('CSLotteryBlindBoxDrawReq', {'box_list': [{
            'box_id': 101018, 'num': 1, 'opened_prop_id': 16110000026, 'opened_prop_num': 1}]})
        self.assertEqual(response['result'], 0)
        self.assertEqual(response['data_change']['prop_changes'][0]['prop']['id'], 28020050003)
        info = self.response('CSGetBoxInfoReq', {'id_list': [101018]})['info_list'][0]
        self.assertEqual(next(group['time_assured'] for group in info['group_list'] if group['core_flag']), 75)


if __name__ == '__main__':
    unittest.main()
