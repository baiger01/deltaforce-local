import tempfile
import json
from collections import deque
from pathlib import Path
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import dfserver.handshake_diagnostic as diagnostic
from dfserver.candidate_business import CandidateMessage
from dfserver.core import Backend, DomainError
from dfserver.handshake_diagnostic import _candidate_codec
from dfserver.handshake_diagnostic import _candidate_local_commerce_response
from dfserver.handshake_diagnostic import _candidate_local_commerce_result
from dfserver.handshake_diagnostic import _candidate_local_inventory_change_notification
from dfserver.handshake_diagnostic import _candidate_local_collection_change_notification
from dfserver.handshake_diagnostic import _candidate_local_collection_response
from dfserver.handshake_diagnostic import _candidate_local_serial_buy_summary
from dfserver.handshake_diagnostic import _candidate_local_deposit_response
from dfserver.handshake_diagnostic import _candidate_local_equip_response
from dfserver.handshake_diagnostic import _candidate_local_equip_summary
from dfserver.handshake_diagnostic import _continue_character_creation
from dfserver.gcp_data import decode_data_frame, encode_data_frame
from dfserver.local_commerce import (CURRENCY_ID, MANDEL_BRICK_PURCHASE_CURRENCY,
                                     MANDEL_KEY_CURRENCY, MANDEL_KEY_ID,
                                     default_weapon_presets, item_condition_fields,
                                     order_id, response_fields,
                                     stock_catalog)


ROOT = Path(__file__).resolve().parent.parent


class LocalCommerceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.backend = Backend(Path(self.temporary.name) / 'save.sqlite3',
                               ROOT / 'definitions.json')
        self.token = self.backend.register('buyer', 'buyer-password-123')['session']
        self.backend.set_native_lobby_profile(
            self.token, level=60, currencies={CURRENCY_ID: 100000}, props=[])
        self.codec = _candidate_codec()

    def request(self, name, fields):
        return CandidateMessage(name, self.codec.services[name], 17, fields)

    def test_catalogue_and_offer_are_encoded_for_original_client(self):
        item_id = 15080010001
        self.assertIn(item_id, stock_catalog())
        self.assertTrue(all(row['name_key'] or item_id == 18300000004
                            for item_id, row in stock_catalog().items()))
        for name in ('CSMarketGetTypeListReq', 'CSAuctionGetTypeListReq',
                     'CSMallGetBuyGoodsReq'):
            fields = response_fields(self.request(name, {}), self.backend, self.token)
            encoded = self.codec.response(self.request(name, {}), fields)
            self.assertLess(len(encoded), 1024 * 1024)
            self.assertTrue(fields.get('type_lists') or fields.get('buy_props'))
        for name in ('CSMarketGetSaleListReq', 'CSAuctionGetSaleListReq'):
            request = self.request(name, {'info': {'prop_id': str(item_id)}})
            fields = response_fields(request, self.backend, self.token)
            self.codec.response(request, fields)
            detail = fields.get('sale_list_info') or fields['sale_list_infos'][0]
            self.assertEqual(int(detail['sale_lists'][0]['order_id']), order_id(item_id))

        batch = self.request('CSAuctionGetSaleListBatchReq', {
            'infos': [{'prop_id': str(item_id)}]})
        batch_fields = response_fields(batch, self.backend, self.token)
        self.codec.response(batch, batch_fields)
        self.assertEqual(int(batch_fields['sale_lists'][0]['prop_id']), item_id)
        self.assertEqual(int(batch_fields['sale_lists'][0]['sale_lists'][0]['order_id']),
                         order_id(item_id))

    def test_single_armor_offer_uses_client_fallback_durability_index(self):
        request = self.request('CSAuctionGetTypeListReq',
                               {'prop_ids': [15080010001]})
        fields = response_fields(request, self.backend, self.token)
        row = fields['type_lists'][0]
        self.assertEqual(row['durability_lvl'], 0)
        self.assertEqual(row['durability_ratio'], 0)
        self.codec.response(request, fields)

        armor_id = 11050006003
        armor_request = self.request('CSAuctionGetTypeListReq',
                                     {'prop_ids': [armor_id]})
        armor_fields = response_fields(armor_request, self.backend, self.token)
        armor_row = armor_fields['type_lists'][0]
        # AuctionServer.GetPropSaleInfo reads index 0 unless all three tiers exist.
        self.assertEqual(armor_row['durability_lvl'], 0)
        self.assertEqual(armor_row['durability_ratio'], 100)
        self.codec.response(armor_request, armor_fields)

        detail_request = self.request('CSAuctionGetSaleListBatchReq',
                                      {'infos': [{'prop_id': str(armor_id)}]})
        detail_fields = response_fields(detail_request, self.backend, self.token)
        detail = detail_fields['sale_lists'][0]
        self.assertEqual(detail['durability_lvl'], 0)
        self.assertEqual(detail['durability_ratio'], 100)
        self.codec.response(detail_request, detail_fields)

    def test_auction_offer_window_contains_heartbeat_time_after_purchase(self):
        item_id = 37190400001
        price = stock_catalog()[item_id]['initial_guide_price']
        detail_request = self.request('CSAuctionGetSaleListBatchReq', {
            'infos': [{'prop_id': item_id}]})
        heartbeat = b'ABCD' + self.codec.encode(
            'CSOnlineHeartbeatReq', {'padding': 17}, sequence=9)
        key = b'0123456789abcdef'
        with patch('dfserver.handshake_diagnostic.time.time', return_value=1790756500.75):
            initial = response_fields(detail_request, self.backend, self.token)
            purchase = response_fields(self.request('CSSerialCheapBuyReq', {
                'scene': 503, 'buy_list': [{'channel': 2, 'single_auction_prop': {
                    'prop_id': item_id, 'buy_num': 30, 'currency': CURRENCY_ID,
                    'price': price, 'to_pos': 199997}}]}), self.backend, self.token)
            reopened = response_fields(detail_request, self.backend, self.token)
            frame = diagnostic._candidate_local_heartbeat_response(
                heartbeat, key, header_word4=12, header_word9=9)
        self.assertEqual(purchase['result'], 0)
        server_time = int(self.codec.decode(decode_data_frame(
            frame, key, direction='server_to_client',
            compression_method=1).messages[0]).fields['tick_count'])
        for response in (initial, reopened):
            decoded = self.codec.decode(self.codec.response(detail_request, response))
            detail = decoded.fields['sale_lists'][0]
            self.assertLessEqual(int(detail['auction_vaild_time_begin']), server_time)
            self.assertGreaterEqual(int(detail['auction_vaild_time_end']), server_time)
            self.assertGreater(int(detail['sale_lists'][0]['selling_num']), 0)

    def test_type_list_deduplicates_identical_rows_but_keeps_distinct_variants(self):
        fields = response_fields(self.request('CSMarketGetTypeListReq', {}),
                                 self.backend, self.token)
        ids = {int(row['prop_id']) for row in fields['type_lists']}
        self.assertIn(14990000029, ids)
        self.assertNotIn(14990000221, ids)
        self.assertIn(14990000005, ids)
        self.assertIn(14990000269, ids)
        requested = response_fields(self.request(
            'CSMarketGetTypeListReq', {'prop_ids': [14990000221]}),
            self.backend, self.token)
        self.assertEqual([int(row['prop_id']) for row in requested['type_lists']],
                         [14990000221])

    def test_browse_list_hides_receiver_alias_of_a_complete_gun(self):
        complete_gun = 10010000019
        receiver = 18010000010
        self.assertEqual(stock_catalog()[complete_gun]['name_key'],
                         stock_catalog()[receiver]['name_key'])
        fields = response_fields(self.request('CSAuctionGetTypeListReq', {}),
                                 self.backend, self.token)
        ids = {int(row['prop_id']) for row in fields['type_lists']}
        self.assertIn(complete_gun, ids)
        self.assertNotIn(receiver, ids)
        requested = response_fields(self.request(
            'CSAuctionGetTypeListReq', {'prop_ids': [receiver]}),
            self.backend, self.token)
        self.assertEqual([int(row['prop_id']) for row in requested['type_lists']],
                         [receiver])

    def test_all_complete_gun_classes_have_weapon_condition_fields(self):
        for item_id in (10010000019, 10020000001, 10030000002,
                        10040000003, 10050000034, 10060000008,
                        10070000022, 10080000007):
            with self.subTest(item_id=item_id):
                condition = item_condition_fields(item_id)
                self.assertIn('weapon', condition)
                self.assertIn('components', condition)

    def test_local_stock_only_lists_guns_with_installed_default_preset(self):
        source = ROOT / 'protocol/weapon_preset_catalog.json'
        mapping = json.loads(source.read_text(encoding='utf-8'))[
            'default_preset_to_receiver']
        self.assertEqual(mapping['10010000019'], 18010000010)
        self.assertIn(10010000019, stock_catalog())
        self.assertNotIn(10010000197, stock_catalog())
        self.assertTrue(all(str(item_id) in mapping for item_id in stock_catalog()
                            if str(item_id).startswith('100')))

    def test_type_list_diagnostic_accepts_client_boolean_with_nums(self):
        summarize = getattr(diagnostic, '_candidate_local_commerce_type_filters', None)
        self.assertIsNotNone(summarize)
        for name in ('CSAuctionGetTypeListReq', 'CSMarketGetTypeListReq'):
            message = b'ABCD' + self.codec.encode(name, {
                'prop_ids': [15080010001], 'prop_prefixes': [1508],
                'with_nums': True}, sequence=25)
            self.assertEqual(summarize(message), {
                'prop_ids': [15080010001], 'prop_prefixes': [1508],
                'with_nums': True})

    def test_full_type_list_fits_a_single_unmerged_data_frame(self):
        key = b'0123456789abcdef'
        request = b'ABCD' + self.codec.encode('CSMarketGetTypeListReq', {}, sequence=17)
        frame = _candidate_local_commerce_response(
            request, self.backend, self.token, key, header_word4=12, header_word9=17)
        decoded = decode_data_frame(frame, key, direction='server_to_client',
                                    compression_method=1, max_output=1024 * 1024)
        message = self.codec.decode(decoded.messages[0])
        self.assertGreater(len(message.fields['type_lists']), 4000)
        self.assertLess(len(message.fields['type_lists']), len(stock_catalog()))
        self.assertEqual(len({int(row['prop_id']) for row in message.fields['type_lists']}),
                         len(message.fields['type_lists']))

    def test_full_market_type_list_result_probe_accepts_installed_catalogue_size(self):
        key = b'0123456789abcdef'
        for name in ('CSMarketGetTypeListReq', 'CSAuctionGetTypeListReq'):
            with self.subTest(name=name):
                request = b'ABCD' + self.codec.encode(name, {'with_nums': True},
                                                      sequence=18)
                frame = _candidate_local_commerce_response(
                    request, self.backend, self.token, key,
                    header_word4=12, header_word9=18)
                self.assertEqual(_candidate_local_commerce_result(frame, key), 0)

    def test_shop_bootstrap_responses_initialize_client_state(self):
        cases = {
            'CSMallGetMysteryShopItemsReq': ('items',),
            'CSMallGetLabelNo1ConfigReq': ('cfg_list',),
            'CSMallGetRecycleGoodsReq': ('recyle_props',),
            'CSMallGetPlayerDailyLimitGoodsReq': ('limit_items',),
            'CSMallGetClickedExchangeIdReq': ('clicked_exchange_ids',),
        }
        for name, repeated_fields in cases.items():
            with self.subTest(name=name):
                request = self.request(name, {})
                fields = response_fields(request, self.backend, self.token)
                self.assertEqual(fields['result'], 0)
                for field in repeated_fields:
                    self.assertIn(field, fields)
                encoded = self.codec.response(request, fields)
                self.assertTrue(encoded)
        recycle = response_fields(self.request('CSMallGetRecycleGoodsReq', {}),
                                  self.backend, self.token)
        self.assertTrue(recycle['is_finish'])
        self.assertEqual(recycle['version_info'],
                         response_fields(self.request('CSMallGetCfgVersionReq', {}),
                                         self.backend, self.token)['version_info'])

    def test_market_prebuy_lookup_returns_a_complete_empty_state(self):
        request = self.request('CSMarketGetAndUpdatePreBuyOrderReq',
                               {'prop_ids': [15080010001]})
        fields = response_fields(request, self.backend, self.token)
        self.assertEqual(fields, {'result': 0, 'orders': []})
        self.codec.response(request, fields)

    def test_deciphered_mandel_bricks_can_pass_client_market_type_gate(self):
        item_id = 16110000001
        self.assertIn(item_id, stock_catalog())
        type_fields = response_fields(
            self.request('CSMarketGetTypeListReq', {'prop_ids': [str(item_id)]}),
            self.backend, self.token)
        self.assertEqual([int(row['prop_id']) for row in type_fields['type_lists']],
                         [item_id])
        self.assertEqual(type_fields['type_lists'][0]['guide_price'], 20000)
        sale_fields = response_fields(
            self.request('CSMarketGetSaleListReq', {'info': {'prop_id': str(item_id)}}),
            self.backend, self.token)
        self.assertEqual(sale_fields['sale_list_info']['sale_lists'][0]['selling_num'],
                         9999)
        self.codec.response(self.request('CSMarketGetSaleListReq', {}), sale_fields)

    def test_original_client_mandel_lottery_purchase_updates_local_save(self):
        item_id = 16110000026
        self.backend.set_native_lobby_profile(
            self.token, level=60,
            currencies={CURRENCY_ID: 100000, MANDEL_BRICK_PURCHASE_CURRENCY: 500000,
                        MANDEL_KEY_CURRENCY: 100000}, props=[])
        request = self.request('CSShopBuyLotteryItemReq', {'buy_props': [
            {'item_id': str(item_id), 'num': '10',
             'currency_type': str(MANDEL_BRICK_PURCHASE_CURRENCY), 'price': '20000'},
            {'item_id': str(MANDEL_KEY_ID), 'num': '10',
             'currency_type': str(MANDEL_KEY_CURRENCY), 'price': '600'},
        ], 'is_open_directly': False})
        fields = response_fields(request, self.backend, self.token)
        self.codec.response(request, fields)
        self.assertEqual(fields['result'], 0)
        self.assertEqual(fields['change']['currency_changes'][0]['delta'], -200000)
        self.assertEqual(fields['change']['currency_changes'][1]['delta'], -600)
        self.assertEqual(fields['change']['prop_changes'][2]['prop'], {
            'id': MANDEL_KEY_ID, 'gid': 0, 'num': 10})
        state = self.backend.native_lobby_profile(self.token)
        self.assertEqual(next(row['amount'] for row in state['currencies']
                              if row['currency_id'] == MANDEL_BRICK_PURCHASE_CURRENCY),
                         300000)
        self.assertEqual(next(row['quantity'] for row in state['collection_props']
                              if row['template_id'] == MANDEL_KEY_ID), 10)
        self.assertEqual(state['props'], [])
        self.assertEqual(state['collection_props'],
                         [{'template_id': item_id, 'quantity': 10},
                          {'template_id': 32210000004, 'quantity': 10},
                          {'template_id': MANDEL_KEY_ID, 'quantity': 10}])

        collection_frame = _candidate_local_collection_response(
            b'ABCD' + self.codec.encode('CSCollectionLoadPropsReq', {}, sequence=18),
            self.backend, self.token, b'0123456789abcdef',
            header_word4=12, header_word9=18)
        loaded = self.codec.decode(decode_data_frame(
            collection_frame, b'0123456789abcdef', direction='server_to_client',
            compression_method=1).messages[0])
        self.assertEqual(int(loaded.fields['common_props'][0]['num']), 10)

        key = b'0123456789abcdef'
        response_frame = _candidate_local_commerce_response(
            b'ABCD' + self.codec.encode('CSShopBuyLotteryItemReq', {
                'buy_props': [{'item_id': item_id, 'num': 1,
                               'currency_type': MANDEL_BRICK_PURCHASE_CURRENCY,
                               'price': 20000},
                              {'item_id': MANDEL_KEY_ID, 'num': 1,
                               'currency_type': MANDEL_KEY_CURRENCY, 'price': 60}]},
                sequence=19),
            self.backend, self.token, key, header_word4=12, header_word9=19)
        notification = _candidate_local_inventory_change_notification(
            response_frame, key, header_word4=12, header_word9=20)
        pushed = self.codec.decode(decode_data_frame(
            notification, key, direction='server_to_client',
            compression_method=1).messages[0])
        self.assertEqual(pushed.name, 'CSDepositChangeNtf')
        self.assertFalse(pushed.fields['deposit_change'].get('prop_changes'))
        self.assertEqual(int(pushed.fields['deposit_change']['currency_changes'][0]['delta']),
                         -20000)
        collection_notification = _candidate_local_collection_change_notification(
            response_frame, key, header_word4=12, header_word9=21)
        collection_push = self.codec.decode(decode_data_frame(
            collection_notification, key, direction='server_to_client',
            compression_method=1).messages[0])
        self.assertEqual(collection_push.name, 'CSCollectionPropChangeNtf')
        self.assertEqual(int(collection_push.fields['data_change'][0]['prop']['id']),
                         item_id)
        self.assertEqual(self.backend.native_lobby_profile(self.token)['collection_props'],
                         [{'template_id': item_id, 'quantity': 11},
                          {'template_id': 32210000004, 'quantity': 11},
                          {'template_id': MANDEL_KEY_ID, 'quantity': 11}])

    def test_direct_mandel_draw_does_not_charge_without_reward_handler(self):
        item_id = 16110000026
        self.backend.set_native_lobby_profile(
            self.token, level=60,
            currencies={MANDEL_BRICK_PURCHASE_CURRENCY: 500000}, props=[])
        request = self.request('CSShopBuyLotteryItemReq', {
            'is_open_directly': True, 'buy_props': [
                {'item_id': item_id, 'num': 1,
                 'currency_type': MANDEL_BRICK_PURCHASE_CURRENCY, 'price': 20000},
                {'item_id': MANDEL_KEY_ID, 'num': 1,
                 'currency_type': MANDEL_KEY_CURRENCY, 'price': 0}]})
        fields = response_fields(request, self.backend, self.token)
        self.assertEqual(fields['result'], 1)
        self.assertEqual(self.backend.native_lobby_profile(self.token)['props'], [])

    def test_prior_mandel_warehouse_stacks_migrate_once_to_collection(self):
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.execute(
                'INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)',
                (6300000000000000001, player_id, 16110000026, 10, 2, 0, 0, 1, 2))
            connection.commit()
        for _ in range(2):
            Backend(Path(self.temporary.name) / 'save.sqlite3',
                    ROOT / 'definitions.json')
        state = self.backend.native_lobby_profile(self.token)
        self.assertEqual(state['props'], [])
        self.assertEqual(state['collection_props'],
                         [{'template_id': 16110000026, 'quantity': 10}])

    def test_shop_item_descriptions_preserve_client_localization(self):
        request = self.request('CSShopGetGameItemConfigReq', {})
        fields = response_fields(request, self.backend, self.token)
        self.codec.response(request, fields)
        self.assertEqual(fields['descs'], [])

    def test_purchase_deducts_once_and_adds_nonoverlapping_warehouse_prop(self):
        item_id = 15080010001
        price = stock_catalog()[item_id]['initial_guide_price']
        request = self.request('CSMarketBuyTReq', {
            'prop_id': str(item_id), 'price': str(price),
            'currency': str(CURRENCY_ID), 'buy_num': '1',
            'order_id': str(order_id(item_id))})
        fields = response_fields(request, self.backend, self.token)
        self.codec.response(request, fields)
        self.assertEqual(fields['result'], 0)
        state = self.backend.native_lobby_profile(self.token)
        self.assertEqual(state['currencies'][0]['amount'], 100000 - price)
        self.assertEqual(len(state['props']), 1)
        self.assertEqual(state['props'][0]['template_id'], item_id)
        self.assertEqual(fields['changes']['currency_changes'][0]['delta'], -price)
        self.assertEqual(int(fields['orders'][0]['prop']['id']), item_id)

    def test_sale_offer_exposes_wear_only_for_protective_gear(self):
        for item_id, expected_condition in ((11010001001, True),
                                            (11050004003, True),
                                            (10010000019, False),
                                            (14020000001, False)):
            request = self.request('CSAuctionGetSaleListReq',
                                   {'info': {'prop_id': str(item_id)}})
            fields = response_fields(request, self.backend, self.token)
            self.codec.response(request, fields)
            prop = fields['sale_list_infos'][0]['sale_lists'][0]['prop']
            self.assertEqual(('health' in prop, 'health_max' in prop),
                             (expected_condition, expected_condition))
            if expected_condition:
                self.assertEqual((prop['health'], prop['health_max']), (100, 100))

    def test_auction_ammo_offer_is_open_for_quick_operation(self):
        item_id = 37010100001
        request = self.request('CSAuctionGetSaleListBatchReq', {
            'infos': [{'prop_id': str(item_id)}]})
        fields = response_fields(request, self.backend, self.token)
        self.codec.response(request, fields)
        detail = fields['sale_lists'][0]
        now = int(time.time())
        self.assertLessEqual(detail['auction_vaild_time_begin'], now)
        self.assertGreater(detail['auction_vaild_time_end'], now)
        self.assertEqual(detail['sale_lists'][0]['selling_num'], 9999)

    def test_serial_purchase_summary_decodes_client_item_and_price(self):
        message = b'ABCD' + self.codec.encode('CSSerialCheapBuyReq', {
            'buy_list': [{'mall_prop': {'prop_info': {'id': 15080010001, 'num': 2},
                                        'exchange_id': 18300000004},
                          'mall_prices': [{'money_type': CURRENCY_ID, 'price': 1250}],
                          'channel': 1}], 'scene': 3}, sequence=17)
        self.assertEqual(_candidate_local_serial_buy_summary(message), {
            'scene': 3, 'buy_plan_type': 0, 'outfit_index': 0, 'rows': [{
                'channel': 1, 'item_id': 15080010001, 'num': 2,
                'exchange_id': 18300000004, 'auction_currency': 0,
                'auction_price': 0,
                'mall_prices': [{'money_type': CURRENCY_ID, 'price': 1250}],
                'target_position': 0, 'target_location': {},
                'auction_assemble_info': {}, 'single_auction_to_pos': 0,
                'single_auction_assemble_info': {},
            }]})

    def test_prebattle_gun_purchase_enters_requested_equipment_slot(self):
        item_id = 10010000019
        receiver_id = 18010000010
        price = stock_catalog()[item_id]['initial_guide_price']
        request = self.request('CSSerialCheapBuyReq', {'scene': 502,
            'buy_list': [{'channel': 2,
                          'single_auction_prop': {'prop_id': item_id,
                                                  'buy_num': 1,
                                                  'currency': CURRENCY_ID,
                                                  'price': price,
                                                  'to_pos': 111}}]})
        fields = response_fields(request, self.backend, self.token)
        self.codec.response(request, fields)
        self.assertEqual(fields['result'], 0)
        added = fields['auction_changes']['prop_changes'][0]
        self.assertEqual(added['dest']['pos'], 111)
        self.assertEqual(added['prop']['position'], 111)
        self.assertEqual(int(added['prop']['id']), receiver_id)
        self.assertIn('weapon', added['prop'])
        state = self.backend.native_lobby_profile(self.token)
        self.assertEqual(state['currencies'][0]['amount'], 100000 - price)
        self.assertEqual(state['props'][0]['grid_page_id'], 111)
        key = b'0123456789abcdef'
        get_props = b'ABCD' + self.codec.encode('CSDepositGetPropsReq', {}, sequence=19)
        frame = _candidate_local_deposit_response(get_props, self.backend, self.token,
                                                  key, header_word4=12, header_word9=19)
        reply = self.codec.decode(decode_data_frame(
            frame, key, direction='server_to_client', compression_method=1).messages[0])
        weapon_slot = next(row for row in reply.fields['equiped_props']
                           if int(row['position']) == 111)
        self.assertEqual(int(weapon_slot['load_props'][0]['id']), receiver_id)
        self.assertEqual(int(weapon_slot['src_prop_id']), receiver_id)
        self.assertEqual(reply.fields['grid_pages'][0].get('props', []), [])

    def test_equipment_move_confirms_and_persists_warehouse_gun(self):
        gun = 10010000019
        row = stock_catalog()[gun]
        bought = self.backend.native_lobby_purchase(
            self.token, template_id=gun, quantity=1,
            unit_price=row['initial_guide_price'], currency_id=CURRENCY_ID,
            length=row['length'], width=row['width'])['props'][0]
        command = {'prop_id': gun, 'prop_gid': bought['gid'],
                   'src_pos': 2, 'target_pos': 111, 'num': 1}
        key = b'0123456789abcdef'
        message = b'ABCD' + self.codec.encode('CSDepositEquipPropReq',
                                             {'cmds': [command]}, sequence=21)
        self.assertEqual(_candidate_local_equip_summary(message)[0]['target_pos'], 111)
        frame = _candidate_local_equip_response(message, self.backend, self.token,
                                                key, header_word4=12, header_word9=21)
        reply = self.codec.decode(decode_data_frame(
            frame, key, direction='server_to_client', compression_method=1).messages[0])
        self.assertEqual(reply.fields['result'], 0)
        change = reply.fields['deposit_change']['prop_changes'][0]
        self.assertEqual(change['change_type'], 5)
        self.assertEqual(change['src']['pos'], 2)
        self.assertEqual(change['dest']['pos'], 111)
        self.assertEqual(self.backend.native_lobby_profile(self.token)['props'][0]['grid_page_id'], 111)

        invalid = b'ABCD' + self.codec.encode('CSDepositEquipPropReq',
            {'cmds': [{**command, 'src_pos': 2, 'target_pos': 112}]}, sequence=22)
        rejected = _candidate_local_equip_response(invalid, self.backend, self.token,
                                                   key, header_word4=12, header_word9=22)
        error = self.codec.decode(decode_data_frame(
            rejected, key, direction='server_to_client', compression_method=1).messages[0])
        self.assertNotEqual(error.fields['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token)['props'][0]['grid_page_id'], 111)

    def test_warehouse_item_moves_into_backpack_space_and_back(self):
        backpack_id = 11080004006
        backpack = stock_catalog()[backpack_id]
        self.backend.native_lobby_purchase(
            self.token, template_id=backpack_id, quantity=1,
            unit_price=backpack['initial_guide_price'], currency_id=CURRENCY_ID,
            length=backpack['length'], width=backpack['width'], target_position=108)
        item_id = 14030000001
        row = stock_catalog()[item_id]
        stored = self.backend.native_lobby_purchase(
            self.token, template_id=item_id, quantity=1,
            unit_price=row['initial_guide_price'], currency_id=CURRENCY_ID,
            length=row['length'], width=row['width'])['props'][0]
        key = b'0123456789abcdef'
        message = b'ABCD' + self.codec.encode('CSDepositEquipPropReq', {'cmds': [{
            'prop_id': item_id, 'prop_gid': stored['gid'], 'src_pos': 2,
            'target_pos': 108001, 'num': 1,
            'spec_loc': {'pos': 108001, 'x': 1, 'y': 1, 'space_id': 5}}]}, sequence=23)
        frame = _candidate_local_equip_response(
            message, self.backend, self.token, key, header_word4=12, header_word9=23)
        reply = self.codec.decode(decode_data_frame(
            frame, key, direction='server_to_client', compression_method=1).messages[0])
        self.assertEqual(reply.fields['result'], 0)
        self.assertEqual(reply.fields['deposit_change']['prop_changes'][0]['dest']['space_id'], 5)
        self.assertEqual(next(p for p in self.backend.native_lobby_profile(self.token)['props']
                              if p['gid'] == stored['gid'])['grid_page_id'], 108001)
        moves = self.backend.native_lobby_move_props(self.token, [{
            'prop_id': item_id, 'prop_gid': stored['gid'], 'src_pos': 108001,
            'target_pos': 2, 'num': 1}])
        self.assertEqual(moves[0]['after']['grid_page_id'], 2)

    def test_reconnected_client_equipment_move_is_answered(self):
        gun = 10010000019
        row = stock_catalog()[gun]
        bought = self.backend.native_lobby_purchase(
            self.token, template_id=gun, quantity=1,
            unit_price=row['initial_guide_price'], currency_id=CURRENCY_ID,
            length=row['length'], width=row['width'])['props'][0]
        command = {'prop_id': gun, 'prop_gid': bought['gid'],
                   'src_pos': 2, 'target_pos': 111, 'num': 1}
        result, response = self._reconnected_request(
            'CSDepositEquipPropReq', {'cmds': [command]})
        entry = result['registration_continuation'][0]
        self.assertTrue(entry.get('response_sent'))
        self.assertTrue(entry['local_equip_response'])
        self.assertEqual(response.fields['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token)['props'][0]['grid_page_id'], 111)

    def test_reconnected_client_body_container_sync_is_answered(self):
        result, response = self._reconnected_request(
            'CSDepositAssemblySyncBodyContainerReq', {'snapshots': []})
        entry = result['registration_continuation'][0]
        self.assertTrue(entry.get('response_sent'))
        self.assertTrue(entry['local_body_container_response'])
        self.assertEqual(response.fields['result'], 0)

    def test_reconnected_client_loads_paid_ammo_and_returns_weapon_state(self):
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[
            {'gid': 2001, 'template_id': 18020000003, 'quantity': 1,
             'grid_page_id': 111, 'x': 0, 'y': 0, 'length': 4, 'width': 2},
            {'gid': 2002, 'template_id': 37190000001, 'quantity': 60,
             'grid_page_id': 199997, 'x': 1, 'y': 0, 'length': 1, 'width': 1},
        ])
        result, response = self._reconnected_request('CSDepositOperateBulletReq', {'cmds': [{
            'op_type': 1, 'bullet_id': 37190000001, 'bullet_gid': 2002,
            'bullet_op_num': 17, 'target_gun_rec_id': 18020000003, 'target_gun_rec_gid': 2001}]})
        entry = result['registration_continuation'][0]
        self.assertTrue(entry.get('response_sent'))
        self.assertEqual(response.fields['result'], 0)
        gun_change = next(change for change in response.fields['changes']['prop_changes']
                          if int(change['prop']['id']) == 18020000003)
        self.assertEqual(int(gun_change['prop']['weapon']['magazine_capacity']), 17)
        self.assertEqual(sum(int(bullet['num']) for bullet in gun_change['prop']['weapon']['load_bullets']), 17)

    def test_reconnected_ammo_purchase_notifies_and_survives_container_sync_and_fetch(self):
        # Captured scene 503 buys 120 loose rounds for Pocket and 17 for Vector.
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={CURRENCY_ID: 100000}, props=[{
                'gid': 2001, 'template_id': 18020000003, 'quantity': 1,
                'grid_page_id': 111, 'x': 0, 'y': 0, 'length': 4, 'width': 2}])
        result, bought = self._reconnected_request('CSSerialCheapBuyReq', {
            'scene': 503, 'buy_list': [{'channel': 2, 'single_auction_prop': {
                'prop_id': 37190000001, 'buy_num': count, 'currency': CURRENCY_ID,
                'price': 215, 'to_pos': position}}
                for count, position in ((120, 199997), (17, 2))]})
        self.assertEqual(bought.fields['result'], 0)
        self.assertTrue(result['registration_continuation'][0].get(
            'local_inventory_change_notification_sent'))
        warehouse_ammo = next(prop for prop in self.backend.native_lobby_profile(self.token)['props']
                              if prop['template_id'] == 37190000001 and prop['grid_page_id'] == 2)
        result, loaded = self._reconnected_request('CSDepositOperateBulletReq', {'cmds': [{
            'op_type': 1, 'bullet_id': 37190000001, 'bullet_gid': warehouse_ammo['gid'],
            'bullet_op_num': 17, 'target_gun_rec_id': 18020000003, 'target_gun_rec_gid': 2001}]})
        self.assertEqual(loaded.fields['result'], 0)
        self.assertTrue(result['registration_continuation'][0].get(
            'local_inventory_change_notification_sent'))
        key = b'0123456789abcdef'
        request = b'ABCD' + self.codec.encode('CSDepositGetPropsReq', {}, sequence=31)

        def fetch():
            frame = _candidate_local_deposit_response(
                request, self.backend, self.token, key, header_word4=12, header_word9=31)
            return self.codec.decode(decode_data_frame(
                frame, key, direction='server_to_client', compression_method=1).messages[0]).fields

        first = fetch()
        pocket = next(row for row in first['equiped_props'] if int(row['position']) == 199997)
        self.assertEqual(sum(int(prop['num']) for prop in pocket['load_props']), 120)
        snapshots = [{'pos': 199997, 'space': int(space['id']),
                      'props': [prop for prop in pocket['load_props']
                                if int(prop['loc']['space_id']) == int(space['id'])]}
                     for space in pocket['grid_space']]
        _, synced = self._reconnected_request('CSDepositAssemblySyncBodyContainerReq',
                                               {'snapshots': snapshots})
        self.assertEqual(synced.fields['result'], 0)
        self.backend = Backend(Path(self.temporary.name) / 'save.sqlite3', ROOT / 'definitions.json')
        reopened = fetch()
        self.assertEqual(reopened['equiped_props'], first['equiped_props'])
        gun = next(row for row in reopened['equiped_props'] if int(row['position']) == 111)
        self.assertEqual(sum(int(prop['num']) for prop in gun['load_props'][0]['weapon']['load_bullets']), 17)
        self.assertEqual(reopened['grid_pages'][0].get('props', []), [])

    def test_owned_ammo_can_move_to_pocket_and_survives_fetch(self):
        item_id = 37190000001
        row = stock_catalog()[item_id]
        stored = self.backend.native_lobby_purchase(self.token, template_id=item_id,
            quantity=60, unit_price=row['initial_guide_price'], currency_id=CURRENCY_ID,
            length=row['length'], width=row['width'],
            max_stack_count=row['max_stack_count'])['props'][0]
        key = b'0123456789abcdef'
        message = b'ABCD' + self.codec.encode('CSDepositEquipPropReq', {'cmds': [{
            'prop_id': item_id, 'prop_gid': stored['gid'], 'src_pos': 2,
            'target_pos': 199997, 'num': 60,
            'spec_loc': {'pos': 199997, 'space_id': 3, 'start_x': 0, 'start_y': 0}}]}, sequence=32)
        frame = _candidate_local_equip_response(
            message, self.backend, self.token, key, header_word4=12, header_word9=32)
        reply = self.codec.decode(decode_data_frame(
            frame, key, direction='server_to_client', compression_method=1).messages[0])
        self.assertEqual(reply.fields['result'], 0)
        change = reply.fields['deposit_change']['prop_changes'][0]
        self.assertEqual(int(change['dest']['pos']), 199997)
        self.assertEqual(int(change['dest']['space_id']), 3)
        saved = self.backend.native_lobby_profile(self.token)['props'][0]
        self.assertEqual((saved['grid_page_id'], saved['x'], saved['quantity']), (199997, 3, 60))
        fetch = b'ABCD' + self.codec.encode('CSDepositGetPropsReq', {}, sequence=33)
        frame = _candidate_local_deposit_response(
            fetch, self.backend, self.token, key, header_word4=12, header_word9=33)
        reply = self.codec.decode(decode_data_frame(
            frame, key, direction='server_to_client', compression_method=1).messages[0])
        pocket = next(row for row in reply.fields['equiped_props'] if int(row['position']) == 199997)
        self.assertEqual(len(pocket['load_props']), 1)
        self.assertEqual(int(pocket['load_props'][0]['loc']['space_id']), 3)
        self.assertEqual(int(pocket['load_props'][0]['num']), 60)

    def test_reconnected_client_guide_progress_is_acknowledged(self):
        result, response = self._reconnected_request(
            'CSGuideSetDataReq', {'data': [{'key': 53020, 'data': 'AQID'}]})
        entry = result['registration_continuation'][0]
        self.assertTrue(entry.get('response_sent'))
        self.assertEqual(response.name, 'CSGuideSetDataRes')
        self.assertEqual(response.fields['result'], 0)

    def _reconnected_request(self, name, fields):
        key = b'0123456789abcdef'
        message = b'ABCD' + self.codec.encode(name, fields, sequence=23)
        frame = encode_data_frame((message,), key, direction='client_to_server',
                                  header_word4=13, header_word9=23)

        class ClosedConnection:
            def __init__(self):
                self.sent = []

            def sendall(self, payload):
                self.sent.append(payload)

            def recv(self, _size):
                return b''

        connection = ClosedConnection()
        result = {}
        _continue_character_creation(
            connection, None, deque(), frame, SimpleNamespace(session_key=key),
            {}, self.backend, self.token, 23, result, continuation_seconds=1)
        if not connection.sent:
            return result, None
        from dfserver.gcp_framing import StreamDecoder
        response_frame = StreamDecoder().feed(connection.sent[0])[0]
        decoded = decode_data_frame(response_frame, key, direction='server_to_client',
                                    compression_method=1)
        return result, self.codec.decode(decoded.messages[0])

    def test_equipment_swap_returns_old_item_to_warehouse(self):
        first, second = 10010000019, 10010000014
        p1 = stock_catalog()[first]
        p2 = stock_catalog()[second]
        equipped = self.backend.native_lobby_purchase(
            self.token, template_id=first, quantity=1,
            unit_price=p1['initial_guide_price'], currency_id=CURRENCY_ID,
            length=p1['length'], width=p1['width'], target_position=111)['props'][0]
        stored = self.backend.native_lobby_purchase(
            self.token, template_id=second, quantity=1,
            unit_price=p2['initial_guide_price'], currency_id=CURRENCY_ID,
            length=p2['length'], width=p2['width'])['props'][0]
        changes = self.backend.native_lobby_move_props(self.token, [{
            'prop_id': second, 'prop_gid': stored['gid'], 'src_pos': 2,
            'target_pos': 111, 'target_prop_gid': equipped['gid'], 'num': 1}])
        self.assertEqual(len(changes), 2)
        positions = {p['template_id']: p['grid_page_id'] for p in
                     self.backend.native_lobby_profile(self.token)['props']}
        self.assertEqual(positions, {first: 2, second: 111})

    def test_second_prebattle_purchase_replaces_equipment_and_stores_old_item(self):
        first, second = 10010000019, 10010000014
        results = []
        for item_id in (first, second):
            price = stock_catalog()[item_id]['initial_guide_price']
            request = self.request('CSSerialCheapBuyReq', {'scene': 502,
                'buy_list': [{'channel': 2, 'single_auction_prop': {
                    'prop_id': item_id, 'buy_num': 1,
                    'currency': CURRENCY_ID, 'price': price,
                    'to_pos': 111}}]})
            results.append(response_fields(request, self.backend, self.token))
        self.assertEqual([result['result'] for result in results], [0, 0])
        changes = results[1]['auction_changes']['prop_changes']
        self.assertEqual([change['change_type'] for change in changes], [5, 1])
        self.assertEqual(changes[0]['src']['pos'], 111)
        self.assertEqual(changes[0]['dest']['pos'], 2)
        self.assertEqual(changes[1]['dest']['pos'], 111)
        positions = {p['template_id']: p['grid_page_id'] for p in
                     self.backend.native_lobby_profile(self.token)['props']}
        self.assertEqual(positions, {default_weapon_presets()[first]: 2,
                                     default_weapon_presets()[second]: 111})

    def test_prebattle_medicine_batch_fills_chest_rig_and_survives_fetch(self):
        rig_id = 11070004001
        rig = stock_catalog()[rig_id]
        self.backend.native_lobby_purchase(
            self.token, template_id=rig_id, quantity=1,
            unit_price=rig['initial_guide_price'], currency_id=CURRENCY_ID,
            length=rig['length'], width=rig['width'], target_position=107)
        rows = [(14020000005, 1), (14020000001, 1),
                (14040000002, 1), (14020000003, 3)]
        request = self.request('CSSerialCheapBuyReq', {'scene': 504,
            'buy_list': [{'channel': 2, 'single_auction_prop': {
                'prop_id': item_id, 'buy_num': count, 'currency': CURRENCY_ID,
                'price': stock_catalog()[item_id]['initial_guide_price'],
                'to_pos': 107001}} for item_id, count in rows]})
        fields = response_fields(request, self.backend, self.token)
        self.codec.response(request, fields)
        self.assertEqual(fields['result'], 0)
        changes = fields['auction_changes']['prop_changes']
        self.assertEqual(len(changes), 6)
        self.assertTrue(all(change['dest']['pos'] == 107001 and
                            1 <= change['dest']['space_id'] <= 7
                            for change in changes))
        state = self.backend.native_lobby_profile(self.token)
        stored = [prop for prop in state['props'] if prop['grid_page_id'] == 107001]
        self.assertEqual(len(stored), 6)
        total = sum(stock_catalog()[item_id]['initial_guide_price'] * count
                    for item_id, count in rows)
        self.assertEqual(fields['auction_changes']['currency_changes'][0]['delta'], -total)
        key = b'0123456789abcdef'
        message = b'ABCD' + self.codec.encode('CSDepositGetPropsReq', {}, sequence=26)
        frame = _candidate_local_deposit_response(
            message, self.backend, self.token, key, header_word4=13, header_word9=26)
        reply = self.codec.decode(decode_data_frame(
            frame, key, direction='server_to_client', compression_method=1).messages[0])
        rig_space = next(row for row in reply.fields['equiped_props']
                         if int(row['position']) == 107001)
        self.assertEqual(len(rig_space['load_props']), 6)

    def test_quick_operation_pocket_target_buys_medicine_atomically(self):
        item_id = 14020000003
        price = stock_catalog()[item_id]['initial_guide_price']
        request = self.request('CSSerialCheapBuyReq', {'scene': 504,
            'buy_list': [{'channel': 2, 'single_auction_prop': {
                'prop_id': item_id, 'buy_num': 4, 'currency': CURRENCY_ID,
                'price': price, 'to_pos': 199997}}]})
        fields = response_fields(request, self.backend, self.token)
        self.assertEqual(fields['result'], 0)
        self.codec.response(request, fields)
        props = self.backend.native_lobby_profile(self.token)['props']
        self.assertEqual(len(props), 4)
        self.assertEqual({prop['grid_page_id'] for prop in props}, {199997})
        self.assertEqual({prop['x'] for prop in props}, {1, 2, 3, 4})
        self.assertEqual({int(change['dest']['pos'])
                          for change in fields['auction_changes']['prop_changes']}, {199997})
        key = b'0123456789abcdef'
        frame = _candidate_local_deposit_response(
            b'ABCD' + self.codec.encode('CSDepositGetPropsReq', {}, sequence=26),
            self.backend, self.token, key, header_word4=13, header_word9=26)
        reply = self.codec.decode(decode_data_frame(
            frame, key, direction='server_to_client', compression_method=1).messages[0])
        temporary = next(row for row in reply.fields['equiped_props']
                         if int(row['position']) == 199997)
        self.assertEqual(len(temporary['load_props']), 4)
        self.assertEqual(len(temporary['grid_space']), 5)
        self.assertEqual(fields['auction_changes']['currency_changes'][0]['delta'],
                         -4 * price)

    def test_purchased_pocket_item_can_move_to_warehouse(self):
        item_id = 14020000003
        request = self.request('CSSerialCheapBuyReq', {'scene': 504,
            'buy_list': [{'channel': 2, 'single_auction_prop': {
                'prop_id': item_id, 'buy_num': 1, 'currency': CURRENCY_ID,
                'price': stock_catalog()[item_id]['initial_guide_price'],
                'to_pos': 199997}}]})
        self.assertEqual(response_fields(request, self.backend, self.token)['result'], 0)
        prop = self.backend.native_lobby_profile(self.token)['props'][0]
        changes = self.backend.native_lobby_move_props(self.token, [{
            'prop_id': item_id, 'prop_gid': prop['gid'], 'src_pos': 199997,
            'target_pos': 2, 'num': 1}])
        self.assertEqual(changes[0]['before']['grid_page_id'], 199997)
        self.assertEqual(changes[0]['after']['grid_page_id'], 2)
        self.assertEqual(changes[0]['after']['gid'], prop['gid'])

    def test_quick_operation_two_row_ammo_buy_is_one_transaction(self):
        item_id = 37170400001
        price = stock_catalog()[item_id]['initial_guide_price']
        self.backend.set_native_lobby_profile(
            self.token, level=60, currencies={CURRENCY_ID: 1_000_000}, props=[])
        request = self.request('CSSerialCheapBuyReq', {'scene': 503,
            'buy_list': [{'channel': 2, 'single_auction_prop': {
                'prop_id': item_id, 'buy_num': count, 'currency': CURRENCY_ID,
                'price': price, 'to_pos': position}}
                for count, position in ((210, 199997), (10, 2))]})
        fields = response_fields(request, self.backend, self.token)
        self.assertEqual(fields['result'], 0)
        self.codec.response(request, fields)
        props = self.backend.native_lobby_profile(self.token)['props']
        self.assertEqual(sum(prop['quantity'] for prop in props), 220)
        self.assertEqual({prop['grid_page_id'] for prop in props}, {2, 199997})
        self.assertEqual(fields['auction_changes']['currency_changes'][0]['delta'],
                         -220 * price)

    def test_quick_operation_mixed_ammo_targets_purchase_together(self):
        self.backend.set_native_lobby_profile(
            self.token, level=60, currencies={CURRENCY_ID: 1_000_000}, props=[
                {'gid': 8001, 'template_id': 11070004001, 'quantity': 1,
                 'grid_page_id': 107, 'x': 0, 'y': 0, 'length': 2, 'width': 2}])
        rows = ((37190000001, 90, 199997), (37190000001, 24, 2),
                (37190500001, 180, 107001), (37190500001, 60, 199997),
                (37190300001, 120, 199997), (37190300001, 90, 107001))
        request = self.request('CSSerialCheapBuyReq', {'scene': 503,
            'buy_list': [{'channel': 2, 'single_auction_prop': {
                'prop_id': item_id, 'buy_num': count, 'currency': CURRENCY_ID,
                'price': stock_catalog()[item_id]['initial_guide_price'],
                'to_pos': position}}
                for item_id, count, position in rows]})
        fields = response_fields(request, self.backend, self.token)
        self.assertEqual(fields['result'], 0)
        self.codec.response(request, fields)
        props = self.backend.native_lobby_profile(self.token)['props']
        purchased = [prop for prop in props if prop['template_id'] in {row[0] for row in rows}]
        self.assertEqual(sum(prop['quantity'] for prop in purchased), sum(row[1] for row in rows))
        self.assertEqual({prop['grid_page_id'] for prop in purchased}, {2, 107001, 199997})
        self.assertEqual(len([prop for prop in purchased if prop['grid_page_id'] == 199997]), 5)
        self.assertEqual(fields['auction_changes']['currency_changes'][0]['delta'],
                         -sum(stock_catalog()[item_id]['initial_guide_price'] * count
                              for item_id, count, _ in rows))

    def test_quick_operation_unknown_backpack_does_not_change_account(self):
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={CURRENCY_ID: 1_000_000}, props=[
                {'gid': 8001, 'template_id': 11080009001, 'quantity': 1,
                 'grid_page_id': 108, 'x': 0, 'y': 0, 'length': 3, 'width': 3}])
        item_id = 14020000006
        price = stock_catalog()[item_id]['initial_guide_price']
        request = self.request('CSSerialCheapBuyReq', {'scene': 504,
            'buy_list': [{'channel': 2, 'single_auction_prop': {
                'prop_id': item_id, 'buy_num': 1, 'currency': CURRENCY_ID,
                'price': price, 'to_pos': 108001}}]})
        fields = response_fields(request, self.backend, self.token)
        self.assertEqual(fields['result'], 14008)
        self.codec.response(request, fields)
        purchased = [prop for prop in self.backend.native_lobby_profile(self.token)['props']
                     if prop['template_id'] == item_id]
        self.assertEqual(purchased, [])
        self.assertEqual(self.backend.native_lobby_profile(self.token)['currencies'][0]['amount'],
                         1_000_000)

    def test_current_backpack_purchase_uses_extracted_five_column_layout(self):
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={CURRENCY_ID: 1_000_000}, props=[
                {'gid': 8001, 'template_id': 11080006004, 'quantity': 1,
                 'grid_page_id': 108, 'x': 0, 'y': 0, 'length': 3, 'width': 3}])
        item_id = 14020000003
        request = self.request('CSSerialCheapBuyReq', {'scene': 504,
            'buy_list': [{'channel': 2, 'single_auction_prop': {
                'prop_id': item_id, 'buy_num': 7, 'currency': CURRENCY_ID,
                'price': stock_catalog()[item_id]['initial_guide_price'],
                'to_pos': 108001}}]})
        fields = response_fields(request, self.backend, self.token)
        self.assertEqual(fields['result'], 0)
        locations = [change['dest'] for change in fields['auction_changes']['prop_changes']]
        self.assertEqual([(loc['start_x'], loc['start_y']) for loc in locations],
                         [(0, 0), (1, 0), (2, 0), (3, 0), (4, 0), (0, 1), (1, 1)])
        self.assertTrue(all(loc['space_id'] == 1 and loc['pos'] == 108001 for loc in locations))

    def test_mixed_prebattle_batch_places_backpack_and_rig_items(self):
        for item_id, position in ((11070004001, 107), (11080004006, 108)):
            row = stock_catalog()[item_id]
            self.backend.native_lobby_purchase(
                self.token, template_id=item_id, quantity=1,
                unit_price=row['initial_guide_price'], currency_id=CURRENCY_ID,
                length=row['length'], width=row['width'], target_position=position)
        rows = ((14030000001, 108001), (14020000005, 107001))
        request = self.request('CSSerialCheapBuyReq', {'scene': 504,
            'buy_list': [{'channel': 2, 'single_auction_prop': {
                'prop_id': item_id, 'buy_num': 1, 'currency': CURRENCY_ID,
                'price': stock_catalog()[item_id]['initial_guide_price'],
                'to_pos': position}} for item_id, position in rows]})
        fields = response_fields(request, self.backend, self.token)
        self.codec.response(request, fields)
        self.assertEqual(fields['result'], 0)
        self.assertEqual({change['dest']['pos'] for change in
                          fields['auction_changes']['prop_changes']}, {107001, 108001})
        key = b'0123456789abcdef'
        message = b'ABCD' + self.codec.encode('CSDepositGetPropsReq', {}, sequence=29)
        frame = _candidate_local_deposit_response(
            message, self.backend, self.token, key, header_word4=13, header_word9=29)
        reply = self.codec.decode(decode_data_frame(
            frame, key, direction='server_to_client', compression_method=1).messages[0])
        backpack = next(row for row in reply.fields['equiped_props']
                        if int(row['position']) == 108001)
        self.assertEqual(backpack['capacity'], 28)
        self.assertEqual(len(backpack['grid_space']), 6)
        self.assertEqual([int(prop['id']) for prop in backpack['load_props']], [14030000001])

    def test_invalid_sale_reports_inventory_error_without_changing_account(self):
        before = self.backend.native_lobby_profile(self.token)
        empty = response_fields(self.request('CSMallSellReq', {
            'sell_props': [], 'prices': []}), self.backend, self.token)
        self.assertEqual(empty['result'], 14026)
        absent = response_fields(self.request('CSMallSellReq', {
            'sell_props': [{'id': 0, 'gid': 1, 'num': 1}],
            'prices': [{'money_type': CURRENCY_ID, 'price': 1}]}),
            self.backend, self.token)
        self.assertEqual(absent['result'], 14008)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_native_sale_can_remove_equipped_gun_with_its_parts_once(self):
        item_id = 18020000001
        row = stock_catalog()[item_id]
        stored = self.backend.native_lobby_purchase(
            self.token, template_id=item_id, quantity=1,
            unit_price=row['initial_guide_price'],
            currency_id=CURRENCY_ID, length=row['length'], width=row['width'],
            target_position=112)['props'][0]
        self.backend.native_lobby_profile(self.token)
        request = self.request('CSMallSellReq', {
            'sell_props': [{'id': item_id, 'gid': stored['gid'], 'num': 1}],
            'prices': [{'money_type': CURRENCY_ID, 'price': 18439}]})
        fields = response_fields(request, self.backend, self.token)
        self.assertEqual(fields['result'], 0)
        self.codec.response(request, fields)
        change = fields['prop_changes']['prop_changes'][0]
        self.assertEqual(change['change_type'], 2)
        self.assertEqual(change['src']['pos'], 112)
        self.assertFalse(self.backend.native_lobby_profile(self.token)['props'])
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute(
                'SELECT COUNT(*) FROM native_lobby_weapon_parts WHERE weapon_gid=?',
                (stored['gid'],)).fetchone()[0], 0)
        self.assertEqual(response_fields(request, self.backend, self.token)['result'], 14012)
        self.assertEqual(self.backend.native_lobby_profile(self.token)['currencies'][0]['amount'],
                         100000 - row['initial_guide_price'] + 18439)

    def test_mall_sell_commits_item_removal_and_currency_once(self):
        item_id = 14030000001
        row = stock_catalog()[item_id]
        self.backend.native_lobby_purchase(
            self.token, template_id=item_id, quantity=1,
            unit_price=row['initial_guide_price'], currency_id=CURRENCY_ID,
            length=row['length'], width=row['width'])
        before = self.backend.native_lobby_profile(self.token)
        prop = before['props'][0]
        request = self.request('CSMallSellReq', {
            'sell_props': [{'id': item_id, 'gid': prop['gid'], 'num': 1}],
            'prices': [{'money_type': CURRENCY_ID, 'price': 1000}]})
        fields = response_fields(request, self.backend, self.token)
        self.codec.response(request, fields)
        self.assertEqual(fields['result'], 0)
        self.assertEqual(fields['get_moneys'][0]['price'], 1000)
        self.assertEqual(fields['prop_changes']['prop_changes'][0]['change_type'], 2)
        after = self.backend.native_lobby_profile(self.token)
        self.assertFalse(after['props'])
        self.assertEqual(after['currencies'][0]['amount'], before['currencies'][0]['amount'] + 1000)
        self.assertEqual(response_fields(request, self.backend, self.token)['result'], 14012)
        self.assertEqual(self.backend.native_lobby_profile(self.token), after)

    def test_mall_sell_wire_response_pushes_inventory_change(self):
        item_id = 14030000001
        row = stock_catalog()[item_id]
        stored = self.backend.native_lobby_purchase(
            self.token, template_id=item_id, quantity=1,
            unit_price=row['initial_guide_price'], currency_id=CURRENCY_ID,
            length=row['length'], width=row['width'])['props'][0]
        key = b'0123456789abcdef'
        request = b'ABCD' + self.codec.encode('CSMallSellReq', {
            'sell_props': [{'id': item_id, 'gid': stored['gid'], 'num': 1}],
            'prices': [{'money_type': CURRENCY_ID, 'price': 1000}]}, sequence=30)
        frame = _candidate_local_commerce_response(
            request, self.backend, self.token, key, header_word4=12, header_word9=30)
        response = self.codec.decode(decode_data_frame(
            frame, key, direction='server_to_client', compression_method=1).messages[0])
        self.assertEqual(response.name, 'CSMallSellRes')
        self.assertEqual(response.fields['result'], 0)
        notification = _candidate_local_inventory_change_notification(
            frame, key, header_word4=12, header_word9=31)
        pushed = self.codec.decode(decode_data_frame(
            notification, key, direction='server_to_client',
            compression_method=1).messages[0])
        self.assertEqual(pushed.name, 'CSDepositChangeNtf')
        self.assertEqual(pushed.fields['deposit_change']['prop_changes'][0]['change_type'], 2)

    def test_equipped_weapon_has_the_containers_read_by_client_ammo_logic(self):
        weapon_id = 10010000019
        row = stock_catalog()[weapon_id]
        self.backend.native_lobby_purchase(
            self.token, template_id=weapon_id, quantity=1,
            unit_price=row['initial_guide_price'], currency_id=CURRENCY_ID,
            length=row['length'], width=row['width'], target_position=111)
        key = b'0123456789abcdef'
        message = b'ABCD' + self.codec.encode('CSDepositGetPropsReq', {}, sequence=27)
        frame = _candidate_local_deposit_response(
            message, self.backend, self.token, key, header_word4=13, header_word9=27)
        reply = self.codec.decode(decode_data_frame(
            frame, key, direction='server_to_client', compression_method=1).messages[0])
        slot = next(row for row in reply.fields['equiped_props']
                    if int(row['position']) == 111)
        prop = slot['load_props'][0]
        self.assertIn('weapon', prop)
        self.assertEqual(item_condition_fields(weapon_id)['weapon']['load_bullets'], [])
        components = prop['components']
        self.assertEqual({int(part['prop_data']['id']) for part in components},
                         {13050000223, 13020000375, 13040000145,
                          13120000242, 13030000177, 13400000001})
        gids = [int(part['prop_data']['gid']) for part in components]
        self.assertEqual(len(gids), len(set(gids)))
        self.assertTrue(all(gid > 0 and gid != int(prop['gid']) for gid in gids))
        reopened = Backend(self.backend.database, ROOT / 'definitions.json')
        saved = reopened.native_lobby_profile(self.token)['props'][0]['components']
        self.assertEqual([part['prop_data']['gid'] for part in saved], gids)

    def test_chest_rig_batch_rejects_overflow_without_charge_or_partial_items(self):
        rig_id = 11070004001
        rig = stock_catalog()[rig_id]
        self.backend.native_lobby_purchase(
            self.token, template_id=rig_id, quantity=1,
            unit_price=rig['initial_guide_price'], currency_id=CURRENCY_ID,
            length=rig['length'], width=rig['width'], target_position=107)
        with self.backend.connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            connection.execute('UPDATE native_lobby_currencies SET amount=100000 '
                               'WHERE currency_id=?', (CURRENCY_ID,))
            connection.commit()
        before = self.backend.native_lobby_profile(self.token)
        item_id = 14020000001
        row = stock_catalog()[item_id]
        with self.assertRaises(DomainError) as error:
            self.backend.native_lobby_purchase_rig_batch(self.token, items=[{
                'template_id': item_id, 'quantity': 15,
                'unit_price': row['initial_guide_price'],
                'length': row['length'], 'width': row['width'],
                'max_stack_count': row['max_stack_count']}], currency_id=CURRENCY_ID)
        self.assertEqual(error.exception.code, 'CHEST_RIG_FULL')
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_serial_purchase_commits_charge_and_item_only_for_valid_offer(self):
        item_id = 15080010001
        price = stock_catalog()[item_id]['initial_guide_price']
        buy_list = [{'mall_prop': {'prop_info': {'id': item_id, 'num': 2}},
                     'mall_prices': [{'money_type': CURRENCY_ID, 'price': price}],
                     'channel': 1}]
        invalid = self.request('CSSerialCheapBuyReq', {'buy_list': [{
            **buy_list[0], 'mall_prices': [{'money_type': CURRENCY_ID,
                                         'price': price - 1}]}]})
        self.assertEqual(response_fields(invalid, self.backend, self.token)['result'], 14026)
        self.assertEqual(self.backend.native_lobby_profile(self.token)['props'], [])
        request = self.request('CSSerialCheapBuyReq', {'buy_list': buy_list})
        fields = response_fields(request, self.backend, self.token)
        self.codec.response(request, fields)
        self.assertEqual(fields['result'], 0)
        self.assertEqual(fields['mall_changes']['currency_changes'][0]['delta'], -2 * price)
        state = self.backend.native_lobby_profile(self.token)
        self.assertEqual(state['currencies'][0]['amount'], 100000 - 2 * price)
        self.assertEqual(sum(row['quantity'] for row in state['props']), 2)
        key = b'0123456789abcdef'
        frame = _candidate_local_commerce_response(
            b'ABCD' + self.codec.encode('CSSerialCheapBuyReq', {
                'buy_list': [{'mall_prop': {'prop_info': {'id': item_id, 'num': 1}},
                              'mall_prices': [{'money_type': CURRENCY_ID,
                                               'price': price}], 'channel': 1}]},
                sequence=17), self.backend, self.token, key,
            header_word4=12, header_word9=17)
        notification = _candidate_local_inventory_change_notification(
            frame, key, header_word4=12, header_word9=18)
        pushed = self.codec.decode(decode_data_frame(
            notification, key, direction='server_to_client',
            compression_method=1).messages[0])
        self.assertEqual(pushed.name, 'CSDepositChangeNtf')

    def test_insufficient_funds_and_full_warehouse_roll_back(self):
        item_id = 15080050142
        row = stock_catalog()[item_id]
        with self.assertRaises(DomainError) as error:
            self.backend.native_lobby_purchase(
                self.token, template_id=item_id, quantity=1,
                unit_price=row['initial_guide_price'], currency_id=CURRENCY_ID,
                length=1, width=1)
        self.assertEqual(error.exception.code, 'INSUFFICIENT_FUNDS')
        self.assertEqual(self.backend.native_lobby_profile(self.token)['props'], [])
        item_id = 15080010001
        price = stock_catalog()[item_id]['initial_guide_price']
        self.backend.set_native_lobby_profile(
            self.token, level=60, currencies={CURRENCY_ID: 2000000}, props=[])
        with self.assertRaises(DomainError) as error:
            self.backend.native_lobby_purchase(
                self.token, template_id=item_id, quantity=361,
                unit_price=price, currency_id=CURRENCY_ID,
                length=1, width=1, max_stack_count=1)
        self.assertEqual(error.exception.code, 'WAREHOUSE_FULL')
        self.assertEqual(self.backend.native_lobby_profile(self.token)['props'], [])


if __name__ == '__main__':
    unittest.main()
