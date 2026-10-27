import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from dfserver.core import Backend
from dfserver.handshake_diagnostic import _candidate_codec
from dfserver.handshake_diagnostic import (
    _candidate_local_collection_response_frames, _candidate_local_inventory_change_notification)
from dfserver.gcp_data import decode_data_frame, encode_data_frame
from dfserver.candidate_business import CandidateMessage
from dfserver.local_commerce import response_fields


ROOT = Path(__file__).resolve().parent.parent


class PremiumShopTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.backend = Backend(Path(self.directory.name) / 'save.sqlite3', ROOT / 'definitions.json')
        self.token = self.backend.register('premium', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=60, props=[],
            currencies={17888808888: 100000, 17888808889: 100000})
        self.codec = _candidate_codec()

    def request(self, name, fields=None):
        request = self.codec.decode(self.codec.encode(name, fields or {}, sequence=19))
        result = response_fields(request, self.backend, self.token)
        self.assertIsNotNone(result, name)
        self.codec.response(request, result)
        return result

    def collection(self):
        return {r['template_id']: r['quantity']
                for r in self.backend.native_lobby_profile(self.token)['collection_props']}

    def test_four_native_sections_have_original_client_records(self):
        result = self.request('CSShopNewGetConfigReq')
        self.assertIn(10104007, {r['tab_id'] for r in result.get('hot_recommendation_descs', [])})
        self.assertIn(20300008, {r['lottery_id'] for r in result['lottery_item_descs']})
        self.assertIn(20100011, {r['lottery_id'] for r in result['lottery_item_descs']})
        self.assertIn(30200024, {r['goods_id'] for r in result.get('mall_gift_descs', [])})
        self.assertEqual(self.request('CSShopGetThemeBundleTimeConfigReq')['bundle_list'], [])
        self.assertEqual(self.request('CSShopGetBuyRecordReq')['mall_gift_records'], [])

    def test_mandel_descriptions_pass_the_native_tab_time_filter(self):
        now = int(time.time())
        rows = self.request('CSShopNewGetConfigReq')['lottery_item_descs']
        mandel = [r for r in rows if r.get('mandel_item_id')]
        self.assertEqual(len(mandel), 11)
        for row in mandel:
            with self.subTest(lottery_id=row['lottery_id']):
                self.assertLess(row.get('begin_time', 0), now)
                self.assertGreater(row.get('end_time', 0), now)

    def test_original_promotional_tiles_keep_their_lottery_jump_targets(self):
        result = self.request('CSShopNewGetConfigReq')
        banners = {r['tab_id']: r for r in result['hot_recommendation_descs']}
        for tab_id, target in ((10210005, '20300008'), (10200011, '20100011')):
            self.assertIn(tab_id, banners)
            self.assertEqual(banners[tab_id]['banner_type'], 2)
            self.assertEqual(banners[tab_id]['jump_to'], target)
            self.assertEqual(banners[tab_id]['bundle_item_list'], [])
            before = self.backend.native_lobby_profile(self.token)
            self.assertNotEqual(self.request('CSShopBuyHotRecommendationReq',
                {'tab_id': tab_id, 'banner_type': 2})['result'], 0)
            self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_recommendations_preserve_native_cdn_fallbacks_and_omit_empty_banners(self):
        banners = {r['tab_id']: r for r in self.request('CSShopNewGetConfigReq')['hot_recommendation_descs']}
        self.assertNotIn(10102077, banners)
        featured = banners[10101057]
        self.assertEqual(featured['IamgeSourceSmall_CDN'],
            'Resource/Store/C=69DB3063DD2DBB10E969574E5C10A48FBD6F6505042181F048324565478A248DC8788BE674874CB14D6ECBED39E12C53.jpg')
        self.assertTrue(featured['IamgeSourceBig_CDN'].startswith('Resource/Store/C='))
        self.assertTrue(featured['ImageSourceLogo_CDN_CN'].endswith('.png'))

    def test_bundle_purchase_grants_its_actual_contents_and_persists_record(self):
        catalog = json.loads((ROOT / 'protocol/premium_shop_catalog.json').read_text())
        offer = next(r for r in catalog['recommendations'] if r['tab_id'] == 10104007)
        fields = {'tab_id': offer['tab_id'], 'banner_type': offer['banner_type'],
                  'item_ids': [r['id'] for r in offer['bundle_item_list']],
                  'currency_type': offer['bundle_currency_type'], 'price': offer['bundle_price']}
        result = self.request('CSShopBuyHotRecommendationReq', fields)
        self.assertEqual(result['result'], 0)
        self.assertEqual(result['change']['currency_changes'][0]['delta'], -2690)
        granted = {r['prop']['id'] for r in result['change']['prop_changes']}
        self.assertIn(30000050013, granted)
        self.assertTrue({38050050066, 38050050067, 38050050068, 38050050069} <= granted)
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        records = self.request('CSShopGetBuyRecordReq')['hot_recommendation_records']
        self.assertEqual(records[0]['tab_id'], 10104007)
        before = self.backend.native_lobby_profile(self.token)
        self.assertNotEqual(self.request('CSShopBuyHotRecommendationReq', fields)['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_hidden_empty_banner_keeps_its_existing_purchase_record(self):
        from dfserver.premium_shop import CATALOG
        offer = next(r for r in CATALOG['recommendations'] if r['tab_id'] == 10102077)
        record = {'tab_id': offer['tab_id'], 'banner_type': offer['banner_type'],
                  'item_ids': [r['id'] for r in offer['bundle_item_list']]}
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.execute('INSERT INTO native_lobby_shop_records '
                '(player_id,kind,offer_id,record_json) VALUES (?,?,?,?)',
                (player_id, 'recommendation', offer['tab_id'], json.dumps(record)))
            connection.commit()
        result = self.request('CSShopGetBuyRecordReq')['hot_recommendation_records']
        self.assertEqual(result[0]['tab_id'], 10102077)
        self.assertTrue(result[0]['is_sold_out'])

    def test_native_sn472_paid_item_list_completes_bundle_and_persists_its_gifts(self):
        from dfserver import premium_shop
        offer = premium_shop.RECOVERED_RECOMMENDATIONS[10101048]
        fields = {'tab_id': '10101048', 'banner_type': 1,
            'item_ids': ['28040250003', '28020250006', '28060850003'],
            'currency_type': '17888808889', 'price': '2400',
            'currency_type_substitute': '17888808888'}
        request = self.codec.decode(self.codec.encode(
            'CSShopBuyHotRecommendationReq', fields, sequence=472))
        result = response_fields(request, self.backend, self.token)
        self.assertEqual(result['result'], 0)
        self.assertEqual(result['change']['currency_changes'][0]['delta'], -2400)
        self.assertEqual({r['prop']['id'] for r in result['change']['prop_changes']},
                         {r['id'] for r in offer['bundle_item_list']})
        self.assertEqual(self.codec.decode(self.codec.response(request, result)).sequence, 472)
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        record = self.request('CSShopGetBuyRecordReq')['hot_recommendation_records'][0]
        self.assertTrue(record['is_sold_out'])
        self.assertEqual(set(record['item_ids']), {r['id'] for r in offer['bundle_item_list']})
        before = self.backend.native_lobby_profile(self.token)
        self.assertNotEqual(self.request('CSShopBuyHotRecommendationReq', fields)['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_native_remaining_paid_items_use_bundle_discount_and_include_unowned_gifts(self):
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.execute('INSERT INTO native_lobby_gun_skins VALUES (?,?,0,NULL)',
                               (player_id, 28040250003))
            connection.commit()
        result = self.request('CSShopBuyHotRecommendationReq', {'tab_id': 10101048,
            'banner_type': 1, 'item_ids': [28020250006, 28060850003],
            'currency_type': 17888808889, 'price': 1600})
        self.assertEqual(result['result'], 0)
        self.assertEqual(result['change']['currency_changes'][0]['delta'], -1600)
        self.assertEqual({r['prop']['id'] for r in result['change']['prop_changes']},
                         {28020250006, 28060850003, 13460040218, 42010040740,
                          42020030782, 38020030561})
        self.assertTrue(self.request('CSShopGetBuyRecordReq')[
            'hot_recommendation_records'][0]['is_sold_out'])

    def test_paid_item_bundle_failure_after_grant_rolls_back_currency_ownership_and_record(self):
        from dfserver import premium_shop
        from dfserver.core import fail
        original_grant = premium_shop.grant
        before = self.backend.native_lobby_profile(self.token)

        def fail_after_grant(connection, player_id, items, changes):
            original_grant(connection, player_id, items, changes)
            self.assertEqual(changes['currency_changes'][0]['delta'], -2400)
            self.assertEqual(len(changes['prop_changes']), 7)
            fail('INVALID_ARGUMENT', 'Injected grant failure')

        with patch('dfserver.premium_shop.grant', side_effect=fail_after_grant):
            result = self.request('CSShopBuyHotRecommendationReq', {
                'tab_id': 10101048, 'banner_type': 1,
                'item_ids': [28040250003, 28020250006, 28060850003],
                'currency_type': 17888808889, 'price': 2400})
        self.assertNotEqual(result['result'], 0)
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)
        self.assertEqual(self.request('CSShopGetBuyRecordReq')['hot_recommendation_records'], [])

    def test_last_remaining_paid_item_uses_original_price_for_explicit_or_full_selection(self):
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            for skin_id in (28040250003, 28020250006):
                connection.execute('INSERT INTO native_lobby_gun_skins VALUES (?,?,0,NULL)',
                                   (player_id, skin_id))
            connection.commit()
        before = self.backend.native_lobby_profile(self.token)
        base = {'tab_id': 10101048, 'banner_type': 1, 'currency_type': 17888808889}
        for extra in ({'item_ids': [28060850003]}, {}):
            with self.subTest(extra=extra):
                result = self.request('CSShopBuyHotRecommendationReq',
                                      {**base, **extra, 'price': 800})
                self.assertNotEqual(result['result'], 0)
                self.assertEqual(self.backend.native_lobby_profile(self.token), before)
        result = self.request('CSShopBuyHotRecommendationReq',
                              {**base, 'item_ids': [28060850003], 'price': 1150})
        self.assertEqual(result['result'], 0)
        self.assertEqual(result['change']['currency_changes'][0]['delta'], -1150)
        self.assertEqual([r['prop']['id'] for r in result['change']['prop_changes']], [28060850003])
        gifts = self.request('CSShopBuyHotRecommendationReq', base)
        self.assertEqual(gifts['result'], 0)
        self.assertEqual(gifts['change']['currency_changes'], [])
        self.assertEqual({r['prop']['id'] for r in gifts['change']['prop_changes']},
                         {13460040218, 42010040740, 42020030782, 38020030561})

    def test_full_remaining_bundle_with_one_paid_item_uses_original_price(self):
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            for skin_id in (28040250003, 28020250006):
                connection.execute('INSERT INTO native_lobby_gun_skins VALUES (?,?,0,NULL)',
                                   (player_id, skin_id))
            connection.commit()
        result = self.request('CSShopBuyHotRecommendationReq', {'tab_id': 10101048,
            'banner_type': 1, 'currency_type': 17888808889, 'price': 1150})
        self.assertEqual(result['result'], 0)
        self.assertEqual(result['change']['currency_changes'][0]['delta'], -1150)
        self.assertTrue(self.request('CSShopGetBuyRecordReq')[
            'hot_recommendation_records'][0]['is_sold_out'])

    def test_standalone_paid_item_keeps_original_price_and_cannot_claim_free_bundle_items(self):
        base = {'tab_id': 10101048, 'banner_type': 1, 'currency_type': 17888808889}
        before = self.backend.native_lobby_profile(self.token)
        for fields in ({**base, 'item_ids': [28040250003], 'price': 800},
                       {**base, 'item_ids': [13460040218], 'price': 0},
                       {**base, 'item_ids': [28040250003, 13460040218], 'price': 1150}):
            self.assertNotEqual(self.request('CSShopBuyHotRecommendationReq', fields)['result'], 0)
            self.assertEqual(self.backend.native_lobby_profile(self.token), before)
        result = self.request('CSShopBuyHotRecommendationReq',
                              {**base, 'item_ids': [28040250003], 'price': 1150})
        self.assertEqual(result['result'], 0)
        self.assertEqual(result['change']['currency_changes'][0]['delta'], -1150)
        self.assertEqual([r['prop']['id'] for r in result['change']['prop_changes']], [28040250003])
        self.assertFalse(self.request('CSShopGetBuyRecordReq')[
            'hot_recommendation_records'][0]['is_sold_out'])

    def test_foreign_bundle_items_and_wrong_prices_do_not_charge(self):
        before = self.backend.native_lobby_profile(self.token)
        for fields in [dict(tab_id=10104007, banner_type=1, item_ids=[32320000001],
                            currency_type=17888808889, price=2690),
                       dict(tab_id=10104007, banner_type=1, item_ids=[30000050013],
                            currency_type=17888808889, price=1)]:
            self.assertNotEqual(self.request('CSShopBuyHotRecommendationReq', fields)['result'], 0)
            self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_special_supply_key_uses_collection_and_purchase_record(self):
        result = self.request('CSShopBuyMallGiftReq', {'goods_id': 30100001, 'num': 1,
            'currency_type': 17888808889, 'price': 60})
        self.assertEqual(result['result'], 0)
        self.assertEqual(self.collection()[32320000001], 1)
        self.assertEqual(self.request('CSShopGetBuyRecordReq')['mall_gift_records'][0]['goods_id'], 30100001)

    def test_staff_pool_has_named_client_prizes_and_round_cost(self):
        result = self.request('CSShopGetLotteryInfoReq')
        self.assertEqual(len(result['lottery_pool_info']), 8)
        pool = next(p for p in result['lottery_pool_info'] if p['lottery_id'] == 20300008)
        self.assertEqual(pool['lottery_id'], 20300008)
        self.assertEqual(pool['cost_item_id'], 32370000001)
        self.assertEqual(pool['cost_num'], 1)
        ids = {p['id'] for r in pool['lottery_rewards'] for p in r['props']}
        self.assertIn(30000060010, ids)
        self.assertEqual(len(pool['lottery_rewards']), 8)

    def test_staff_reward_numbers_match_the_client_pool_sort_indices(self):
        pools = self.request('CSShopGetLotteryInfoReq')['lottery_pool_info']
        for pool in pools:
            with self.subTest(lottery_id=pool['lottery_id']):
                self.assertEqual([r['num_id'] for r in pool['lottery_rewards']], list(range(1, 9)))
                self.assertEqual(pool['prop_num_ids'], [])

    def test_legacy_global_reward_numbers_are_translated_without_granting_again(self):
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.execute('INSERT INTO native_lobby_staff_draws '
                '(player_id,lottery_id,won_ids_json,record_json) VALUES (?,?,?,?)',
                (player_id, 20300008, '[64]', json.dumps({'lottery_id': 20300008, 'num': 1})))
            connection.commit()
        before = self.backend.native_lobby_profile(self.token)
        info = self.request('CSShopGetLotteryInfoReq', {'lottery_id': 20300008})['lottery_pool_info'][0]
        self.assertEqual(info['prop_num_ids'], [8])
        self.assertEqual(info['cost_num'], 3)
        self.assertEqual(next(r for r in info['lottery_rewards'] if r['num_id'] == 8)['prob'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_staff_draw_grants_the_whole_remaining_pool_on_great_reward(self):
        self.assertEqual(self.request('CSShopBuyLotteryItemReq', {'buy_props': [{
            'item_id': 32370000001, 'num': 1, 'currency_type': 17888808889, 'price': 100}]
        })['result'], 0)
        with patch('dfserver.premium_shop.secrets.randbelow', return_value=0):
            result = self.request('CSShopOpenLotteryItemReq', {'lottery_id': 20300008, 'round': 1})
        self.assertEqual(result['result'], 0)
        self.assertEqual(self.collection().get(32370000001, 0), 0)
        self.assertEqual(self.collection()[30000060010], 1)
        self.assertEqual(len(result['lottery_pool_info']['prop_num_ids']), 8)
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        before = self.backend.native_lobby_profile(self.token)
        self.assertNotEqual(self.request('CSShopOpenLotteryItemReq',
            {'lottery_id': 20300008, 'round': 1})['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)
        self.assertEqual(len(self.request('CSShopGetBuyRecordReq')['open_lottery_records']), 1)

    def test_native_seventh_staff_round_grants_subtype_15_weapon_skin(self):
        from dfserver import gun_skins
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            for number in range(3, 9):
                connection.execute('INSERT INTO native_lobby_staff_draws '
                    '(player_id,lottery_id,won_ids_json,record_json) VALUES (?,?,?,?)',
                    (player_id, 20300003, json.dumps([number]),
                     json.dumps({'lottery_id': 20300003, 'num': 1})))
            connection.commit()
        # Native seq790 bought the 25 keys needed for round 7 inline.
        fields = {'lottery_id': 20300003, 'round': 7, 'buy_prop': {
            'item_id': 32370000002, 'num': 25, 'currency_type': 17888808889,
            'price': 2500, 'currency_type_substitute': 17888808888}}
        request = self.codec.decode(self.codec.encode(
            'CSShopOpenLotteryItemReq', fields, sequence=790))
        with patch('dfserver.premium_shop.secrets.randbelow', return_value=8):
            result = response_fields(request, self.backend, self.token)
        self.codec.response(request, result)
        self.assertEqual(result['result'], 0)
        self.assertEqual(result['change']['currency_changes'][0]['delta'], -2500)
        changes = [r for r in result['change']['prop_changes'] if r['prop']['id'] == 28150150001]
        self.assertEqual(changes, [{'change_type': 1, 'delta': 1,
                                   'prop': {'id': 28150150001, 'gid': 0, 'num': 1}}])
        self.assertNotIn(28150150001, self.collection())
        self.assertEqual(gun_skins.SKINS[28150150001]['weapon_id'], 18150000001)
        self.assertEqual(result['lottery_pool_info']['prop_num_ids'], [3, 4, 5, 6, 7, 8, 2])
        self.assertEqual(result['lottery_pool_info']['cost_num'], 31)
        self.assertEqual(self.collection().get(32370000002, 0), 0)
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        with self.backend.connection() as connection:
            owned = connection.execute('SELECT skin_id,gid FROM native_lobby_gun_skins '
                'WHERE player_id=? AND skin_id=?', (player_id, 28150150001)).fetchone()
        self.assertEqual(tuple(owned), (28150150001, 0))
        applied = self.request('CSWAssemblyApplySkinReq', {'data_type': 0, 'cmds': [{
            'weapon_id': 18150000001, 'skin_id': 28150150001, 'apply_all': True}]})
        self.assertEqual(applied['result'], 0)
        self.assertEqual(applied['changes']['weapon_skin_setup'], [{
            'weapon_id': 18150000001, 'skin_id': 28150150001, 'skin_gid': 0}])
        before = self.backend.native_lobby_profile(self.token)
        self.assertNotEqual(self.request('CSShopOpenLotteryItemReq', fields)['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_hero_fashion_cannot_equip_another_hero_or_unowned_skin(self):
        result = self.request('CSHeroEquipFashionReq', {'hero_id': 88000000027,
            'new_fashions': [{'slot': 0, 'id': 30000060008}]})
        self.assertNotEqual(result['result'], 0)
        self.request('CSShopBuyHotRecommendationReq', {'tab_id': 10104007, 'banner_type': 1,
            'item_ids': [30000050013], 'currency_type': 17888808889, 'price': 2210})
        good = self.request('CSHeroEquipFashionReq', {'hero_id': 88000000025,
            'new_fashions': [{'slot': 0, 'id': 30000050013}]})
        self.assertEqual(good['result'], 0)
        self.assertEqual(good['target_hero']['fashion_equipped'][0]['id'], 30000050013)
        wrong = self.request('CSHeroEquipFashionReq', {'hero_id': 88000000027,
            'new_fashions': [{'slot': 0, 'id': 30000050013}]})
        self.assertNotEqual(wrong['result'], 0)

    def test_inline_key_purchase_and_stale_round_do_not_charge_twice(self):
        fields = {'lottery_id': 20300008, 'round': 1, 'buy_prop': {
            'item_id': 32370000001, 'num': 1, 'currency_type': 17888808889, 'price': 100}}
        with patch('dfserver.premium_shop.secrets.randbelow', return_value=9999):
            result = self.request('CSShopOpenLotteryItemReq', fields)
        self.assertEqual(result['result'], 0)
        self.assertEqual(len(result['lottery_pool_info']['prop_num_ids']), 1)
        self.assertEqual(result['lottery_pool_info']['cost_num'], 3)
        self.assertEqual(self.collection().get(32370000001, 0), 0)
        before = self.backend.native_lobby_profile(self.token)
        self.assertNotEqual(self.request('CSShopOpenLotteryItemReq', fields)['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)
        fields['round'] = 2
        self.assertNotEqual(self.request('CSShopOpenLotteryItemReq', fields)['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_insufficient_keys_and_split_payment_rollback(self):
        before = self.backend.native_lobby_profile(self.token)
        self.assertNotEqual(self.request('CSShopOpenLotteryItemReq',
            {'lottery_id': 20300008, 'round': 1})['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)
        self.backend.set_native_lobby_profile(self.token, level=60, props=[],
            currencies={17888808889: 2200, 17888808888: 1})
        before = self.backend.native_lobby_profile(self.token)
        result = self.request('CSShopBuyHotRecommendationReq', {
            'tab_id': 10104007, 'banner_type': 1, 'item_ids': [30000050013],
            'currency_type': 17888808889, 'price': 2140,
            'currency_type_substitute': 17888808888, 'price_substitute': 70})
        self.assertNotEqual(result['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)
        self.assertEqual(self.request('CSShopGetBuyRecordReq')['hot_recommendation_records'], [])

    def test_local_cash_bundle_grants_configured_contents_without_payment_sdk(self):
        before = self.backend.native_lobby_profile(self.token)
        result = self.request('CSShopBuyMallGiftReq', {
            'goods_id': 30200024, 'num': 1, 'is_cash_buy': True,
            'CashBuyReq': {'product_id': '30200024', 'quantity': 1}})
        self.assertEqual(result['result'], 0)
        self.assertFalse(result['is_cash_buy'])
        self.assertEqual(result['change']['currency_changes'][0]['delta'], 60)
        self.assertTrue({38020030623, 42010040829} <= self.collection().keys())
        self.assertEqual(self.backend.native_lobby_profile(self.token)['props'], before['props'])

    def test_notifications_update_collection_and_hero_before_purchase_callback(self):
        request = CandidateMessage('CSShopBuyHotRecommendationReq',
            self.codec.services['CSShopBuyHotRecommendationReq'], 19, {
                'tab_id': 10104007, 'banner_type': 1, 'item_ids': [30000050013],
                'currency_type': 17888808889, 'price': 2210})
        result = response_fields(request, self.backend, self.token)
        key = b'0123456789abcdef'
        response = encode_data_frame((self.codec.response(request, result),), key,
            direction='server_to_client', opaque_flag=64, header_word4=12, header_word9=20)
        frames = _candidate_local_collection_response_frames(response, key, self.backend, self.token)
        messages = [self.codec.decode(decode_data_frame(f, key,
            direction='server_to_client', compression_method=1, max_output=1024 * 1024).messages[0]) for f in frames]
        self.assertEqual([m.name for m in messages], [
            'CSCollectionPropChangeNtf', 'CSHeroUnlockNtf', 'CSShopBuyHotRecommendationRes'])
        self.assertEqual([f.header_word9 for f in frames], [20, 21, 22])
        self.assertEqual(messages[-1].sequence, 19)
        self.assertEqual(int(messages[1].fields['heros'][0]['hero_id']), 88000000025)
        currency = _candidate_local_inventory_change_notification(frames[-1], key,
            header_word4=12, header_word9=23)
        changes = self.codec.decode(decode_data_frame(currency, key,
            direction='server_to_client', compression_method=1).messages[0]).fields['deposit_change']
        self.assertFalse(changes.get('prop_changes'))
        self.assertEqual(int(changes['currency_changes'][0]['delta']), -2210)

    def test_bundle_accessory_claim_refreshes_hero_without_a_new_fashion(self):
        from dfserver import gun_skins
        gun_skins.collection(self.backend, self.token)
        self.request('CSShopBuyHotRecommendationReq', {'tab_id': 10104007,
            'banner_type': 1, 'item_ids': [30000050013],
            'currency_type': 17888808889, 'price': 2210})
        request = CandidateMessage('CSShopBuyHotRecommendationReq',
            self.codec.services['CSShopBuyHotRecommendationReq'], 22, {
                'tab_id': 10104007, 'banner_type': 1, 'currency_type': 17888808889})
        result = response_fields(request, self.backend, self.token)
        self.assertEqual(result['result'], 0)
        self.assertNotIn(30000050013, {r['prop']['id'] for r in result['change']['prop_changes']})
        key = b'0123456789abcdef'
        response = encode_data_frame((self.codec.response(request, result),), key,
            direction='server_to_client', opaque_flag=64, header_word4=12, header_word9=20)
        frames = _candidate_local_collection_response_frames(response, key, self.backend, self.token)
        messages = [self.codec.decode(decode_data_frame(f, key,
            direction='server_to_client', compression_method=1, max_output=1024 * 1024).messages[0]) for f in frames]
        self.assertEqual([m.name for m in messages], [
            'CSCollectionPropChangeNtf', 'CSHeroUnlockNtf', 'CSShopBuyHotRecommendationRes'])
        target = next(r for r in messages[1].fields['heros'] if int(r['hero_id']) == 88000000025)
        voices = [r for r in target['accessories'] if int(r['item']['prop_id']) in
                  {38050050066, 38050050067, 38050050068, 38050050069}]
        self.assertEqual(len(voices), 4)
        self.assertTrue(all(r['is_unlock'] for r in voices))

    def test_unmapped_weapon_skin_offer_does_not_charge_or_create_collection_prop(self):
        before = self.backend.native_lobby_profile(self.token)
        result = self.request('CSShopBuyHotRecommendationReq', {'tab_id': 10101035,
            'banner_type': 1, 'item_ids': [28010650008], 'currency_type': 17888808889, 'price': 1150})
        self.assertNotEqual(result['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_native_confirmed_melee_bundles_are_advertised(self):
        config = self.request('CSShopNewGetConfigReq')
        advertised = {r['tab_id'] for r in config['hot_recommendation_descs']}
        self.assertTrue({10102058, *range(10103001, 10103011)} <= advertised)
        self.assertTrue({10101035, 10102013, 10102077}.isdisjoint(advertised))

    def test_melee_bundle_purchase_persists_native_ownership_and_cannot_charge_twice(self):
        from dfserver import melee_weapons, premium_shop
        offer = premium_shop.RECOVERED_RECOMMENDATIONS[10103001]
        fields = {'tab_id': offer['tab_id'], 'banner_type': offer['banner_type'],
            'currency_type': offer['bundle_currency_type'], 'price': offer['bundle_price']}
        result = self.request('CSShopBuyHotRecommendationReq', fields)
        self.assertEqual(result['result'], 0)
        self.assertEqual(result['change']['currency_changes'][0]['delta'], -5200)
        self.assertIn({'change_type': 1, 'delta': 1,
            'prop': {'id': 28101250003, 'gid': 0, 'num': 1}}, result['change']['prop_changes'])
        self.assertNotIn(28101250003, self.collection())
        state = self.backend.native_lobby_profile(self.token)
        owned = next(r for r in state['melee_props'] if r['template_id'] == melee_weapons.SKINS[28101250003])
        self.assertGreater(owned['gid'], 0)
        self.backend.native_lobby_move_props(self.token, [{'prop_id': owned['template_id'],
            'prop_gid': owned['gid'], 'target_pos': melee_weapons.MELEE_POSITION}])
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        self.assertIn(owned, self.backend.native_lobby_profile(self.token)['melee_props'])
        self.assertEqual(self.backend.native_lobby_profile(self.token)['selected_melee_id'], owned['template_id'])
        before = self.backend.native_lobby_profile(self.token)
        self.assertNotEqual(self.request('CSShopBuyHotRecommendationReq', fields)['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)
        records = self.request('CSShopGetBuyRecordReq')['hot_recommendation_records']
        self.assertEqual(len(records), 1)
        self.assertTrue(records[0]['is_sold_out'])

    def test_melee_bundle_deducts_native_owned_skin_from_remaining_quote(self):
        self.backend.ensure_native_lobby_melee_collection(self.token)
        fields = {'tab_id': 10103001, 'banner_type': 1,
            'currency_type': 17888808889, 'price': 1600}
        result = self.request('CSShopBuyHotRecommendationReq', fields)
        self.assertEqual(result['result'], 0)
        self.assertEqual(result['change']['currency_changes'][0]['delta'], -1600)
        self.assertNotIn(28101250003, {r['prop']['id'] for r in result['change']['prop_changes']})
        before = self.backend.native_lobby_profile(self.token)
        self.assertNotEqual(self.request('CSShopBuyHotRecommendationReq', {
            'tab_id': 10103002, 'banner_type': 1, 'item_ids': [28101250010],
            'currency_type': 17888808889, 'price': 4880})['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_new_melee_receiver_is_notified_before_skin_and_purchase_callback(self):
        result = self.request('CSShopBuyHotRecommendationReq', {
            'tab_id': 10103001, 'banner_type': 1, 'item_ids': [28101250003],
            'currency_type': 17888808889, 'price': 4880})
        self.assertEqual(result['result'], 0)
        key = b'0123456789abcdef'
        response = encode_data_frame((self.codec.encode('CSShopBuyHotRecommendationRes',
            result, sequence=19),), key, direction='server_to_client',
            opaque_flag=64, header_word4=12, header_word9=20)
        frames = _candidate_local_collection_response_frames(response, key, self.backend, self.token)
        messages = [self.codec.decode(decode_data_frame(f, key,
            direction='server_to_client', compression_method=1).messages[0]) for f in frames]
        self.assertEqual([m.name for m in messages], [
            'CSMeleeUnlockChangeNtf', 'CSCollectionPropChangeNtf', 'CSShopBuyHotRecommendationRes'])
        self.assertEqual([f.header_word9 for f in frames], [20, 21, 22])
        receiver_change = messages[0].fields['deposit_change']['prop_changes'][0]
        self.assertEqual(receiver_change['change_type'], 1)
        prop = receiver_change['prop']
        self.assertEqual(int(prop['id']), 18100000008)
        self.assertEqual(int(prop['weapon']['skin_id']), 28101250003)
        owned = next(r for r in self.backend.native_lobby_profile(self.token)['melee_props']
                     if r['template_id'] == 18100000008)
        self.assertEqual(int(prop['gid']), owned['gid'])
        self.assertEqual(int(prop['num']), 1)
        self.assertEqual(prop['position'], 0)
        self.assertEqual([int(r['prop']['id']) for r in messages[1].fields['data_change']], [28101250003])
        self.assertEqual([int(r['prop']['id']) for r in messages[2].fields['change']['prop_changes']], [28101250003])
        currency = _candidate_local_inventory_change_notification(frames[-1], key,
            header_word4=12, header_word9=23)
        change = self.codec.decode(decode_data_frame(currency, key,
            direction='server_to_client', compression_method=1).messages[0]).fields['deposit_change']
        self.assertFalse(change.get('prop_changes'))
        self.assertEqual(int(change['currency_changes'][0]['delta']), -4880)

    def test_existing_melee_receiver_claim_does_not_send_duplicate_unlock_notification(self):
        from dfserver import gun_skins
        self.backend.ensure_native_lobby_melee_collection(self.token)
        gun_skins.collection(self.backend, self.token)
        result = self.request('CSShopBuyHotRecommendationReq', {
            'tab_id': 10103001, 'banner_type': 1, 'currency_type': 17888808889})
        self.assertEqual(result['result'], 0)
        key = b'0123456789abcdef'
        response = encode_data_frame((self.codec.encode('CSShopBuyHotRecommendationRes',
            result, sequence=19),), key, direction='server_to_client',
            opaque_flag=64, header_word4=12, header_word9=20)
        frames = _candidate_local_collection_response_frames(response, key, self.backend, self.token)
        names = [self.codec.decode(decode_data_frame(f, key,
            direction='server_to_client', compression_method=1, max_output=1024 * 1024).messages[0]).name for f in frames]
        self.assertNotIn('CSMeleeUnlockChangeNtf', names)

    def test_missing_game_item_skin_bundles_remain_hidden_and_cannot_charge(self):
        catalog = json.loads((ROOT / 'protocol/premium_shop_catalog.json').read_text())
        advertised = {r['tab_id'] for r in self.request('CSShopNewGetConfigReq')['hot_recommendation_descs']}
        for offer_id in (10101035, 10102013):
            with self.subTest(tab_id=offer_id):
                self.assertNotIn(offer_id, advertised)
                offer = next(r for r in catalog['recommendations'] if r['tab_id'] == offer_id)
                before = self.backend.native_lobby_profile(self.token)
                self.assertNotEqual(self.request('CSShopBuyHotRecommendationReq', {
                    'tab_id': offer_id, 'banner_type': offer['banner_type'],
                    'currency_type': offer['bundle_currency_type'], 'price': offer['bundle_price']})['result'], 0)
                self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_gift_records_accumulate_instead_of_hiding_previous_purchases(self):
        for _ in range(2):
            self.assertEqual(self.request('CSShopBuyMallGiftReq', {'goods_id': 30400001,
                'num': 1, 'currency_type': 17888808889, 'price': 100})['result'], 0)
        records = self.request('CSShopGetBuyRecordReq')['mall_gift_records']
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['num'], 2)

    def test_old_weekly_gift_record_does_not_keep_the_native_offer_locked(self):
        self.request('CSShopBuyMallGiftReq', {'goods_id': 30100001,
            'num': 1, 'currency_type': 17888808889, 'price': 60})
        with patch('dfserver.premium_shop.week_start', return_value=2**40):
            self.assertEqual(self.request('CSShopGetBuyRecordReq')['mall_gift_records'], [])
            self.assertEqual(self.request('CSShopBuyMallGiftReq', {'goods_id': 30100001,
                'num': 1, 'currency_type': 17888808889, 'price': 60})['result'], 0)

    def test_unrecovered_payment_offer_is_not_advertised_or_charged(self):
        config = self.request('CSShopNewGetConfigReq')
        self.assertNotIn(30900011, {r['goods_id'] for r in config['mall_gift_descs']})
        before = self.backend.native_lobby_profile(self.token)
        self.assertNotEqual(self.request('CSShopBuyMallGiftReq', {
            'goods_id': 30900011, 'num': 1, 'price': 6})['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_native_full_bundle_request_claims_freebies_when_paid_skins_owned(self):
        from dfserver import gun_skins
        gun_skins.collection(self.backend, self.token)
        result = self.request('CSShopBuyHotRecommendationReq', {
            'tab_id': 10102078, 'banner_type': 1, 'currency_type': 17888808889,
            'currency_type_substitute': 17888808888})
        self.assertEqual(result['result'], 0)
        self.assertFalse(result['change']['currency_changes'])
        self.assertTrue({38020030615, 42010040818, 42020030880} <= self.collection().keys())

    def test_native_standalone_fashion_quote_uses_original_item_price(self):
        result = self.request('CSShopBuyHotRecommendationReq', {
            'tab_id': 10104006, 'banner_type': 1, 'item_ids': [30000050029],
            'currency_type': 17888808889, 'price': 2210,
            'currency_type_substitute': 17888808888})
        self.assertEqual(result['result'], 0)
        self.assertEqual(result['change']['currency_changes'][0]['delta'], -2210)
