import json
from pathlib import Path
import tempfile
import unittest

from dfserver import local_commerce as commerce
from dfserver.core import Backend
from dfserver.gcp_data import decode_data_frame
from dfserver.handshake_diagnostic import _candidate_codec, _candidate_local_commerce_response
from dfserver.weapon_components import ROWS, default_components
from dfserver.weapon_ammo import magazine_capacity


ROOT = Path(__file__).resolve().parent.parent
LMG_PRESETS = {
    10040000900: 18040000001,
    10040000006: 18040000002,
    10040000910: 18040000003,
    10040001528: 18040000004,
}


class GunsmithStockTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.database = Path(directory.name) / 'save.sqlite3'
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.token = self.backend.register('gunsmith-stock', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={commerce.CURRENCY_ID: 20000000}, props=[])
        self.codec = _candidate_codec()

    def request(self, name, fields):
        key = b'0123456789abcdef'
        encoded = b'ABCD' + self.codec.encode(name, fields, sequence=711)
        response = _candidate_local_commerce_response(encoded, self.backend, self.token, key,
            header_word4=12, header_word9=711)
        return self.codec.decode(decode_data_frame(response, key,
            direction='server_to_client', compression_method=1).messages[0]).fields

    def quoted(self, preset):
        result = self.request('CSAuctionGetSaleListBatchReq', {'infos': [{'prop_id': preset}]})
        self.assertEqual(result['result'], 0)
        self.assertEqual(len(result.get('sale_lists', [])), 1)
        return result['sale_lists'][0]

    def tree_price(self, receiver):
        # ShopServer 0.131 prices GetAllParts(), excluding model-only components.
        pending = [ROWS[str(receiver)]['prop']]
        total = 0
        while pending:
            node = pending.pop()
            source = commerce.installed_items()[str(node['id'])]
            if not source['is_model_only']:
                total += source['initial_guide_price'] * node['num']
            pending.extend(part['prop_data'] for part in node.get('components', []))
        return total

    def parts(self, components, parent=()):
        result = []
        for part in components:
            path = parent + (part['slot'],)
            prop = part['prop_data']
            result.append((path, int(prop['id']), int(prop['num'])))
            result.extend(self.parts(prop.get('components', []), path))
        return result

    def test_lmg_browse_matches_four_distinct_client_default_receivers(self):
        result = self.request('CSAuctionGetTypeListReq', {'prop_prefixes': ['1004']})
        listed = [int(row['prop_id']) for row in result.get('type_lists', [])]
        self.assertEqual(set(listed), set(LMG_PRESETS))
        self.assertEqual(len(listed), len(LMG_PRESETS))

    def test_zero_size_presets_quote_and_deliver_real_receiver_parts_after_restart(self):
        for preset, receiver in LMG_PRESETS.items():
            with self.subTest(preset=preset, receiver=receiver):
                detail = self.quoted(preset)
                offer = detail['sale_lists'][0]
                price = self.tree_price(receiver)
                self.assertGreater(price, 2)
                self.assertEqual(int(offer['price']), price)
                actual = commerce.installed_items()[str(receiver)]
                self.assertEqual((offer['prop']['length'], offer['prop']['width']),
                                 (actual['length'], actual['width']))
                self.assertEqual(self.parts(offer['prop']['components']),
                                 self.parts(default_components(receiver)))
                result = self.request('CSSerialCheapBuyReq', {'scene': 502, 'buy_list': [{
                    'channel': 2, 'single_auction_prop': {'prop_id': preset, 'buy_num': 1,
                    'currency': commerce.CURRENCY_ID, 'price': price, 'to_pos': 111}}]})
                self.assertEqual(result['result'], 0)
                self.assertEqual(int(result['orders'][0]['prop']['id']), preset)
                self.assertEqual(int(result['orders'][0]['buy_price']), price)
                self.assertEqual(int(result['auction_changes']['currency_changes'][0]['delta']), -price)
                reopened = Backend(self.database, ROOT / 'definitions.json')
                guns = [row for row in reopened.native_lobby_profile(self.token)['props']
                        if row['grid_page_id'] == 111]
                self.assertEqual(len(guns), 1)
                gun = guns[0]
                self.assertEqual(gun['template_id'], receiver)
                self.assertEqual((gun['length'], gun['width']), (actual['length'], actual['width']))
                self.assertEqual(self.parts(gun['components']), self.parts(default_components(receiver)))
                capacity = magazine_capacity(default_components(receiver), receiver)
                self.assertIsNotNone(capacity)
                self.assertEqual(gun['weapon']['magazine_capacity'], capacity)
                self.assertEqual(int(self.quoted(preset)['guide_price']), price)

    def test_each_client_base_firearm_can_be_quoted_and_purchased_as_its_own_receiver(self):
        source = json.loads((ROOT / 'protocol/weapon_preset_catalog.json').read_text(encoding='utf-8'))
        expected = {int(row['default_preset_id']): int(receiver)
                    for receiver, row in source['rows'].items()
                    if row['is_base_weapon'] and row['default_preset_id']
                    and str(receiver).startswith(tuple('180' + str(n) for n in range(1, 8)))}
        self.assertEqual(len(expected), 67)
        result = self.request('CSAuctionGetTypeListReq', {'prop_prefixes': ['100']})
        self.assertEqual({int(row['prop_id']) for row in result.get('type_lists', [])}, set(expected))
        for preset, receiver in expected.items():
            with self.subTest(preset=preset, receiver=receiver):
                self.backend.set_native_lobby_profile(self.token, level=60,
                    currencies={commerce.CURRENCY_ID: 20000000}, props=[])
                detail = self.quoted(preset)
                price = int(detail['guide_price'])
                self.assertEqual(price, self.tree_price(receiver))
                bought = self.request('CSSerialCheapBuyReq', {'scene': 502, 'buy_list': [{
                    'channel': 2, 'single_auction_prop': {'prop_id': preset, 'buy_num': 1,
                    'currency': commerce.CURRENCY_ID, 'price': price, 'to_pos': 111}}]})
                self.assertEqual(bought['result'], 0)
                gun = self.backend.native_lobby_profile(self.token)['props'][0]
                self.assertEqual(gun['template_id'], receiver)
                self.assertEqual(self.parts(gun['components']), self.parts(default_components(receiver)))

    def test_placeholder_preset_price_is_not_used_as_complete_gun_price(self):
        # These source presets have price 2; their actual parts have normal prices.
        for preset, receiver in ((10010001854, 18010000043),
                                 (10020001973, 18020000012),
                                 (10050001724, 18050000032)):
            with self.subTest(preset=preset):
                self.assertEqual(commerce.installed_items()[str(preset)]['initial_guide_price'], 2)
                detail = self.quoted(preset)
                self.assertEqual(int(detail['guide_price']), self.tree_price(receiver))
                self.assertGreater(int(detail['guide_price']), 2)

    def test_nonbase_receiver_is_not_a_gunsmith_sale_offer(self):
        result = self.request('CSAuctionGetTypeListReq', {'prop_prefixes': ['100']})
        listed = {int(row['prop_id']) for row in result.get('type_lists', [])}
        self.assertNotIn(10010000018, listed)
        self.assertNotIn(10050000001, listed)

    def test_receiver_without_sol_default_is_not_sold_as_an_empty_gun(self):
        receiver = 18010000046
        result = self.request('CSAuctionGetTypeListReq', {'prop_ids': [receiver]})
        self.assertFalse(result.get('type_lists'))
        self.assertIn(receiver, commerce.priced_inventory_catalog())
        before = self.backend.native_lobby_profile(self.token)
        bought = self.request('CSSerialCheapBuyReq', {'scene': 502, 'buy_list': [{
            'channel': 2, 'single_auction_prop': {'prop_id': receiver, 'buy_num': 1,
            'currency': commerce.CURRENCY_ID,
            'price': commerce.installed_items()[str(receiver)]['initial_guide_price'],
            'to_pos': 111}}]})
        self.assertNotEqual(bought['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_special_receivers_without_a_verified_sale_path_are_not_offered(self):
        # Native RecFunction gives these special receivers no sale default;
        # 18100000001 has no matching RecFunction row. WeaponFeature.IsWeapon
        # nevertheless accepts all Receiver IDs before the selection filter.
        excluded = (18990000001, 18080000006, 18130000001,
                    18140000001, 18100000001, 18150000001)
        before = self.backend.native_lobby_profile(self.token)
        for receiver in excluded:
            with self.subTest(receiver=receiver):
                self.assertIn(receiver, commerce.priced_inventory_catalog())
                types = self.request('CSAuctionGetTypeListReq', {'prop_ids': [receiver]})
                self.assertFalse(types.get('type_lists'))
                quotes = self.request('CSAuctionGetSaleListBatchReq', {
                    'infos': [{'prop_id': receiver}]})
                self.assertFalse(quotes.get('sale_lists'))
                bought = self.request('CSSerialCheapBuyReq', {'scene': 502, 'buy_list': [{
                    'channel': 2, 'single_auction_prop': {'prop_id': receiver, 'buy_num': 1,
                    'currency': commerce.CURRENCY_ID,
                    'price': commerce.priced_inventory_catalog()[receiver]['initial_guide_price'],
                    'to_pos': 111}}]})
                self.assertNotEqual(bought['result'], 0)
                self.assertEqual(self.backend.native_lobby_profile(self.token), before)
        for confirmed in commerce.CONFIRMED_MALL_IDS:
            self.assertIn(confirmed, commerce.stock_catalog())

    def test_bad_complete_gun_quote_does_not_debit_or_grant(self):
        before = self.backend.native_lobby_profile(self.token)
        result = self.request('CSSerialCheapBuyReq', {'scene': 502, 'buy_list': [{
            'channel': 2, 'single_auction_prop': {'prop_id': 10040001528, 'buy_num': 1,
            'currency': commerce.CURRENCY_ID, 'price': 2, 'to_pos': 111}}]})
        self.assertNotEqual(result['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)


if __name__ == '__main__':
    unittest.main()
