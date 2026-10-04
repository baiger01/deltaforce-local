import tempfile
import unittest
from pathlib import Path

from dfserver import local_commerce as commerce
from dfserver.container_layouts import BACKPACK_LAYOUT, CHEST_RIG_LAYOUT
from dfserver.core import Backend
from dfserver.gcp_data import decode_data_frame
from dfserver.handshake_diagnostic import _candidate_codec, _candidate_local_commerce_response


ROOT = Path(__file__).resolve().parent.parent


class ContainerStockTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.database = Path(directory.name) / 'save.sqlite3'
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.token = self.backend.register('container-stock', 'local-password-123')['session']
        self.reset_profile()
        self.codec = _candidate_codec()

    def reset_profile(self):
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={commerce.CURRENCY_ID: 20000000}, props=[])

    def request(self, name, fields):
        key = b'0123456789abcdef'
        encoded = b'ABCD' + self.codec.encode(name, fields, sequence=712)
        response = _candidate_local_commerce_response(encoded, self.backend, self.token, key,
            header_word4=12, header_word9=712)
        return self.codec.decode(decode_data_frame(response, key,
            direction='server_to_client', compression_method=1).messages[0]).fields

    def test_sale_catalog_requires_recovered_container_layout(self):
        expected = set(CHEST_RIG_LAYOUT) | set(BACKPACK_LAYOUT)
        result = self.request('CSAuctionGetTypeListReq', {'prop_prefixes': ['1107', '1108']})
        listed = {int(row['prop_id']) for row in result.get('type_lists', [])}
        self.assertEqual(listed, expected)

    def test_previous_native_failures_have_no_sale_quote_but_retain_recycle_price(self):
        for item_id in (11070002005, 11070008001):
            with self.subTest(item_id=item_id):
                self.assertFalse(item_id in commerce.stock_catalog())
                self.assertIn(item_id, commerce.priced_inventory_catalog())
                quote = self.request('CSAuctionGetSaleListBatchReq',
                    {'infos': [{'prop_id': item_id}]})
                self.assertEqual(quote['result'], 0)
                self.assertFalse(quote.get('sale_lists'))
                recycle = self.request('CSAuctionGetGameItemSellPriceReq', {'prop_ids': [item_id]})
                self.assertEqual(int(recycle['sell_props'][0]['prop_id']), item_id)

    def test_stale_container_purchase_cannot_debit_or_displace(self):
        for item_id in (11070002005, 11070008001):
            with self.subTest(item_id=item_id):
                before = self.backend.native_lobby_profile(self.token)
                result = self.request('CSSerialCheapBuyReq', {'scene': 502, 'buy_list': [{
                    'channel': 2, 'single_auction_prop': {'prop_id': item_id, 'buy_num': 1,
                    'currency': commerce.CURRENCY_ID,
                    'price': commerce.installed_items()[str(item_id)]['initial_guide_price'],
                    'to_pos': 107}}]})
                self.assertNotEqual(result['result'], 0)
                self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_all_recovered_containers_quote_equip_and_reopen_with_actual_layout(self):
        for slot, layouts in ((107, CHEST_RIG_LAYOUT), (108, BACKPACK_LAYOUT)):
            for item_id, layout in layouts.items():
                with self.subTest(item_id=item_id, slot=slot):
                    self.reset_profile()
                    quote = self.request('CSAuctionGetSaleListBatchReq',
                        {'infos': [{'prop_id': item_id}]})
                    price = int(quote['sale_lists'][0]['guide_price'])
                    bought = self.request('CSSerialCheapBuyReq', {'scene': 502, 'buy_list': [{
                        'channel': 2, 'single_auction_prop': {'prop_id': item_id, 'buy_num': 1,
                        'currency': commerce.CURRENCY_ID, 'price': price, 'to_pos': slot}}]})
                    self.assertEqual(bought['result'], 0)
                    change = bought['auction_changes']['pos_changes'][0]
                    self.assertEqual(int(change['src_prop_id']), item_id)
                    self.assertEqual(change['pos_id'], slot * 1000 + 1)
                    self.assertEqual([(s['length'], s['width']) for s in change['space']],
                                     list(layout))
                    reopened = Backend(self.database, ROOT / 'definitions.json')
                    equipped = reopened.native_lobby_profile(self.token)['props']
                    self.assertEqual(len(equipped), 1)
                    self.assertEqual(equipped[0]['template_id'], item_id)
                    self.assertEqual(equipped[0]['grid_page_id'], slot)


if __name__ == '__main__':
    unittest.main()
