from collections import Counter
from pathlib import Path
import tempfile
import unittest

from dfserver.core import Backend
from dfserver.gcp_data import decode_data_frame
from dfserver.handshake_diagnostic import _candidate_codec, _candidate_local_commerce_response
from dfserver.local_commerce import CURRENCY_ID, order_id, stock_catalog
from dfserver.socket_guid import socket_path


ROOT = Path(__file__).resolve().parent.parent


class SerialPurchaseOrderTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.database = Path(directory.name) / 'save.sqlite3'
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.token = self.backend.register('serial-order-buyer', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={CURRENCY_ID: 20000000}, props=[])
        self.codec = _candidate_codec()

    def buy(self, entries, *, scene=101, sequence=710):
        key = b'0123456789abcdef'
        request = b'ABCD' + self.codec.encode('CSSerialCheapBuyReq',
            {'scene': scene, 'buy_plan_type': 0, 'outfit_index': 0,
             'buy_list': entries}, sequence=sequence)
        frame = _candidate_local_commerce_response(request, self.backend, self.token, key,
            header_word4=12, header_word9=sequence)
        return self.codec.decode(decode_data_frame(frame, key,
            direction='server_to_client', compression_method=1).messages[0]).fields

    def entry(self, item_id, count=1, *, quoted_price=None):
        price = stock_catalog()[item_id]['initial_guide_price']
        return {'channel': 2, 'auction_prop': {'prop_id': item_id, 'total_num': count,
            'currency': CURRENCY_ID, 'price': price if quoted_price is None else quoted_price}}

    def assert_orders(self, result, expected):
        # AuctionServer.DoMultiPriceBuyReq callback 0.77.0, Lua lines 1804-1906,
        # PCs 264-277 sum orders[*].prop.num and prop.num * buy_price.
        # Source SHA256: ad10c29ff0fa53ca89ebebf9f0ba447cae2e47195b8921b24731cd01e4a82a6c.
        orders = result.get('orders', [])
        self.assertEqual(len(orders), len(expected))
        self.assertEqual(sum(int(order['prop']['num']) for order in orders),
                         sum(count for _, count, _ in expected))
        total = sum(int(order['prop']['num']) * int(order['buy_price']) for order in orders)
        self.assertEqual(total, sum(count * price for _, count, price in expected))
        self.assertEqual(int(result['auction_changes']['currency_changes'][0]['delta']), -total)
        for order, (item_id, count, price) in zip(orders, expected):
            self.assertEqual(int(order['prop']['id']), item_id)
            self.assertEqual(int(order['prop']['num']), count)
            self.assertEqual(int(order['show_prop_id']), item_id)
            self.assertEqual(int(order['order_id']), order_id(item_id))
            self.assertEqual(int(order['price_currency']), CURRENCY_ID)
            self.assertEqual(int(order['price']), price)
            self.assertEqual(int(order['buy_price']), price)

    def assert_failure_unchanged(self, entries, *, scene=101):
        before = self.backend.native_lobby_profile(self.token)
        result = self.buy(entries, scene=scene)
        self.assertNotEqual(result['result'], 0)
        self.assertEqual(result.get('orders', []), [])
        self.assertEqual(result.get('auction_changes', {}).get('prop_changes', []), [])
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_actual_six_keycard_requests_report_and_save_one_one_four(self):
        # Actual trial: sequences 710/727 buy one card each, 753/758/761/766 buy the third.
        cards = ((15050500001, 1857276), (15050500004, 2934984), (15050500009, 1400735))
        sequences = (710, 727, 753, 758, 761, 766)
        purchases = cards[:2] + (cards[2],) * 4
        for sequence, (item_id, price) in zip(sequences, purchases):
            with self.subTest(sequence=sequence, item_id=item_id):
                self.assertEqual(stock_catalog()[item_id]['initial_guide_price'], price)
                result = self.buy([self.entry(item_id)], sequence=sequence)
                self.assertEqual(result['result'], 0)
                self.assert_orders(result, [(item_id, 1, price)])
        reopened = Backend(self.database, ROOT / 'definitions.json')
        state = reopened.native_lobby_profile(self.token)
        self.assertEqual(Counter({item_id: sum(prop['quantity'] for prop in state['props']
            if prop['template_id'] == item_id) for item_id, _ in cards}),
            Counter({15050500001: 1, 15050500004: 1, 15050500009: 4}))
        self.assertEqual(state['currencies'][0]['amount'],
                         20000000 - (1857276 + 2934984 + 4 * 1400735))
        self.assertEqual(len({prop['gid'] for prop in state['props']}), 6)

    def test_batch_quantity_and_unit_price_match_the_committed_charge(self):
        # Actual scene 301 material vector, sequence 1788 in the earlier native trial.
        expected = [(15020010008, 1, 3500), (15020040001, 1, 25614), (15040010021, 2, 13069)]
        for total_quote in (False, True):
            with self.subTest(total_quote=total_quote):
                entries = [self.entry(item_id, count,
                    quoted_price=price * count if total_quote else price)
                    for item_id, count, price in expected]
                result = self.buy(entries, scene=301)
                self.assertEqual(result['result'], 0)
                self.assert_orders(result, expected)

    def test_single_equipment_purchase_reports_offer_and_actual_destination(self):
        item_id = 10010000019
        price = stock_catalog()[item_id]['initial_guide_price']
        result = self.buy([{'channel': 2, 'single_auction_prop': {
            'prop_id': item_id, 'buy_num': 1, 'currency': CURRENCY_ID,
            'price': price, 'to_pos': 111}}], scene=502)
        self.assertEqual(result['result'], 0)
        self.assert_orders(result, [(item_id, 1, price)])
        change = result['auction_changes']['prop_changes'][0]
        self.assertEqual(int(change['prop']['id']), 18010000010)
        self.assertEqual(change['dest']['pos'], 111)

    def assembly_entries(self):
        # Actual AKM root/nested component vectors from trial sequences 1042/1099.
        return [{'channel': 2, 'auction_prop': {'prop_id': item_id,
            'total_num': 1, 'currency': CURRENCY_ID, 'price': price,
            'assemble_info': {'id': item_id, 'num': 1, 'target_gid': 4001,
                              'pos_guid': guid}}}
            for item_id, guid, price in ((13240000006, 72339069014645763, 2069),
                                         (13430000001, 281474976710710, 1606))]

    def prepare_weapon(self):
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={CURRENCY_ID: 100000}, props=[
                {'gid': 4001, 'template_id': 18010000006, 'quantity': 1,
                 'grid_page_id': 111, 'x': 0, 'y': 0, 'length': 5, 'width': 2}])

    def test_automatic_assembly_reports_purchased_components_not_changed_weapon(self):
        self.prepare_weapon()
        entries = self.assembly_entries()
        result = self.buy(entries, scene=201)
        self.assertEqual(result['result'], 0)
        self.assert_orders(result, [(13240000006, 1, 2069), (13430000001, 1, 1606)])
        weapon = self.backend.native_lobby_profile(self.token)['props'][0]
        for entry in entries:
            offer = entry['auction_prop']
            parts = weapon['components']
            for slot in socket_path(offer['assemble_info']['pos_guid']):
                child = next(part for part in parts if part['slot'] == slot)['prop_data']
                parts = child['components']
            self.assertEqual(child['id'], offer['prop_id'])
        self.assertEqual(len(result['auction_changes']['prop_changes']), 1)

    def test_single_auction_prop_assembly_encodes_completed_order(self):
        self.prepare_weapon()
        offer = self.assembly_entries()[1]['auction_prop']
        offer['buy_num'] = offer.pop('total_num')
        result = self.buy([{'channel': 2, 'single_auction_prop': offer}], scene=201)
        self.assertEqual(result['result'], 0)
        self.assert_orders(result, [(13430000001, 1, 1606)])
        weapon = self.backend.native_lobby_profile(self.token)['props'][0]
        parts = weapon['components']
        for slot in socket_path(offer['assemble_info']['pos_guid']):
            child = next(part for part in parts if part['slot'] == slot)['prop_data']
            parts = child['components']
        self.assertEqual(child['id'], 13430000001)
        self.assertEqual(len(result['auction_changes']['prop_changes']), 1)

    def test_bad_batch_quote_has_no_completed_orders_or_mutations(self):
        self.assert_failure_unchanged([self.entry(15020010008),
            self.entry(15050500001, quoted_price=1)])

    def test_insufficient_funds_has_no_completed_orders_or_mutations(self):
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={CURRENCY_ID: 1}, props=[])
        self.assert_failure_unchanged([self.entry(15050500001)])

    def test_full_warehouse_has_no_completed_orders_or_mutations(self):
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={CURRENCY_ID: 20000000}, props=[
                {'gid': 4001, 'template_id': 15050500001, 'quantity': 1,
                 'grid_page_id': 2, 'x': 0, 'y': 0, 'length': 9, 'width': 40}])
        self.assert_failure_unchanged([self.entry(15050500001)])

    def test_invalid_assembly_target_has_no_completed_orders_or_mutations(self):
        self.prepare_weapon()
        entries = self.assembly_entries()
        entries[-1]['auction_prop']['assemble_info']['target_gid'] = 999999
        self.assert_failure_unchanged(entries, scene=201)


if __name__ == '__main__':
    unittest.main()
