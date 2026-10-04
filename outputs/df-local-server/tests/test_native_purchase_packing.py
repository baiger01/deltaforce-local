from collections import Counter
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from dfserver.core import Backend, BACKPACK_POSITION, CHEST_RIG_POSITION
from dfserver.handshake_diagnostic import _candidate_codec, _candidate_local_commerce_response
from dfserver.gcp_data import decode_data_frame
from dfserver.local_commerce import CURRENCY_ID, stock_catalog


ROOT = Path(__file__).resolve().parent.parent


class NativePurchasePackingTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.database = Path(directory.name) / 'save.sqlite3'
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.token = self.backend.register('packing-buyer', 'local-password-123')['session']
        self.codec = _candidate_codec()

    @staticmethod
    def prop(gid, item_id, position, *, quantity=1, x=0, y=0, length=1, width=1):
        return {'gid': gid, 'template_id': item_id, 'quantity': quantity,
                'grid_page_id': position, 'x': x, 'y': y, 'length': length, 'width': width}

    def provision(self, props):
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={CURRENCY_ID: 1000000}, props=props)

    def buy(self, items, *, scene=504):
        entries = [{'channel': 2, 'single_auction_prop': {
            'prop_id': item_id, 'buy_num': count, 'currency': CURRENCY_ID,
            'price': stock_catalog()[item_id]['initial_guide_price'], 'to_pos': position}}
            for item_id, count, position in items]
        key = b'0123456789abcdef'
        request = b'ABCD' + self.codec.encode('CSSerialCheapBuyReq', {
            'scene': scene, 'buy_plan_type': 0, 'outfit_index': 0, 'buy_list': entries}, sequence=573)
        frame = _candidate_local_commerce_response(request, self.backend, self.token, key,
            header_word4=12, header_word9=573)
        return self.codec.decode(decode_data_frame(frame, key,
            direction='server_to_client', compression_method=1).messages[0]).fields

    def observed_props(self):
        # Trial 1791092848791436300, successful seq572 at 13:49:32.443937.
        # loc.x/y are item spans, start_x/start_y are coordinates. Local gids
        # are replaced by test instances; all template IDs and placements match.
        props = [self.prop(1001, 11070005004, 107),
                 self.prop(1002, 11080006004, 108)]
        gid = 1100
        for space, starts in ((1, ((0, 0), (0, 1), (0, 2))),
                              (2, ((0, 0), (1, 0), (0, 1), (1, 1)))):
            for x, y in starts:
                props.append(self.prop(gid, 37240700001, CHEST_RIG_POSITION,
                    quantity=20, x=space, y=y * (1 if space == 1 else 2) + x))
                gid += 1
        props.extend((self.prop(1201, 14070000001, CHEST_RIG_POSITION, x=2, y=5),
                      self.prop(1202, 14020000006, CHEST_RIG_POSITION,
                                x=4, length=2, width=2),
                      self.prop(1203, 14070000008, CHEST_RIG_POSITION, x=7)))
        return props

    @staticmethod
    def observed_purchase():
        # Failing native seq573: requested destinations are preserved verbatim.
        return [(14070000009, 1, BACKPACK_POSITION),
                (14040000001, 1, CHEST_RIG_POSITION),
                (14060000002, 1, CHEST_RIG_POSITION),
                (14070000003, 1, CHEST_RIG_POSITION),
                (14070000004, 1, BACKPACK_POSITION),
                (14070000005, 1, BACKPACK_POSITION),
                (14060000006, 1, CHEST_RIG_POSITION),
                (14030000002, 1, CHEST_RIG_POSITION)]

    def assert_purchase(self, before, items, response):
        self.assertEqual(response['result'], 0)
        self.assertEqual([int(order['prop']['id']) for order in response['orders']],
                         [item_id for item_id, _, _ in items])
        self.assertEqual([int(order['prop']['num']) for order in response['orders']],
                         [count for _, count, _ in items])
        stacks = []
        for item_id, count, position in items:
            maximum = stock_catalog()[item_id]['max_stack_count']
            while count:
                stack = min(count, maximum)
                stacks.append((item_id, stack, position))
                count -= stack
        changes = response['auction_changes']['prop_changes']
        self.assertEqual([int(change['prop']['id']) for change in changes],
                         [item_id for item_id, _, _ in stacks])
        self.assertEqual([int(change['prop']['position']) for change in changes],
                         [position for _, _, position in stacks])
        price = sum(stock_catalog()[item_id]['initial_guide_price'] * count
                    for item_id, count, _ in items)
        state = Backend(self.database, ROOT / 'definitions.json').native_lobby_profile(self.token)
        self.assertEqual(state['currencies'][0]['amount'], 1000000 - price)
        original = {prop['gid']: prop for prop in before['props']}
        saved = {prop['gid']: prop for prop in state['props']}
        self.assertEqual({gid: saved[gid] for gid in original}, original)
        created = [prop for prop in state['props'] if prop['gid'] not in original]
        self.assertEqual(Counter((prop['template_id'], prop['quantity'], prop['grid_page_id'])
                                 for prop in created), Counter(stacks))
        self.assertEqual(len({prop['gid'] for prop in created}), len(created))
        return state

    def test_observed_eight_medicines_fit_exact_remaining_rig_cells(self):
        self.provision(self.observed_props())
        before = self.backend.native_lobby_profile(self.token)
        items = self.observed_purchase()
        state = self.assert_purchase(before, items, self.buy(items))
        long_medicine = next(prop for prop in state['props'] if prop['template_id'] == 14060000006)
        self.assertEqual((long_medicine['grid_page_id'], long_medicine['x'],
                          long_medicine['length'], long_medicine['width']),
                         (CHEST_RIG_POSITION, 3, 3, 1))
        self.assertTrue(long_medicine['rotated'])

    def test_largest_first_needs_an_alternative_orientation_to_fit(self):
        # A verified 5x9 backpack with only its upper-left 4x3 region free.
        props = [self.prop(1002, 11080006004, 108)]
        for y in range(9):
            for x in range(5):
                if x < 4 and y < 3:
                    continue
                props.append(self.prop(2000 + y * 5 + x, 14070000003,
                    BACKPACK_POSITION, x=1, y=y * 5 + x))
        self.provision(props)
        before = self.backend.native_lobby_profile(self.token)
        # 3x2 first-fit blocks 2x2 even when sorted by decreasing area. A
        # rotated 2x3 followed by 2x2 and 1x1 fits without moving owned items.
        items = [(15040040007, 1, BACKPACK_POSITION),
                 (14060000002, 1, BACKPACK_POSITION),
                 (14070000003, 1, BACKPACK_POSITION)]
        self.assert_purchase(before, items, self.buy(items))

    def test_truly_insufficient_rig_rolls_back_backpack_and_currency_together(self):
        props = self.observed_props()
        props.append(self.prop(1204, 14070000003, CHEST_RIG_POSITION, x=7, y=1))
        self.provision(props)
        before = self.backend.native_lobby_profile(self.token)
        response = self.buy(self.observed_purchase())
        self.assertEqual(response['result'], 14032)
        self.assertFalse(response.get('orders'))
        self.assertFalse(response.get('auction_changes'))
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute(
                'SELECT COUNT(*) FROM native_lobby_prop_rotations').fetchone()[0], 0)

    def test_fallback_preserves_stack_counts_and_original_notification_order(self):
        self.provision(self.observed_props())
        before = self.backend.native_lobby_profile(self.token)
        items = [(37110300001, 121, BACKPACK_POSITION)] + self.observed_purchase()
        self.assert_purchase(before, items, self.buy(items))

    def test_search_budget_failure_keeps_every_destination_and_currency_unchanged(self):
        self.provision(self.observed_props())
        before = self.backend.native_lobby_profile(self.token)
        with patch('dfserver.core.NATIVE_PURCHASE_PACKING_STEPS', 0):
            response = self.buy(self.observed_purchase())
        self.assertEqual(response['result'], 14032)
        self.assertFalse(response.get('orders'))
        self.assertFalse(response.get('auction_changes'))
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)


if __name__ == '__main__':
    unittest.main()
