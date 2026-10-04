from collections import Counter
from pathlib import Path
import tempfile
import unittest

from dfserver.core import Backend
from dfserver.gcp_data import decode_data_frame
from dfserver.handshake_diagnostic import _candidate_codec, _candidate_local_commerce_response
from dfserver.local_commerce import CURRENCY_ID


ROOT = Path(__file__).resolve().parent.parent


class NativeMaterialBatchTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.database = Path(directory.name) / 'save.sqlite3'
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.token = self.backend.register('material-buyer', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={CURRENCY_ID: 100000}, props=[])
        self.codec = _candidate_codec()

    def orders(self):
        # Original client scene 301, sequence 1788 from the 16:42 native trial.
        return [{'channel': 2, 'auction_prop': {'prop_id': item_id, 'total_num': count,
                 'currency': CURRENCY_ID, 'price': price}}
                for item_id, count, price in ((15020010008, 1, 3500),
                    (15020040001, 1, 25614), (15040010021, 2, 13069))]

    def purchase(self, entries):
        key = b'0123456789abcdef'
        request = b'ABCD' + self.codec.encode('CSSerialCheapBuyReq',
            {'scene': 301, 'buy_list': entries}, sequence=1788)
        response = _candidate_local_commerce_response(request, self.backend, self.token, key,
            header_word4=12, header_word9=1788)
        return self.codec.decode(decode_data_frame(response, key,
            direction='server_to_client', compression_method=1).messages[0]).fields

    def test_real_three_item_request_is_delivered_and_persisted_once(self):
        result = self.purchase(self.orders())
        self.assertEqual(result['result'], 0)
        self.assertEqual(int(result['auction_changes']['currency_changes'][0]['delta']), -55252)
        self.assertTrue(all(row['dest']['pos'] == 2
                            for row in result['auction_changes']['prop_changes']))
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        state = self.backend.native_lobby_profile(self.token)
        totals = Counter()
        for row in state['props']:
            totals[row['template_id']] += row['quantity']
        self.assertEqual(totals, {15020010008: 1, 15020040001: 1, 15040010021: 2})
        self.assertEqual(state['currencies'][0]['amount'], 44748)

    def test_bad_quote_rolls_back_entire_batch(self):
        orders = self.orders()
        orders[-1]['auction_prop']['price'] = 1
        before = self.backend.native_lobby_profile(self.token)
        self.assertNotEqual(self.purchase(orders)['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_insufficient_funds_roll_back_entire_batch(self):
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={CURRENCY_ID: 10000}, props=[])
        before = self.backend.native_lobby_profile(self.token)
        self.assertNotEqual(self.purchase(self.orders())['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)


if __name__ == '__main__':
    unittest.main()
