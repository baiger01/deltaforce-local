"""Native market-to-Mandel view contract, using recovered client identifiers.

MandelBrickPagePanel 0.29@23012 passes _curItemId unchanged. MandelDrawOnly
0.6@13516 calls StoreServer.GetDrawByMandelID (0.99@57977), whose exact ID
lookup returns nil when neither the active config nor StoreLottery has it.
"""

import tempfile
from pathlib import Path
import time
import unittest

from dfserver import mandel
from dfserver.core import Backend
from dfserver.handshake_diagnostic import _candidate_codec
from dfserver.local_commerce import (
    MANDEL_BRICK_PURCHASE_CURRENCY, response_fields, stock_catalog)


ROOT = Path(__file__).resolve().parent.parent
# StoreLottery export 7152, rows 0..10, SHA256
# 9afbcc8eb3b98d08ee45b4ef0cea12464decb9f82b1faeb64337a2a25d757e62.
SOURCE_DRAW_BRICKS = frozenset((16110000014, *range(16110000017, 16110000027)))


class NativeMandelViewTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.backend = Backend(Path(temporary.name) / 'save.sqlite3',
                               ROOT / 'definitions.json')
        self.token = self.backend.register('mandel-view', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(
            self.token, level=60, props=[],
            currencies={MANDEL_BRICK_PURCHASE_CURRENCY: 500000})
        self.codec = _candidate_codec()

    def request(self, name, fields=None):
        request = self.codec.decode(self.codec.encode(name, fields or {}, sequence=19))
        fields = response_fields(request, self.backend, self.token)
        self.assertIsNotNone(fields, name)
        return self.codec.decode(self.codec.response(request, fields)).fields

    def test_draw_brick_allowlist_keeps_exact_source_item_pool_links(self):
        self.assertEqual(mandel.DRAW_BRICK_IDS, SOURCE_DRAW_BRICKS)
        stores = {row['item_id']: row for row in mandel.CATALOG['store_lotteries']}
        for item_id in mandel.DRAW_BRICK_IDS:
            with self.subTest(item_id=item_id):
                self.assertEqual(stores[item_id]['lottery_type'], 1)
                box_id = mandel.BRICKS[item_id]['box_id']
                self.assertIn(box_id, mandel.BOXES)
                self.assertTrue(mandel.box_info(box_id)['group_list'])

    def test_market_open_and_reopen_resolve_a_real_draw_record(self):
        # The failed native trial opened 16110000001. It has no StoreLottery row.
        candidates = [int(value) for value in stock_catalog()
                      if str(value).startswith('161100')]
        self.assertEqual(set(candidates), SOURCE_DRAW_BRICKS)
        type_fields = self.request('CSMarketGetTypeListReq', {'prop_ids': candidates})
        shown = [int(row['prop_id']) for row in type_fields['type_lists']]
        self.assertEqual(set(shown), SOURCE_DRAW_BRICKS)
        client_table = {row['lottery_id']: row for row in mandel.CATALOG['store_lotteries']}
        for _ in range(2):
            config = self.request('CSShopNewGetConfigReq')
            now = int(time.time())
            # RefreshServerItemInfo accepts only native LotteryId rows;
            # StoreLotteryItem.RefreshServerInfo converts mandel_item_id with tonumber.
            # CandidateCodec preserves uint64 values as decimal strings in Python.
            active = [row for row in config['lottery_item_descs']
                      if int(row['lottery_id']) in client_table
                      and int(row['begin_time']) < now < int(row['end_time'])]
            for item_id in shown:
                with self.subTest(item_id=item_id):
                    draw_data = next((row for row in active
                                      if int(row['mandel_item_id']) == item_id), None)
                    self.assertIsNotNone(draw_data)
                    self.assertEqual(client_table[int(draw_data['lottery_id'])]['item_id'], item_id)
                    box_id = mandel.BRICKS[item_id]['box_id']
                    boxes = self.request('CSGetBoxInfoReq', {'id_list': [box_id]})
                    self.assertEqual(int(boxes['info_list'][0]['box_id']), box_id)
                    self.assertTrue(boxes['info_list'][0]['group_list'])

    def test_unmapped_legacy_brick_cannot_be_bought_or_mapped_to_a_fake_pool(self):
        # This historical brick has a ConnectedPool, but no matching StoreLottery row.
        item_id = 16110000005
        self.assertIn(item_id, mandel.BRICKS)
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.execute('INSERT INTO native_lobby_collection_props VALUES (?,?,?)',
                               (player_id, item_id, 2))
            connection.commit()
        before = self.backend.native_lobby_profile(self.token)
        fields = self.request('CSShopBuyLotteryItemReq', {'buy_props': [{
            'item_id': item_id, 'num': 1,
            'currency_type': MANDEL_BRICK_PURCHASE_CURRENCY, 'price': 20000}]})
        self.assertNotEqual(fields['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)
        self.assertNotIn(item_id, {int(row['mandel_item_id']) for row in
                                  mandel.shop_config()['lottery_item_descs']})


if __name__ == '__main__':
    unittest.main()
