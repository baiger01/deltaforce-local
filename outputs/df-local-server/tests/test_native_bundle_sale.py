from pathlib import Path
import tempfile
import unittest

from dfserver.core import Backend
from dfserver.handshake_diagnostic import _candidate_codec, _candidate_local_commerce_response
from dfserver.gcp_data import decode_data_frame
from dfserver.local_commerce import CURRENCY_ID, _price, priced_inventory_catalog


ROOT = Path(__file__).resolve().parent.parent


class NativeBundleSaleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.backend = Backend(Path(self.directory.name) / 'save.sqlite3', ROOT / 'definitions.json')
        self.token = self.backend.register('bundle-buyer', 'bundle-password-123')['session']
        self.codec = _candidate_codec()
        items = priced_inventory_catalog()
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={CURRENCY_ID: 100000}, props=[
                {'gid': gid, 'template_id': item_id, 'quantity': 1, 'grid_page_id': 2,
                 'x': x, 'y': 0, 'length': items[item_id]['length'], 'width': items[item_id]['width']}
                for gid, item_id, x in ((1001, 18020000001, 0), (1002, 14030000001, 6))])
        self.backend.native_lobby_profile(self.token)
        with self.backend.connection() as connection:
            connection.execute('INSERT INTO native_lobby_weapon_bullets VALUES (?,?,?,?)',
                               (2001, 1001, 37200100001, 30))
            connection.execute('INSERT INTO native_lobby_weapon_parts '
                               '(gid,weapon_gid,parent_gid,slot,template_id) VALUES (?,?,?,?,?)',
                               (2002, 1001, 1001, 11, 13110000067))
            connection.commit()
        self.before = self.backend.native_lobby_profile(self.token)
        self.weapon = next(row for row in self.before['props'] if row['gid'] == 1001)

    def sell(self, price, *, second_gid=1002, forged_bullets=False):
        prop = {'id': 18020000001, 'gid': 1001, 'num': 1}
        if forged_bullets:
            prop['weapon'] = {'load_bullets': [{'id': 37200100001, 'gid': 2001, 'num': 1000}]}
        message = b'ABCD' + self.codec.encode('CSMallSellReq', {
            'sell_props': [prop, {'id': 14030000001, 'gid': second_gid, 'num': 1}],
            'prices': [{'money_type': CURRENCY_ID, 'price': price}]}, sequence=51)
        key = b'0123456789abcdef'
        frame = _candidate_local_commerce_response(message, self.backend, self.token, key,
                                                   header_word4=1, header_word9=51)
        return self.codec.decode(decode_data_frame(frame, key, direction='server_to_client',
                                                   compression_method=1).messages[0])

    def ceiling(self):
        catalog = priced_inventory_catalog()
        amount = sum(_price(catalog[row['template_id']]) * row['quantity'] for row in self.before['props'])
        pending = list(self.weapon['components'])
        while pending:
            prop = pending.pop()['prop_data']
            if int(prop['id']) in catalog:
                amount += _price(catalog[int(prop['id'])]) * int(prop['num'])
            pending.extend(prop.get('components', []))
        return amount + _price(catalog[37200100001]) * 30

    def test_loaded_gun_and_parts_sell_as_one_owned_bundle_and_survive_reopen(self):
        price = self.ceiling()
        self.assertGreater(price, sum(_price(priced_inventory_catalog()[row['template_id']])
                                       for row in self.before['props']))
        response = self.sell(price)
        self.assertEqual(response.fields['result'], 0)
        changes = response.fields['prop_changes']['prop_changes']
        self.assertEqual(len(changes), 2)
        gun = next(change['prop'] for change in changes if int(change['prop']['gid']) == 1001)
        self.assertEqual(int(gun['weapon']['load_bullets'][0]['num']), 30)
        self.assertTrue(gun['components'])
        with self.backend.connection() as connection:
            for table in ('native_lobby_weapon_parts', 'native_lobby_weapon_bullets'):
                self.assertEqual(connection.execute(f'SELECT COUNT(*) FROM {table} WHERE weapon_gid=1001')
                                 .fetchone()[0], 0)
        reopened = Backend(self.backend.database, ROOT / 'definitions.json')
        after = reopened.native_lobby_profile(self.token)
        self.assertFalse(after['props'])
        balance = next(row['amount'] for row in after['currencies'] if row['currency_id'] == CURRENCY_ID)
        self.assertEqual(balance, 100000 + price)
        self.assertNotEqual(self.sell(price).fields['result'], 0)
        self.assertEqual(reopened.native_lobby_profile(self.token), after)

    def test_stale_member_rolls_back_whole_sale_and_keeps_loaded_ammo(self):
        self.assertNotEqual(self.sell(1, second_gid=9999).fields['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), self.before)

    def test_quote_cannot_count_client_supplied_unowned_extra_ammunition(self):
        self.assertNotEqual(self.sell(self.ceiling() + 1, forged_bullets=True).fields['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), self.before)


if __name__ == '__main__':
    unittest.main()
