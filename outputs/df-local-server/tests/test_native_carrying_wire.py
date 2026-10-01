import tempfile
from pathlib import Path
import unittest

from dfserver.core import Backend
from dfserver.gcp_data import decode_data_frame
from dfserver.handshake_diagnostic import (
    _candidate_codec, _candidate_local_commerce_response,
    _candidate_local_deposit_response, _candidate_local_equip_response)
from dfserver.local_commerce import CURRENCY_ID, stock_catalog


ROOT = Path(__file__).resolve().parent.parent
CHEST_ID = 11070005004
BACKPACK_ID = 11080006004
SMALL_CHEST_ID = 11070004001
SMALL_BACKPACK_ID = 11080003005
SMALL_CHEST_LAYOUT = [(1, 2), (1, 2), (1, 2), (1, 1), (1, 1), (1, 3), (1, 3)]


class NativeCarryingWireTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.database = Path(temporary.name) / 'save.sqlite3'
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.token = self.backend.register('carrying-wire', 'local-password-123')['session']
        self.codec, self.key = _candidate_codec(), b'0123456789abcdef'
        self.provision()

    @staticmethod
    def prop(gid, template_id, position, *, quantity=1, x=0, y=0):
        return {'gid': gid, 'template_id': template_id, 'quantity': quantity,
                'grid_page_id': position, 'x': x, 'y': y, 'length': 1, 'width': 1}

    def provision(self, props=None):
        if props is None:
            props = [self.prop(1001, CHEST_ID, 107),
                     self.prop(1002, 14020000003, 107001, quantity=3, x=5, y=3),
                     self.prop(1003, BACKPACK_ID, 108),
                     self.prop(1004, 14020000003, 108001, quantity=2, x=1, y=7)]
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={CURRENCY_ID: 100000}, props=props)

    def reply(self, name, fields, handler):
        request = b'ABCD' + self.codec.encode(name, fields, sequence=91)
        frame = handler(request, self.backend, self.token, self.key,
                        header_word4=12, header_word9=91)
        return self.codec.decode(decode_data_frame(frame, self.key,
            direction='server_to_client', compression_method=1).messages[0]).fields

    def deposit(self):
        return self.reply('CSDepositGetPropsReq', {}, _candidate_local_deposit_response)

    def equip(self, commands):
        return self.reply('CSDepositEquipPropReq', {'cmds': commands},
                          _candidate_local_equip_response)

    def assert_layout(self, change, position, template_id, layout):
        self.assertEqual(change['pos_id'], position)
        self.assertEqual(change['change_type'], 3)
        self.assertEqual(int(change.get('src_prop_id', 0)), template_id)
        self.assertEqual([(space['id'], space['length'], space['width'])
                          for space in change.get('space', [])],
                         [(index, width, height) for index, (width, height) in enumerate(layout, 1)])

    def test_encrypted_unequip_clears_both_layouts_and_reports_every_original_content_location(self):
        result = self.equip([
            {'prop_id': CHEST_ID, 'prop_gid': 1001, 'src_pos': 107, 'target_pos': 2, 'num': 1},
            {'prop_id': BACKPACK_ID, 'prop_gid': 1003, 'src_pos': 108, 'target_pos': 2, 'num': 1}])
        self.assertEqual(result['result'], 0)
        positions = result['deposit_change']['pos_changes']
        self.assertEqual(len(positions), 2)
        self.assert_layout(positions[0], 107001, 0, [])
        self.assert_layout(positions[1], 108001, 0, [])
        changes = {int(change['prop']['gid']): change
                   for change in result['deposit_change']['prop_changes']}
        self.assertEqual(set(changes), {1001, 1002, 1003, 1004})
        for gid, position, space, x, y, quantity in (
                (1002, 107001, 5, 1, 1, 3), (1004, 108001, 1, 2, 1, 2)):
            change = changes[gid]
            self.assertEqual((change['src']['pos'], change['src']['space_id'],
                              change['src']['start_x'], change['src']['start_y']),
                             (position, space, x, y))
            self.assertEqual(change['dest']['pos'], 2)
            self.assertEqual(int(change['prop']['num']), quantity)
        slots = {slot['position']: slot for slot in self.deposit()['equiped_props']}
        for position in (107001, 108001):
            self.assertEqual(slots[position].get('capacity', 0), 0)
            self.assertEqual(slots[position].get('load_props', []), [])

    def test_encrypted_replacement_uses_new_layouts_and_old_source_coordinates(self):
        self.provision([
            self.prop(1001, CHEST_ID, 107),
            self.prop(1002, 14020000003, 107001, quantity=3, x=5, y=3),
            self.prop(1003, BACKPACK_ID, 108),
            self.prop(1004, 14020000003, 108001, quantity=2, x=1, y=7),
            self.prop(1005, SMALL_CHEST_ID, 2, x=3, y=10),
            self.prop(1006, SMALL_BACKPACK_ID, 2, x=4, y=10)])
        result = self.equip([
            {'prop_id': SMALL_CHEST_ID, 'prop_gid': 1005, 'src_pos': 2, 'target_pos': 107},
            {'prop_id': SMALL_BACKPACK_ID, 'prop_gid': 1006, 'src_pos': 2, 'target_pos': 108}])
        self.assertEqual(result['result'], 0)
        positions = result['deposit_change']['pos_changes']
        self.assertEqual(len(positions), 2)
        self.assert_layout(positions[0], 107001, SMALL_CHEST_ID, SMALL_CHEST_LAYOUT)
        self.assert_layout(positions[1], 108001, SMALL_BACKPACK_ID, [(3, 7)])
        changes = {int(change['prop']['gid']): change
                   for change in result['deposit_change']['prop_changes']}
        self.assertEqual(set(changes), {1001, 1002, 1003, 1004, 1005, 1006})
        self.assertEqual((changes[1002]['src']['start_x'], changes[1002]['src']['start_y']), (1, 1))
        self.assertEqual((changes[1004]['src']['start_x'], changes[1004]['src']['start_y']), (2, 1))
        self.assertEqual(changes[1005]['dest']['pos'], 107)
        self.assertEqual(changes[1006]['dest']['pos'], 108)

    def test_encrypted_purchase_replacement_returns_new_layout_and_all_displaced_items(self):
        row = stock_catalog()[SMALL_CHEST_ID]
        result = self.reply('CSSerialCheapBuyReq', {'scene': 504, 'buy_list': [{
            'channel': 2, 'single_auction_prop': {'prop_id': SMALL_CHEST_ID,
                'buy_num': 1, 'currency': CURRENCY_ID,
                'price': row['initial_guide_price'], 'to_pos': 107}}]},
            _candidate_local_commerce_response)
        self.assertEqual(result['result'], 0)
        change = result['auction_changes']
        self.assertEqual(len(change['pos_changes']), 1)
        self.assert_layout(change['pos_changes'][0], 107001, SMALL_CHEST_ID, SMALL_CHEST_LAYOUT)
        props = change['prop_changes']
        self.assertEqual(len(props), 3)
        moved = {int(prop['prop']['gid']): prop for prop in props if prop['change_type'] == 5}
        self.assertEqual(set(moved), {1001, 1002})
        self.assertEqual((moved[1002]['src']['start_x'], moved[1002]['src']['start_y']), (1, 1))
        added = next(prop for prop in props if prop['change_type'] == 1)
        self.assertEqual(int(added['prop']['id']), SMALL_CHEST_ID)
        self.assertEqual(added['dest']['pos'], 107)
        self.assertEqual(int(change['currency_changes'][0]['delta']), -row['initial_guide_price'])

    def test_encrypted_bootstrap_without_carrying_equipment_has_zero_capacity_and_no_spaces(self):
        self.provision([])
        slots = {slot['position']: slot for slot in self.deposit()['equiped_props']}
        for position in (107001, 108001):
            with self.subTest(position=position):
                slot = slots[position]
                self.assertEqual(int(slot.get('src_prop_id', 0)), 0)
                self.assertEqual(slot.get('capacity', 0), 0)
                self.assertEqual(slot.get('grid_space', []), [])
                self.assertEqual(slot.get('load_props', []), [])


if __name__ == '__main__':
    unittest.main()
