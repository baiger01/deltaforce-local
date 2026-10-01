import tempfile
from pathlib import Path
import unittest

from dfserver.core import Backend, DomainError
from dfserver.gcp_data import decode_data_frame
from dfserver.handshake_diagnostic import (
    _candidate_codec, _candidate_local_deposit_response, _candidate_local_equip_response)
from dfserver.local_commerce import CURRENCY_ID, response_fields, stock_catalog


ROOT = Path(__file__).resolve().parent.parent


class NativeSafeBoxTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.database = Path(temporary.name) / 'save.sqlite3'
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.token = self.backend.register('safe-box-test', 'local-password-123')['session']
        self.codec, self.key = _candidate_codec(), b'0123456789abcdef'
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[{
            'gid': 1001, 'template_id': 14020000003, 'quantity': 1,
            'grid_page_id': 2, 'x': 0, 'y': 0, 'length': 1, 'width': 1}])

    def reply(self, name, fields, handler):
        request = b'ABCD' + self.codec.encode(name, fields, sequence=81)
        frame = handler(request, self.backend, self.token, self.key,
                        header_word4=12, header_word9=81)
        return self.codec.decode(decode_data_frame(
            frame, self.key, direction='server_to_client', compression_method=1).messages[0]).fields

    def deposit(self):
        return self.reply('CSDepositGetPropsReq', {}, _candidate_local_deposit_response)

    def state(self):
        return {p['gid']: p for p in self.backend.native_lobby_profile(self.token)['props']}

    def test_fetch_has_owned_permission_selected_box_and_real_internal_capacity(self):
        deposit = self.deposit()
        permissions = {int(row['id']) for row in deposit['safe_and_card_pack_permission']}
        self.assertEqual(permissions, {11090000002, 11090000004})
        slot = next(row for row in deposit['equiped_props'] if row['position'] == 109001)
        self.assertEqual(int(slot['src_prop_id']), 11090000002)
        self.assertEqual(slot['capacity'], 4)
        self.assertEqual([(row['length'], row['width']) for row in slot['grid_space']], [(2, 2)])
        self.assertEqual(self.deposit(), deposit)

    def test_real_permission_command_without_gid_switches_capacity_and_persists(self):
        self.deposit()
        result = self.reply('CSDepositEquipPropReq', {
            'cmds': [{'prop_id': 11090000004, 'target_pos': 109}]}, _candidate_local_equip_response)
        self.assertEqual(result['result'], 0)
        change = next(row for row in result['deposit_change']['pos_changes'] if row['pos_id'] == 109001)
        self.assertEqual(int(change['src_prop_id']), 11090000004)
        self.assertEqual(change['change_type'], 3)
        self.assertEqual([p['change_type'] for p in result['deposit_change']['prop_changes']], [2, 1])
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        slot = next(row for row in self.deposit()['equiped_props'] if row['position'] == 109001)
        self.assertEqual(slot['capacity'], 9)

    def test_safe_storage_survives_reconnect_and_disallowed_item_does_not_move(self):
        self.deposit()
        moves = self.backend.native_lobby_move_props(self.token, [{
            'prop_id': 14020000003, 'prop_gid': 1001, 'src_pos': 2, 'target_pos': 109001,
            'spec_loc': {'pos': 109001, 'space_id': 1, 'start_x': 1, 'x': 1, 'y': 1}}])
        self.assertEqual(moves[0]['after']['grid_page_id'], 109001)
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        slot = next(row for row in self.deposit()['equiped_props'] if row['position'] == 109001)
        self.assertEqual(int(slot['load_props'][0]['gid']), 1001)
        self.assertEqual(slot['load_props'][0]['loc']['start_x'], 1)
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.execute('INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)',
                               (1002, player_id, 11010004001, 1, 2, 4, 0, 1, 1))
            connection.commit()
        before = self.state()
        with self.assertRaises(DomainError):
            self.backend.native_lobby_move_props(self.token, [{
                'prop_id': 11010004001, 'prop_gid': 1002, 'src_pos': 2, 'target_pos': 109001}])
        self.assertEqual(self.state(), before)

    def test_unknown_box_and_invalid_second_command_roll_back_switch(self):
        self.deposit()
        before = self.state()
        for commands in ([{'prop_id': 11090009999, 'target_pos': 109}], [
                {'prop_id': 11090000004, 'target_pos': 109},
                {'prop_id': 14020000003, 'prop_gid': 1001, 'target_pos': 999} ]):
            result = self.reply('CSDepositEquipPropReq', {'cmds': commands}, _candidate_local_equip_response)
            self.assertNotEqual(result['result'], 0)
            self.assertEqual(self.state(), before)

    def test_switch_with_contents_keeps_coordinates_and_rejects_smaller_overflow(self):
        self.deposit()
        self.backend.native_lobby_move_props(self.token, [{
            'prop_id': 14020000003, 'prop_gid': 1001, 'target_pos': 109001,
            'spec_loc': {'pos': 109001, 'space_id': 1, 'start_x': 1, 'start_y': 1}}])
        result = self.reply('CSDepositEquipPropReq', {
            'cmds': [{'prop_id': 11090000004, 'target_pos': 109}]}, _candidate_local_equip_response)
        self.assertEqual(result['result'], 0)
        item = next(row for row in result['deposit_change']['prop_changes'] if int(row['prop']['gid']) == 1001)
        self.assertEqual((item['dest']['start_x'], item['dest']['start_y']), (1, 1))
        self.backend.native_lobby_move_props(self.token, [{
            'prop_id': 14020000003, 'prop_gid': 1001, 'target_pos': 109001,
            'spec_loc': {'pos': 109001, 'space_id': 1, 'start_x': 2, 'start_y': 2}}])
        before = self.state()
        failed = self.reply('CSDepositEquipPropReq', {
            'cmds': [{'prop_id': 11090000002, 'target_pos': 109}]}, _candidate_local_equip_response)
        self.assertNotEqual(failed['result'], 0)
        self.assertEqual(self.state(), before)

    def test_body_snapshot_and_purchase_use_safe_container_and_preserve_ownership(self):
        self.deposit()
        self.backend.native_lobby_sync_body_containers(self.token, [{
            'pos': 109001, 'space': 1, 'props': [{
                'id': 14020000003, 'gid': 1001, 'num': 1,
                'loc': {'pos': 109001, 'space_id': 1, 'start_y': 1}}]}])
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.execute('INSERT INTO native_lobby_currencies VALUES (?,?,?)',
                               (player_id, 17020000010, 100000))
            connection.commit()
        bought = self.backend.native_lobby_purchase_container_batch(self.token, currency_id=17020000010,
            items=[{'template_id': 14020000003, 'quantity': 1, 'unit_price': 10,
                    'length': 1, 'width': 1, 'max_stack_count': 1, 'target_position': 109001}])
        self.assertEqual(bought['props'][0]['grid_page_id'], 109001)
        permission_gids = {int(p['gid']) for p in self.backend.native_lobby_profile(self.token)['safe_box_permissions']}
        self.assertNotIn(bought['props'][0]['gid'], permission_gids)
        before = self.backend.native_lobby_profile(self.token)
        with self.assertRaises(DomainError):
            self.backend.native_lobby_purchase_container_batch(self.token, currency_id=17020000010,
                items=[{'template_id': 11010004001, 'quantity': 1, 'unit_price': 10,
                        'length': 1, 'width': 1, 'max_stack_count': 1, 'target_position': 109001}])
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_expired_permission_is_not_usable(self):
        self.deposit()
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_safe_box_permissions SET expire_timestamp=1 '
                               'WHERE template_id=11090000004')
            connection.commit()
        before = self.state()
        result = self.reply('CSDepositEquipPropReq', {
            'cmds': [{'prop_id': 11090000004, 'target_pos': 109}]}, _candidate_local_equip_response)
        self.assertNotEqual(result['result'], 0)
        self.assertEqual(self.state(), before)

    def test_permission_slot_cannot_escape_through_move_or_body_snapshot(self):
        self.deposit()
        before = self.state()
        box = next(prop for prop in before.values() if prop['grid_page_id'] == 109)
        with self.assertRaises(DomainError):
            self.backend.native_lobby_move_props(self.token, [{
                'prop_id': box['template_id'], 'prop_gid': box['gid'],
                'src_pos': 109, 'target_pos': 2}])
        self.assertEqual(self.state(), before)
        with self.assertRaises(DomainError):
            self.backend.native_lobby_sync_body_containers(self.token, [{
                'pos': 199997, 'space': 1, 'props': [{
                    'id': box['template_id'], 'gid': box['gid'], 'num': 1,
                    'loc': {'pos': 199997, 'space_id': 1}}]}])
        self.assertEqual(self.state(), before)
        self.assertEqual(self.deposit()['result'], 0)

    def test_single_mall_purchase_delivers_to_safe_box_and_rolls_back_when_full(self):
        self.deposit()
        item_id = 14020000003
        price = stock_catalog()[item_id]['initial_guide_price']
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.execute('INSERT INTO native_lobby_currencies VALUES (?,?,?)',
                               (player_id, CURRENCY_ID, 100000))
            connection.commit()

        def buy(count):
            request = self.codec.decode(self.codec.encode('CSSerialCheapBuyReq', {
                'scene': 504, 'buy_list': [{'channel': 1, 'mall_prop': {'prop_info': {
                    'id': item_id, 'num': count, 'position': 109001}},
                    'mall_prices': [{'money_type': CURRENCY_ID, 'price': price * count}]}]},
                sequence=83))
            result = response_fields(request, self.backend, self.token)
            self.codec.response(request, result)
            return result

        result = buy(4)
        self.assertEqual(result['result'], 0)
        changes = result['mall_changes']['prop_changes']
        self.assertEqual(len(changes), 4)
        self.assertTrue(all(row['dest']['pos'] == 109001 for row in changes))
        before = self.backend.native_lobby_profile(self.token)
        self.assertNotEqual(buy(1)['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)


if __name__ == '__main__':
    unittest.main()
