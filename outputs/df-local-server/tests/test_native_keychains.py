from pathlib import Path
import tempfile
import unittest

from dfserver import native_keycards as keys
from dfserver.core import Backend, DomainError
from dfserver.gcp_data import decode_data_frame
from dfserver.handshake_diagnostic import (
    _candidate_codec, _candidate_local_deposit_response, _candidate_local_equip_response,
    _candidate_local_body_container_response)


ROOT = Path(__file__).resolve().parent.parent
CARD = 15050100001  # Source Key table: map 22, durability 20.


class NativeKeychainTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.database = Path(directory.name) / 'save.sqlite3'
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.token = self.backend.register('keychain-owner', 'local-password-123')['session']
        self.codec, self.key = _candidate_codec(), b'0123456789abcdef'

    def bags(self):
        rows = [row for row in keys.catalog()['resolved_key_boxes']
                if row['MapID'] == 22 and row['DefaultSlotNum'] > 0]
        self.assertTrue(rows, 'Tests require independently decoded Key/KeyBox ItemID bindings')
        return sorted(rows, key=lambda row: (row['DefaultSlotNum'], row['Index']))

    def grant(self, ids=None, selected=None):
        ids = ids or [int(self.bags()[0]['item_id'])]
        self.backend.ensure_native_lobby_keychains(
            self.token, template_ids=ids, selected_template_id=selected)
        return ids

    def card(self, gid=1001, x=0, health=3):
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.execute('INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)',
                (gid, player_id, CARD, 1, 2, x, 0, 1, 1))
            connection.execute('INSERT INTO native_lobby_keycard_health VALUES (?,?,20)', (gid, health))
            connection.commit()

    def state(self, token=None):
        return self.backend.native_lobby_profile(token or self.token)

    def reply(self, name, fields, handler):
        request = b'ABCD' + self.codec.encode(name, fields, sequence=81)
        frame = handler(request, self.backend, self.token, self.key,
                        header_word4=12, header_word9=81)
        return self.codec.decode(decode_data_frame(
            frame, self.key, direction='server_to_client', compression_method=1).messages[0]).fields

    def move(self, gid=1001, **extra):
        return {'prop_id': CARD, 'prop_gid': gid, 'src_pos': 2,
                'target_pos': 116001, **extra}

    def test_fresh_accounts_have_no_implicit_keychain_grant(self):
        self.assertEqual(self.state()['keychain_permissions'], [])
        fields = self.reply('CSDepositGetPropsReq', {}, _candidate_local_deposit_response)
        slots = {row['position']: row for row in fields['equiped_props']}
        self.assertEqual(slots[116].get('load_props', []), [])
        self.assertEqual(slots[116001].get('load_props', []), [])
        self.assertEqual(slots[116001].get('grid_space', []), [])
        self.assertEqual(fields.get('access_card_packs', []), [])

    def test_unverified_template_grant_rolls_back(self):
        with self.assertRaises(DomainError):
            self.backend.ensure_native_lobby_keychains(self.token,
                template_ids=[11120000011], selected_template_id=11120000011)
        self.assertEqual(self.state()['keychain_permissions'], [])

    def test_grant_is_idempotent_and_no_gid_permission_equip_uses_native_wire(self):
        item_id = self.grant()[0]
        permission = self.state()['keychain_permissions'][0]
        self.grant([item_id])
        self.assertEqual(self.state()['keychain_permissions'], [permission])
        fields = self.reply('CSDepositEquipPropReq', {'cmds': [
            {'prop_id': item_id, 'target_pos': 116}]}, _candidate_local_equip_response)
        self.assertEqual(fields['result'], 0)
        changes = fields['deposit_change']
        added = next(row for row in changes['prop_changes'] if row['change_type'] == 1)
        self.assertEqual((int(added['prop']['id']), int(added['prop']['gid'])),
                         (item_id, permission['gid']))
        position = next(row for row in changes['pos_changes'] if row['pos_id'] == 116001)
        self.assertEqual(int(position['src_prop_id']), item_id)
        self.assertEqual(position['space'], keys.grid_spaces(item_id))

    def test_main_load_has_permissions_equipped_bag_and_exact_map_spaces(self):
        item_id = self.grant()[0]
        self.backend.native_lobby_move_props(self.token, [{'prop_id': item_id, 'target_pos': 116}])
        fields = self.reply('CSDepositGetPropsReq', {}, _candidate_local_deposit_response)
        permissions = fields['access_card_packs']
        self.assertEqual([int(row['id']) for row in permissions], [item_id])
        self.assertEqual(int(permissions[0].get('expire_timestamp', 0)), 0)
        self.assertIn(permissions[0], fields['safe_and_card_pack_permission'])
        slots = {row['position']: row for row in fields['equiped_props']}
        self.assertEqual(int(slots[116]['load_props'][0]['id']), item_id)
        self.assertEqual(slots[116001]['grid_space'], keys.grid_spaces(item_id))
        self.assertEqual(slots[116001]['capacity'], sum(
            space['base_cnt'] for space in keys.grid_spaces(item_id)))
        # _FetchAllItems_Start2 clears only warehouse extension slots. Loading
        # the same keychain here would create its ordinary gid twice.
        extension = self.reply('CSDepositGetExtensionPropsReq', {}, _candidate_local_deposit_response)
        self.assertEqual(extension['result'], 0)
        self.assertEqual(extension.get('extension_slots', []), [])
        self.assertEqual(extension.get('in_extension_pages', []), [])

    def test_used_card_auto_places_in_its_source_map_and_survives_reload(self):
        item_id = self.grant(selected=int(self.bags()[0]['item_id']))[0]
        self.card()
        fields = self.reply('CSDepositEquipPropReq', {'cmds': [self.move()]},
                            _candidate_local_equip_response)
        self.assertEqual(fields['result'], 0)
        change = fields['deposit_change']['prop_changes'][0]
        self.assertEqual((change['dest']['pos'], change['dest']['space_id']), (116001, 22))
        self.assertEqual(change['prop']['health'], 3)
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        fields = self.reply('CSDepositGetPropsReq', {}, _candidate_local_deposit_response)
        slot = next(row for row in fields['equiped_props'] if row['position'] == 116001)
        self.assertEqual(int(slot['src_prop_id']), item_id)
        prop = slot['load_props'][0]
        self.assertEqual((int(prop['gid']), prop['health'], prop['loc']['space_id']), (1001, 3, 22))
        returned = self.reply('CSDepositEquipPropReq', {'cmds': [
            self.move(src_pos=116001, target_pos=2)]}, _candidate_local_equip_response)
        self.assertEqual(returned['result'], 0)
        change = returned['deposit_change']['prop_changes'][0]
        self.assertEqual(change['src']['space_id'], 22)
        self.assertEqual(change['prop']['health'], 3)

    def test_wrong_map_non_card_locked_cell_and_missing_bag_reject_atomically(self):
        self.card()
        with self.assertRaises(DomainError):
            self.backend.native_lobby_move_props(self.token, [self.move()])
        item_id = self.grant(selected=int(self.bags()[0]['item_id']))[0]
        before = self.state()
        space = next(row for row in keys.grid_spaces(item_id) if row['id'] == 22)
        for loc in ({'pos': 116001, 'space_id': 19},
                    {'pos': 116001, 'space_id': 22, 'start_x': 0,
                     'start_y': space['width']},
                    {'pos': 116001, 'space_id': 22,
                     'start_x': space['base_cnt'] % space['length'],
                     'start_y': space['base_cnt'] // space['length']}):
            with self.subTest(loc=loc), self.assertRaises(DomainError):
                self.backend.native_lobby_move_props(self.token, [self.move(spec_loc=loc)])
            self.assertEqual(self.state(), before)
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.execute('INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)',
                (1002, player_id, 14020000003, 1, 2, 1, 0, 1, 1))
            connection.commit()
        before = self.state()
        with self.assertRaises(DomainError):
            self.backend.native_lobby_move_props(self.token,
                [self.move(gid=1002, prop_id=14020000003)])
        self.assertEqual(self.state(), before)

    def test_batch_failure_rolls_back_bag_equip_and_card_move(self):
        item_id = self.grant()[0]
        self.card()
        before = self.state()
        with self.assertRaises(DomainError):
            self.backend.native_lobby_move_props(self.token, [
                {'prop_id': item_id, 'target_pos': 116}, self.move(),
                self.move(gid=99999999)])
        self.assertEqual(self.state(), before)

    def test_stacked_card_cannot_enter_keychain(self):
        self.grant(selected=int(self.bags()[0]['item_id']))
        self.card()
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_props SET quantity=2 WHERE gid=1001')
            connection.commit()
        before = self.state()
        with self.assertRaises(DomainError):
            self.backend.native_lobby_move_props(self.token, [self.move()])
        self.assertEqual(self.state(), before)

    def test_stacked_swap_target_cannot_enter_keychain(self):
        self.grant(selected=int(self.bags()[0]['item_id']))
        self.card()
        self.card(1002, 1)
        self.backend.native_lobby_move_props(self.token, [self.move()])
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_props SET quantity=2 WHERE gid=1002')
            connection.commit()
        before = self.state()
        with self.assertRaises(DomainError):
            self.backend.native_lobby_move_props(self.token, [self.move(src_pos=116001,
                target_pos=2, target_prop_id=CARD, target_prop_gid=1002,
                spec_loc={'pos': 2, 'space_id': 1, 'start_x': 1, 'start_y': 0})])
        self.assertEqual(self.state(), before)

    def test_capacity_rejects_smaller_bag_with_contents_and_preserves_health(self):
        rows = self.bags()
        small, large = rows[0], rows[-1]
        self.assertLess(small['DefaultSlotNum'], large['DefaultSlotNum'])
        small_id, large_id = int(small['item_id']), int(large['item_id'])
        self.grant([small_id, large_id], selected=large_id)
        self.card(health=0)
        index, width = small['DefaultSlotNum'], large['BoxLength']
        self.backend.native_lobby_move_props(self.token, [self.move(spec_loc={
            'pos': 116001, 'space_id': 22, 'start_x': index % width, 'start_y': index // width})])
        before = self.state()
        with self.assertRaises(DomainError):
            self.backend.native_lobby_move_props(self.token, [{'prop_id': small_id, 'target_pos': 116}])
        self.assertEqual(self.state(), before)
        self.assertEqual(next(row for row in before['props'] if row['gid'] == 1001)['health'], 0)

    def test_unowned_expired_wrong_gid_and_permission_escape_are_rejected(self):
        item_id = self.grant(selected=int(self.bags()[0]['item_id']))[0]
        permission = self.state()['keychain_permissions'][0]
        other = self.backend.register('keychain-other', 'local-password-456')['session']
        before = self.state()
        with self.assertRaises(DomainError):
            self.backend.native_lobby_move_props(other, [{'prop_id': item_id, 'target_pos': 116}])
        self.assertEqual(self.state(other)['keychain_permissions'], [])
        for command in ({'prop_id': item_id, 'prop_gid': permission['gid'] + 1, 'target_pos': 116},
                        {'prop_id': item_id, 'prop_gid': permission['gid'], 'src_pos': 116, 'target_pos': 2}):
            with self.assertRaises(DomainError):
                self.backend.native_lobby_move_props(self.token, [command])
            self.assertEqual(self.state(), before)
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_keychain_permissions SET expire_timestamp=1')
            connection.commit()
        with self.assertRaises(DomainError):
            self.backend.native_lobby_move_props(self.token, [{'prop_id': item_id, 'target_pos': 116}])

    def test_map_snapshot_uses_actual_map_id_and_rolls_back_unknown_owned_card(self):
        self.grant(selected=int(self.bags()[0]['item_id']))
        self.card()
        snapshot = {'pos': 116001, 'space': 22, 'props': [{
            'id': CARD, 'gid': 1001, 'num': 1,
            'loc': {'pos': 116001, 'space_id': 22, 'start_x': 0, 'start_y': 0}}]}
        fields = self.reply('CSDepositAssemblySyncBodyContainerReq', {'snapshots': [snapshot]},
                            _candidate_local_body_container_response)
        self.assertEqual(fields['result'], 0)
        prop = fields['deposit_change']['prop_changes'][0]['prop']
        self.assertEqual((prop['loc']['space_id'], prop['health']), (22, 3))
        before = self.state()
        invalid = {**snapshot, 'props': [{**snapshot['props'][0], 'gid': 99999999}]}
        with self.assertRaises(DomainError):
            self.backend.native_lobby_sync_body_containers(self.token, [invalid])
        self.assertEqual(self.state(), before)

    def test_full_source_map_rejects_extra_card_and_atomic_card_swap_keeps_health(self):
        item_id = self.grant(selected=int(self.bags()[0]['item_id']))[0]
        space = next(row for row in keys.grid_spaces(item_id) if row['id'] == 22)
        for index in range(space['base_cnt'] + 1):
            self.card(gid=1001 + index, x=index, health=index % 4)
        for index in range(space['base_cnt']):
            self.backend.native_lobby_move_props(self.token, [self.move(gid=1001 + index)])
        extra = 1001 + space['base_cnt']
        before = self.state()
        with self.assertRaises(DomainError):
            self.backend.native_lobby_move_props(self.token, [self.move(gid=extra)])
        self.assertEqual(self.state(), before)
        result = self.reply('CSDepositEquipPropReq', {'cmds': [self.move(gid=extra,
            target_prop_id=CARD, target_prop_gid=1001,
            spec_loc={'pos': 116001, 'space_id': 22, 'start_x': 0, 'start_y': 0})]},
            _candidate_local_equip_response)
        self.assertEqual(result['result'], 0)
        changes = result['deposit_change']['prop_changes']
        self.assertEqual(len(changes), 2)
        moved = {int(row['prop']['gid']): row for row in changes}
        self.assertEqual(moved[1001]['dest']['pos'], 2)
        self.assertEqual(moved[extra]['dest']['space_id'], 22)
        self.assertEqual(moved[1001]['prop'].get('health', 0), 0)
        self.assertEqual(moved[extra]['prop'].get('health', 0), space['base_cnt'] % 4)

    def test_same_map_card_swap_and_other_account_gid_cannot_escape(self):
        item_id = self.grant(selected=int(self.bags()[0]['item_id']))[0]
        self.card(1001, 0, 0)
        self.card(1002, 1, 3)
        for gid in (1001, 1002):
            self.backend.native_lobby_move_props(self.token, [self.move(gid=gid)])
        self.backend.native_lobby_move_props(self.token, [self.move(src_pos=116001,
            target_prop_id=CARD, target_prop_gid=1002,
            spec_loc={'pos': 116001, 'space_id': 22, 'start_x': 1, 'start_y': 0})])
        saved = {row['gid']: row for row in self.state()['props']}
        self.assertEqual((saved[1001]['x'], saved[1001]['y'], saved[1001]['health']), (22, 1, 0))
        self.assertEqual((saved[1002]['x'], saved[1002]['y'], saved[1002]['health']), (22, 0, 3))
        other = self.backend.register('keychain-other-card', 'local-password-456')['session']
        self.backend.ensure_native_lobby_keychains(other, template_ids=[item_id], selected_template_id=item_id)
        before, other_before = self.state(), self.state(other)
        with self.assertRaises(DomainError):
            self.backend.native_lobby_move_props(other, [self.move(src_pos=116001, target_pos=2)])
        self.assertEqual(self.state(), before)
        self.assertEqual(self.state(other), other_before)
        self.assertNotEqual(before['keychain_permissions'][0]['gid'], other_before['keychain_permissions'][0]['gid'])


if __name__ == '__main__':
    unittest.main()
