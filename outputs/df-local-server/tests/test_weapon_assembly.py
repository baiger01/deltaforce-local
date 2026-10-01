import copy
from pathlib import Path
import tempfile
import unittest

from dfserver.core import Backend, DomainError
from dfserver import weapon_assembly
from dfserver.candidate_business import CandidateMessage
from dfserver.handshake_diagnostic import _candidate_codec
from dfserver.socket_guid import socket_path


ROOT = Path(__file__).resolve().parent.parent


class WeaponAssemblyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'save.sqlite3'
        self.backend = Backend(self.path, ROOT / 'definitions.json')
        self.token = self.backend.register('assembly-test', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={17020000010: 100000}, props=[
            {'gid': 4001, 'template_id': 18010000006, 'quantity': 1,
             'grid_page_id': 111, 'x': 0, 'y': 0, 'length': 5, 'width': 2},
            {'gid': 4002, 'template_id': 13030000138, 'quantity': 1,
             'grid_page_id': 2, 'x': 0, 'y': 0, 'length': 1, 'width': 1},
        ])

    def state(self):
        return {p['gid']: p for p in self.backend.native_lobby_profile(self.token)['props']}

    def prop(self):
        return {'id': 18010000006, 'gid': 4001, 'num': 1,
                'components': copy.deepcopy(self.state()[4001]['components'])}

    def instance_templates(self, state):
        items = {}
        def visit(part):
            self.assertNotIn(part['gid'], items)
            items[part['gid']] = part.get('id', part.get('template_id'))
            for child in part.get('components', []):
                visit(child['prop_data'])
        for prop in state.values():
            visit(prop)
        return items

    def buy_entry(self, item_id, guid, price):
        # Actual original-client AKM requests: trial sequences 1042 and 1099.
        return {'channel': 2, 'auction_prop': {'prop_id': item_id,
            'currency': 17020000010, 'price': price, 'total_num': 1,
            'assemble_info': {'pos_guid': guid, 'id': item_id,
                              'target_gid': 4001, 'num': 1}}}

    def buy(self, entries):
        codec = _candidate_codec()
        request = CandidateMessage('CSSerialCheapBuyReq', codec.services['CSSerialCheapBuyReq'], 73,
                                   {'scene': 201, 'buy_list': entries})
        codec.encode(request.name, request.fields, sequence=73)
        response = weapon_assembly.purchase_response(request, self.backend, self.token)
        codec.response(request, response)
        return response

    def attached(self, guid):
        parts = self.state()[4001]['components']
        for slot in socket_path(guid):
            child = next(part for part in parts if part['slot'] == slot)['prop_data']
            parts = child['components']
        return child

    def test_owned_part_is_installed_and_replaced_part_returned_without_loss(self):
        desired = self.prop()
        old_gid = desired['components'][0]['prop_data']['gid']
        desired['components'][0]['prop_data']['gid'] = 4002
        moves = weapon_assembly.update(self.backend, self.token, {'prop': desired})
        state = self.state()
        self.assertNotIn(4002, state)
        self.assertEqual(state[old_gid]['grid_page_id'], 2)
        self.assertEqual(state[4001]['components'][0]['prop_data']['gid'], 4002)
        self.assertEqual(len(moves), 3)
        self.backend = Backend(self.path, ROOT / 'definitions.json')
        self.assertEqual(self.state(), state)

    def test_unowned_or_duplicate_component_rolls_back(self):
        before = self.state()
        for bad_gid in (99999, 4001):
            desired = self.prop()
            desired['components'][0]['prop_data']['gid'] = bad_gid
            with self.assertRaises(DomainError):
                weapon_assembly.update(self.backend, self.token, {'prop': desired})
            self.assertEqual(self.state(), before)

    def test_removing_all_parts_does_not_recreate_defaults_on_reopen(self):
        desired = self.prop()
        desired['components'] = []
        weapon_assembly.update(self.backend, self.token, {'prop': desired})
        self.backend = Backend(self.path, ROOT / 'definitions.json')
        self.assertEqual(self.state()[4001].get('components', []), [])

    def test_failed_detach_when_warehouse_full_keeps_original_weapon(self):
        with self.backend.connection() as c:
            c.execute('UPDATE native_lobby_props SET length=9,width=40 WHERE gid=4002')
            c.commit()
        before = self.state()
        desired = self.prop()
        desired['components'] = []
        with self.assertRaises(DomainError):
            weapon_assembly.update(self.backend, self.token, {'prop': desired})
        self.assertEqual(self.state(), before)

    def test_unsupported_modes_and_peer_operations_rollback_and_encode_error(self):
        codec = _candidate_codec()
        before = self.state()
        unsupported = [{'data_type': value} for value in (1, 2, 3)] + [
            {'swapped_peer_gun': {'id': 18010000006, 'gid': 4001}},
            {'unequip_pos': [{'prop_id': 13030000138, 'prop_gid': 4002,
                              'loc': {'pos': 2}}]}]
        for fields in unsupported:
            request = CandidateMessage('CSWAssemblyDepositPropUpdateReq',
                codec.services['CSWAssemblyDepositPropUpdateReq'], 71,
                {'prop': self.prop(), **fields})
            codec.encode(request.name, request.fields, sequence=71)
            response = weapon_assembly.response_fields(request, self.backend, self.token)
            self.assertNotEqual(response['result'], 0)
            codec.response(request, response)
            self.assertEqual(self.state(), before)

    def test_update_response_echoes_context_and_contains_complete_owned_weapon(self):
        codec = _candidate_codec()
        desired = self.prop()
        desired['components'][0]['prop_data']['gid'] = 4002
        fields = {'prop': desired, 'data_type': 0, 'bag_id': 0,
                  'source': 1, 'pass_through': 'local-review', 'unequip_pos': []}
        request = CandidateMessage('CSWAssemblyDepositPropUpdateReq',
            codec.services['CSWAssemblyDepositPropUpdateReq'], 72, fields)
        codec.encode(request.name, request.fields, sequence=72)
        response = weapon_assembly.response_fields(request, self.backend, self.token)
        codec.response(request, response)
        self.assertEqual(response['result'], 0)
        for key in ('data_type', 'bag_id', 'source', 'pass_through'):
            self.assertEqual(response[key], fields[key])
        self.assertEqual(response['local_prop']['gid'], 4001)
        self.assertEqual(response['local_prop']['components'], self.state()[4001]['components'])
        self.assertEqual(response['changes']['prop_changes'][-1]['prop'], response['local_prop'])

    def test_nested_incoming_part_preserves_or_detaches_omitted_children(self):
        # These parent/child IDs and slots are native defaults for receiver 18010000016.
        for keep_child in (True, False):
            self.backend.set_native_lobby_profile(self.token, level=60,
                currencies={17020000010: 100000}, props=[
                    {'gid': 4001, 'template_id': 18010000016, 'quantity': 1,
                     'grid_page_id': 111, 'x': 0, 'y': 0, 'length': 5, 'width': 2},
                    {'gid': 4002, 'template_id': 13020000380, 'quantity': 1,
                     'grid_page_id': 2, 'x': 0, 'y': 0, 'length': 2, 'width': 1}])
            with self.backend.connection() as connection:
                connection.execute('INSERT INTO native_lobby_weapon_parts VALUES (?,?,?,?,?)',
                    (4003, 4002, 4002, 6, 13130000207))
                connection.commit()

            def owned_instances(state):
                ids = set()
                def visit(part):
                    self.assertNotIn(part['gid'], ids)
                    ids.add(part['gid'])
                    for child in part.get('components', []):
                        visit(child['prop_data'])
                for prop in state.values():
                    visit(prop)
                return ids

            before = self.state()
            original_ids = owned_instances(before)
            desired = {'id': 18010000016, 'gid': 4001, 'num': 1,
                       'components': copy.deepcopy(before[4001]['components'])}
            barrel = next(part for part in desired['components'] if part['slot'] == 2)
            previous_gid = barrel['prop_data']['gid']
            barrel['prop_data'] = {'id': 13020000380, 'gid': 4002, 'num': 1,
                'components': copy.deepcopy(before[4002]['components']) if keep_child else []}
            weapon_assembly.update(self.backend, self.token, {'prop': desired})
            after = self.state()
            self.assertEqual(owned_instances(after), original_ids)
            self.assertIn(previous_gid, after)
            self.assertNotIn(4002, after)
            if keep_child:
                attached = next(part for part in after[4001]['components'] if part['slot'] == 2)
                self.assertEqual(attached['prop_data']['components'][0]['prop_data']['gid'], 4003)
                self.assertNotIn(4003, after)
            else:
                self.assertEqual(after[4003]['template_id'], 13130000207)
                self.assertEqual(after[4003]['grid_page_id'], 2)
            self.backend = Backend(self.path, ROOT / 'definitions.json')
            self.assertEqual(self.state(), after)

    def test_actual_root_and_nested_single_purchases_install_and_persist(self):
        for item_id, guid, price in ((13430000001, 281474976710710, 1606),
                                    (13240000006, 72339069014645763, 2069)):
            before = self.instance_templates(self.state())
            response = self.buy([self.buy_entry(item_id, guid, price)])
            self.assertEqual(response['result'], 0)
            self.assertEqual(response['auction_changes']['reason'], 18)
            self.assertEqual(response['auction_changes']['currency_changes'][0]['delta'], -price)
            part = self.attached(guid)
            self.assertEqual(part['id'], item_id)
            after = self.state()
            self.assertNotIn(part['gid'], after)
            all_items = self.instance_templates(after)
            self.assertEqual(len(all_items), len(before) + 1)
            self.assertTrue(before.items() <= all_items.items())
            self.assertTrue(all(move['prop']['loc']['pos'] != 0
                                for move in response['auction_changes']['prop_changes']))
            self.backend = Backend(self.path, ROOT / 'definitions.json')
            self.assertEqual(self.state(), after)

    def test_actual_root_and_nested_batch_debits_once_without_lost_instances(self):
        before = self.instance_templates(self.state())
        entries = [self.buy_entry(13240000006, 72339069014645763, 2069),
                   self.buy_entry(13430000001, 281474976710710, 1606)]
        response = self.buy(entries)
        self.assertEqual(response['result'], 0)
        self.assertEqual(response['auction_changes']['currency_changes'], [
            {'currency_id': 17020000010, 'delta': -3675, 'current_num': 96325}])
        self.assertEqual(len(response['auction_changes']['prop_changes']), 1)
        self.assertEqual(self.attached(281474976710710)['id'], 13430000001)
        self.assertEqual(self.attached(72339069014645763)['id'], 13240000006)
        all_items = self.instance_templates(self.state())
        self.assertEqual(len(all_items), len(before) + 2)
        self.assertTrue(before.items() <= all_items.items())

    def test_batch_bad_price_target_or_guid_keeps_money_and_every_instance(self):
        before = self.backend.native_lobby_profile(self.token)
        good = self.buy_entry(13430000001, 281474976710710, 1606)
        bad_price = self.buy_entry(13240000006, 72339069014645763, 1)
        bad_target = self.buy_entry(13240000006, 72339069014645763, 2069)
        bad_target['auction_prop']['assemble_info']['target_gid'] = 999999
        bad_guid = self.buy_entry(13240000006, 0x0801000000001C03, 2069)
        missing_parent = self.buy_entry(13240000006, 0x0101000000001C35, 2069)
        for bad in (bad_price, bad_target, bad_guid, missing_parent):
            response = self.buy([good, bad])
            self.assertNotEqual(response['result'], 0)
            self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_full_warehouse_does_not_block_new_socket_but_replacement_rolls_back(self):
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_props SET length=9,width=40 WHERE gid=4002')
            connection.commit()
        entry = self.buy_entry(13430000001, 281474976710710, 1606)
        self.assertEqual(self.buy([entry])['result'], 0)
        before = self.backend.native_lobby_profile(self.token)
        response = self.buy([entry])
        self.assertNotEqual(response['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_insufficient_batch_funds_keeps_money_and_every_instance(self):
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_currencies SET amount=3674 '
                'WHERE currency_id=17020000010')
            connection.commit()
        before = self.backend.native_lobby_profile(self.token)
        response = self.buy([
            self.buy_entry(13430000001, 281474976710710, 1606),
            self.buy_entry(13240000006, 72339069014645763, 2069)])
        self.assertNotEqual(response['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_replaced_purchased_component_returns_with_same_gid(self):
        entry = self.buy_entry(13430000001, 281474976710710, 1606)
        self.assertEqual(self.buy([entry])['result'], 0)
        previous = self.attached(281474976710710)['gid']
        before = self.instance_templates(self.state())
        response = self.buy([entry])
        self.assertEqual(response['result'], 0)
        after = self.state()
        self.assertEqual(after[previous]['template_id'], 13430000001)
        self.assertEqual(after[previous]['grid_page_id'], 2)
        self.assertNotEqual(self.attached(281474976710710)['gid'], previous)
        all_items = self.instance_templates(after)
        self.assertEqual(len(all_items), len(before) + 1)
        self.assertTrue(before.items() <= all_items.items())


if __name__ == '__main__':
    unittest.main()
