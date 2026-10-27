from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from dfserver.core import Backend, DomainError
from dfserver import native_warehouse_extensions as extensions
from dfserver.local_commerce import inventory_location, CURRENCY_ID, stock_catalog
from dfserver.premium_shop import ITEMS
from dfserver import native_prop_bindings
from dfserver import native_quests, native_safehouse, native_safehouse_progress, weapon_assembly, battle_pass
from dfserver.client_errors import error_code, inventory_error
from dfserver.handshake_diagnostic import _candidate_codec


ROOT = Path(__file__).resolve().parent.parent


class WarehouseExtensionInventoryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.database = Path(self.directory.name) / 'save.sqlite3'
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.token = self.backend.register('box-inventory', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={CURRENCY_ID: 0}, props=[])
        self.backend.set_native_lobby_devices(self.token, {1010: 3})
        self.add(9001, 20030010001)
        self.add(9002, 15010010004, x=3)
        self.install()

    def add(self, gid, item, *, page=2, x=0, y=0, quantity=1):
        metadata = ITEMS[str(item)]
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.execute('INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)',
                (gid, player_id, item, quantity, page, x, y, metadata['length'], metadata['width']))
            connection.commit()

    def install(self, gid=9001, item=20030010001, slot=3001):
        with self.backend.connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            player_id = self.backend._authorize(connection, self.token)
            result = extensions.operate(self.backend, connection, player_id,
                {'operation': 1, 'prop_id': item, 'prop_gid': gid, 'src_pos': 2, 'dest_pos': slot}, {})
            connection.commit()
        self.assertEqual(result['result'], 0)

    def move(self, gid=9002, target=3, *, x=0, y=0, rotated=False, swap=None):
        command = {'prop_gid': gid, 'target_pos': target,
                   'spec_loc': {'pos': target, 'space_id': 0, 'start_x': x, 'start_y': y, 'rotate': rotated}}
        if swap:
            command['target_prop_gid'] = swap
        return self.backend.native_lobby_move_props(self.token, [command])

    def props(self):
        return {row['gid']: row for row in self.backend.native_lobby_profile(self.token)['props']}

    def test_real_collectible_move_rotate_withdraw_and_reopen(self):
        moved = self.move(x=7, y=3, rotated=True)
        loc = inventory_location(moved[0]['after'])
        self.assertEqual(loc, {'pos': 3, 'space_id': 0, 'start_x': 7, 'start_y': 3,
                               'x': 2, 'y': 1, 'rotate': True})
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        profile = self.backend.native_lobby_profile(self.token)
        state = profile['warehouse_extensions']
        self.assertEqual(state['extension_pos_order'], [3001])
        self.assertEqual(state['in_extension_pages'][0]['props'][0]['gid'], 9002)
        self.assertEqual(profile['cur_extension_num'], 1)
        self.assertEqual(profile['max_extension_num'], 2)
        self.move(target=2, x=4, y=5)
        self.assertEqual((self.props()[9002]['grid_page_id'], self.props()[9002]['length'],
                          self.props()[9002]['width']), (2, 1, 2))

    def test_type_prefix_exclusions_and_unowned_page_are_rejected(self):
        for gid, item in ((9003, 10010000019), (9004, 15050100001), (9005, 15209223101)):
            self.add(gid, item, x=gid - 9000, y=8)
            with self.subTest(item=item), self.assertRaises(DomainError):
                self.move(gid)
            self.assertEqual(self.props()[gid]['grid_page_id'], 2)
        with self.assertRaises(DomainError):
            self.move(target=4)
        other = self.backend.register('other-boxes', 'local-password-123')['session']
        with self.assertRaises(DomainError):
            self.backend.native_lobby_move_props(other, [{'prop_gid': 9002, 'target_pos': 3}])

    def test_original_category_quality_rules_and_existing_stock_price(self):
        self.assertTrue(extensions.can_store(20030010001, 15010010004))
        self.assertFalse(extensions.can_store(20030010001, 15050100001))
        self.assertFalse(extensions.can_store(20030010001, 15209223101))
        self.assertFalse(extensions.can_store(20030010001, 10010000019))
        self.assertFalse(extensions.can_store(20030050001, 15010010004))
        self.assertEqual(stock_catalog()[20030010001]['initial_guide_price'], 826875)

    def test_exact_geometry_rejects_outside_page_and_unsupported_space(self):
        before = self.props()
        for x, y, rotate in ((9, 0, False), (0, 3, False), (8, 3, True)):
            with self.subTest(x=x, y=y), self.assertRaises(DomainError):
                self.move(x=x, y=y, rotated=rotate)
        with self.assertRaises(DomainError):
            self.backend.native_lobby_move_props(self.token, [{'prop_gid': 9002, 'target_pos': 3,
                'spec_loc': {'pos': 3, 'space_id': 2}}])
        self.assertEqual(self.props(), before)

    def test_recorded_native_main_space_one_accepts_actual_chest_to_warehouse_request(self):
        self.add(9010, 11070005004, page=107)
        gid = 6400000000000000382
        self.add(gid, 14020000006, page=107001, x=5)
        codec = _candidate_codec()
        # Native trial 1792474286351322800.log, command at line668.
        command = {'prop_id': 14020000006, 'prop_gid': gid, 'src_pos': 107001,
            'target_pos': 2, 'target_prop_gid': 0, 'num': 1,
            'spec_loc': {'pos': 2, 'start_x': 4, 'start_y': 24, 'x': 2, 'y': 2, 'space_id': 1}}
        request = codec.decode(codec.encode('CSDepositEquipPropReq', {'cmds': [command]}, sequence=11))
        decoded = request.fields['cmds'][0]
        for name in ('prop_id', 'prop_gid', 'src_pos', 'target_pos', 'target_prop_gid', 'num'):
            decoded[name] = int(decoded.get(name) or 0)
        self.backend.native_lobby_move_props(self.token, [decoded])
        row = self.props()[gid]
        self.assertEqual((row['grid_page_id'], row['x'], row['y'], row['length'], row['width']),
                         (2, 4, 24, 2, 2))

    def test_native_extension_single_space_one_and_legacy_zero_are_accepted(self):
        for space, x in ((1, 2), (0, 4)):
            self.backend.native_lobby_move_props(self.token, [{'prop_gid': 9002, 'target_pos': 3,
                'spec_loc': {'pos': 3, 'space_id': space, 'start_x': x, 'start_y': 0}}])
            self.assertEqual((self.props()[9002]['grid_page_id'], self.props()[9002]['x']), (3, x))
        with self.assertRaises(DomainError):
            self.backend.native_lobby_move_props(self.token, [{'prop_gid': 9002, 'target_pos': 2,
                'spec_loc': {'pos': 2, 'space_id': 2}}])

    def test_move_receipt_reads_order_in_same_transaction_and_publishes_after_commit(self):
        self.add(9003, 20030010001, x=5)
        self.install(9003, slot=4001)
        self.backend.set_native_lobby_sort_config(self.token, {}, [4001, 3001])
        testcase = self
        class Receipt(dict):
            def update(self, *args, **kwargs):
                with testcase.backend.connection() as connection:
                    testcase.assertEqual(connection.execute('SELECT grid_page_id FROM native_lobby_props '
                                                            'WHERE gid=9002').fetchone()[0], 3)
                return super().update(*args, **kwargs)
        receipt = Receipt()
        original = extensions.installed_state
        def state(connection, player_id):
            self.assertTrue(connection.in_transaction)
            self.assertEqual(connection.execute('SELECT grid_page_id FROM native_lobby_props '
                                                'WHERE player_id=? AND gid=9002', (player_id,)).fetchone()[0], 3)
            self.assertEqual(receipt, {})
            return original(connection, player_id)
        with patch.object(extensions, 'installed_state', side_effect=state) as read_state:
            moves = self.backend.native_lobby_move_props(self.token,
                [{'prop_gid': 9002, 'target_pos': 3}], receipt=receipt)
        read_state.assert_called_once()
        self.assertIsInstance(moves, list)
        self.assertEqual((moves[0]['before']['grid_page_id'], moves[0]['after']['grid_page_id']), (2, 3))
        self.assertEqual(receipt, {'extension_pos_order': [4001, 3001]})

    def test_failed_move_batch_does_not_publish_receipt_or_any_partial_move(self):
        before = self.props()
        receipt = {}
        with self.assertRaises(DomainError):
            self.backend.native_lobby_move_props(self.token,
                [{'prop_gid': 9002, 'target_pos': 3}, {'prop_gid': 9002, 'target_pos': 4}], receipt=receipt)
        self.assertEqual(receipt, {})
        self.assertEqual(self.props(), before)

    def test_installed_physical_box_cannot_move_or_sell(self):
        with self.assertRaises(DomainError):
            self.move(9001, 2)
        with self.assertRaises(DomainError):
            self.backend.native_lobby_sell(self.token, items=[{'gid': 9001, 'template_id': 20030010001,
                'quantity': 1}], currency_id=CURRENCY_ID, total_price=0)
        self.assertEqual(self.props()[9001]['grid_page_id'], 3001)
        self.assertEqual(self.backend.native_lobby_profile(self.token)['cur_extension_num'], 1)
        with self.assertRaises(DomainError):
            self.backend.native_lobby_sync_body_containers(self.token, [{'pos': 199997, 'space': 1,
                'props': [{'id': 20030010001, 'gid': 9001, 'num': 1}]}])
        self.assertEqual(self.props()[9001]['grid_page_id'], 3001)

    def test_two_way_swap_obeys_both_box_rules(self):
        self.move()
        self.add(9003, 15010010001, x=4)
        self.move(9003, 3, x=0, y=0, swap=9002)
        rows = self.props()
        self.assertEqual((rows[9003]['grid_page_id'], rows[9002]['grid_page_id']), (3, 2))
        self.add(9004, 10010000019, x=0, y=10)
        before = self.props()
        with self.assertRaises(DomainError):
            self.move(9003, 2, x=0, y=10, swap=9004)
        self.assertEqual(self.props(), before)

    def test_full_box_and_later_batch_failure_roll_back(self):
        for index in range(36):
            self.add(9100 + index, 15010010001, page=3, x=index % 9, y=index // 9)
        before = self.props()
        with self.assertRaises(DomainError):
            self.move()
        self.assertEqual(self.props(), before)
        with self.assertRaises(DomainError):
            self.backend.native_lobby_move_props(self.token, [
                {'prop_gid': 9100, 'target_pos': 2}, {'prop_gid': 9002, 'target_pos': 4}])
        self.assertEqual(self.props(), before)

    def test_stack_merge_preserves_remainder_and_binding(self):
        self.add(9003, 15200000073, x=4, quantity=20)
        self.add(9004, 15200000073, page=3, x=0, quantity=50)
        changes = self.move(9003, swap=9004)
        self.assertEqual(self.props()[9003]['quantity'], 10)
        self.assertEqual(self.props()[9003]['grid_page_id'], 2)
        self.assertEqual(self.props()[9004]['quantity'], 60)
        self.assertEqual(len(changes), 2)
        self.add(9005, 15200000073, x=5, quantity=5)
        self.add(9006, 15200000073, page=3, x=1, quantity=3)
        changes = self.move(9005, x=1, swap=9006)
        self.assertNotIn(9005, self.props())
        self.assertTrue(any(move['after'] is None for move in changes))
        self.assertEqual(self.props()[9006]['quantity'], 8)

    def test_different_binding_stacks_swap_without_combining(self):
        self.add(9003, 15200000073, x=4, quantity=5)
        self.add(9004, 15200000073, page=3, quantity=10)
        with self.backend.connection() as connection:
            native_prop_bindings.set_binding(connection, 9003, 0, 17)
            native_prop_bindings.set_binding(connection, 9004, 0, 18)
            connection.commit()
        self.move(9003, swap=9004)
        rows = self.props()
        self.assertEqual((rows[9003]['grid_page_id'], rows[9003]['quantity'], rows[9003]['bind_player']), (3, 5, 17))
        self.assertEqual((rows[9004]['grid_page_id'], rows[9004]['quantity'], rows[9004]['bind_player']), (2, 10, 18))

    def test_real_installed_slot_order_and_extension_sort_persist(self):
        self.add(9003, 20030010001, x=4)
        self.install(9003, slot=4001)
        self.move(x=8, y=2)
        self.backend.set_native_lobby_sort_config(self.token, {'sort_style': 1}, [4001, 3001])
        self.backend.native_lobby_sort_positions(self.token, [3])
        self.assertEqual(self.props()[9002]['grid_page_id'], 3)
        self.assertLess(self.props()[9002]['y'], 4)
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.assertEqual(self.backend.native_lobby_profile(self.token)['extension_pos_order'], [4001, 3001])
        for order in ([3, 4], [3001], [3001, 3001], [3001, 98001]):
            with self.subTest(order=order), self.assertRaises(DomainError):
                self.backend.set_native_lobby_sort_config(self.token, {}, order)

    def test_purchase_move_sort_and_uninstall_share_the_current_main_geometry(self):
        self.move()
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            columns, main_rows = extensions.warehouse_grid(connection, player_id, 2)
            connection.executemany('INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)',
                [(10000 + index, player_id, 15010010001, 1, 2, index % columns, index // columns, 1, 1)
                 for index in range(columns * main_rows)])
            connection.execute('UPDATE native_lobby_currencies SET amount=1000 WHERE player_id=?', (player_id,))
            connection.commit()
        original = extensions.warehouse_grid
        def dimensions(connection, player_id, page):
            return (columns, main_rows + 5) if page == 2 else original(connection, player_id, page)
        # The geometry stub tests the callers; it does not create a client configuration row.
        with patch.object(extensions, 'warehouse_grid', side_effect=dimensions):
            bought = self.backend.native_lobby_purchase(self.token, template_id=15010010001,
                quantity=1, unit_price=1, currency_id=CURRENCY_ID, length=1, width=1)
            self.assertEqual(bought['props'][0]['y'], main_rows)
            item = {'template_id': 15010010001, 'quantity': 1, 'unit_price': 1,
                    'length': 1, 'width': 1, 'max_stack_count': 1, 'target_position': 2}
            for method in (self.backend.native_lobby_purchase_warehouse_batch,
                           self.backend.native_lobby_purchase_container_batch):
                result = method(self.token, items=[item], currency_id=CURRENCY_ID)
                self.assertEqual(result['props'][0]['y'], main_rows)
            self.move(target=2, x=3, y=main_rows)
            self.backend.native_lobby_sort_positions(self.token, [2])
            self.assertTrue(any(row['y'] >= main_rows for row in self.props().values() if row['grid_page_id'] == 2))
            with self.backend.connection() as connection:
                connection.execute('BEGIN IMMEDIATE')
                player_id = self.backend._authorize(connection, self.token)
                result = extensions.operate(self.backend, connection, player_id,
                    {'operation': 2, 'prop_id': 20030010001, 'prop_gid': 9001,
                     'src_pos': 3001, 'dest_pos': 2}, {})
                connection.commit()
            self.assertEqual(result['result'], 0)
            self.assertGreaterEqual(self.props()[9001]['y'], main_rows)

    def test_quest_and_upgrade_submission_guard_installed_instance_before_consumption(self):
        self.move()
        before = self.props()
        quest = native_quests.QUESTS[20904]
        objectives = {ident: {'quest_objective_id': ident, 'value': 0, 'has_completed': False}
                      for ident in quest['ObjectiveList']}
        with self.backend.connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            player_id = self.backend._authorize(connection, self.token)
            with self.assertRaises(DomainError) as caught:
                native_quests._submit(connection, player_id, quest, objectives,
                    {'submit_list': [{'obj_id': 2090401, 'submit_props': [
                        {'id': 15060080003, 'gid': 9001, 'num': 1, 'position': 3001}]}]})
            self.assertEqual(caught.exception.code, 'DepositExtensionOperInvalid')
            required = native_safehouse_progress._pairs(native_safehouse_progress.UPGRADES[(1010, 4)]['ItemList'])
            material = next(item for item in required if not ITEMS[str(item)]['is_currency'])
            with self.assertRaises(DomainError) as caught:
                native_safehouse_progress._submit(connection, player_id, {'device_id': 1010,
                    'submit_prop_list': [{'id': material, 'gid': 9001, 'num': 1, 'position': 3001}]})
            self.assertEqual(caught.exception.code, 'DepositExtensionOperInvalid')
            connection.rollback()
        self.assertEqual(self.props(), before)
        self.assertFalse(any(row['value'] for row in objectives.values()))

    def test_automatic_material_selection_counts_only_uninstalled_physical_boxes(self):
        self.move()
        self.add(9003, 20030010001, x=4)
        before = self.props()
        with self.backend.connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            player_id = self.backend._authorize(connection, self.token)
            with self.assertRaises(DomainError) as caught:
                native_safehouse._consume(connection, player_id,
                    [{'prop_id': 15010010004, 'num': 1}, {'prop_id': 20030010001, 'num': 2}])
            self.assertEqual(caught.exception.code, 'SafehouseDelMaterialFail')
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_props '
                             'WHERE template_id=20030010001').fetchone()[0], 2)
            native_safehouse._consume(connection, player_id, [{'prop_id': 20030010001, 'num': 1}])
            connection.commit()
        rows = self.props()
        self.assertEqual(rows[9001], before[9001])
        self.assertEqual(rows[9002], before[9002])
        self.assertNotIn(9003, rows)
        self.assertEqual(self.backend.native_lobby_profile(self.token)['cur_extension_num'], 1)

    def test_other_physical_grant_and_removed_component_boundaries_use_current_geometry(self):
        self.move()
        with self.backend.connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            player_id = self.backend._authorize(connection, self.token)
            columns, main_rows = extensions.warehouse_grid(connection, player_id, 2)
            connection.executemany('INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)',
                [(10000 + index, player_id, 15010010001, 1, 2, index % columns, index // columns, 1, 1)
                 for index in range(columns * main_rows)])
            original = extensions.warehouse_grid
            def dimensions(connection, player_id, page):
                return (columns, main_rows + 5) if page == 2 else original(connection, player_id, page)
            with patch.object(extensions, 'warehouse_grid', side_effect=dimensions):
                self.assertEqual(weapon_assembly._warehouse_cell(connection, player_id, 1, 1, (0, main_rows)), (0, main_rows))
                self.assertEqual(weapon_assembly._warehouse_cell(connection, player_id, 1, 1), (0, main_rows))
                products = native_safehouse._items(native_safehouse.FORMULAS[372830001]['ProductList'])
                granted = native_safehouse._grant_products(self.backend, connection, player_id, products)
                for row in granted:
                    self.assertGreaterEqual(connection.execute('SELECT y FROM native_lobby_props WHERE gid=?',
                                                               (row['gid'],)).fetchone()[0], main_rows)
                changes = {'deposit_changes': []}
                battle_pass._warehouse_grant(self.backend, connection, player_id,
                    {'id': 15010010001, 'num': 1}, ITEMS['15010010001'], changes)
                self.assertGreaterEqual(changes['deposit_changes'][0]['dest']['start_y'], main_rows)
            connection.rollback()

    def test_inventory_error_preserves_only_declared_deposit_error_names(self):
        self.assertEqual(inventory_error(DomainError('DepositExtensionOperInvalid', 'installed')),
                         error_code('DepositExtensionOperInvalid'))
        self.assertEqual(inventory_error(DomainError('DepositUnknownLocalName', 'unknown')),
                         error_code('DepositInternalError'))


if __name__ == '__main__':
    unittest.main()
