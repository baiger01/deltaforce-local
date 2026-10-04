import tempfile
from pathlib import Path
import unittest

from dfserver.core import Backend, DomainError
from dfserver.local_commerce import CURRENCY_ID, inventory_location


ROOT = Path(__file__).resolve().parent.parent
CHEST = 107001
BACKPACK = 108001
CHEST_ID = 11070005004
BACKPACK_ID = 11080006004
SMALL_CHEST_ID = 11070004001
MEDICINE_ID = 14020000003


class NativeCarryingContainerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.backend = Backend(Path(self.temporary.name) / 'save.sqlite3',
                               ROOT / 'definitions.json')
        self.token = self.backend.register('carrying-test', 'local-password-123')['session']
        self.provision()

    @staticmethod
    def prop(gid, template_id, position, *, quantity=1, x=0, y=0, length=1, width=1):
        return {'gid': gid, 'template_id': template_id, 'quantity': quantity,
                'grid_page_id': position, 'x': x, 'y': y, 'length': length, 'width': width}

    def provision(self, props=None):
        if props is None:
            props = [self.prop(1001, CHEST_ID, 107),
                     self.prop(1002, MEDICINE_ID, CHEST, quantity=3, x=5, y=3),
                     self.prop(1003, BACKPACK_ID, 108),
                     self.prop(1004, MEDICINE_ID, BACKPACK, quantity=2, x=1, y=7)]
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={CURRENCY_ID: 100000}, props=props)

    def state(self):
        return {p['gid']: p for p in self.backend.native_lobby_profile(self.token)['props']}

    def move(self, gid, source, target=2, **extra):
        prop = self.state()[gid]
        return self.backend.native_lobby_move_props(self.token, [{
            'prop_id': prop['template_id'], 'prop_gid': gid, 'src_pos': source,
            'target_pos': target, 'num': prop['quantity'], 'spec_loc': {}, **extra}])

    def purchase_chest(self, template_id=SMALL_CHEST_ID):
        return self.backend.native_lobby_purchase(self.token, template_id=template_id,
            quantity=1, unit_price=100, currency_id=CURRENCY_ID, length=1, width=1,
            target_position=107)

    def fill_warehouse(self, *, leave=0):
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            for index in range(360 - leave):
                connection.execute('INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)',
                    (10000 + index, player_id, MEDICINE_ID, 1, 2, index % 9, index // 9, 1, 1))
            connection.commit()

    def receipt_count(self):
        with self.backend.connection() as connection:
            return connection.execute('SELECT COUNT(*) FROM native_lobby_container_move_receipts').fetchone()[0]

    def test_unequip_chest_evacuates_contents_with_original_wire_location(self):
        changes = self.move(1001, 107)
        state = self.state()
        self.assertEqual(state[1002]['grid_page_id'], 2)
        self.assertEqual(state[1002]['quantity'], 3)
        content = next(change for change in changes if change['after']['gid'] == 1002)
        self.assertEqual(content['before']['space_width'], 2)
        self.assertEqual(inventory_location(content['before'])['start_x'], 1)
        self.assertEqual(inventory_location(content['before'])['start_y'], 1)
        self.assertEqual({p['grid_page_id'] for p in state.values()}, {2, 108, BACKPACK})

    def test_unequip_backpack_preserves_rotation_and_occupied_dimensions(self):
        self.provision([self.prop(1003, BACKPACK_ID, 108),
                        self.prop(1004, 14020000005, BACKPACK, x=1, y=7, length=3, width=1)])
        with self.backend.connection() as connection:
            connection.execute('INSERT INTO native_lobby_prop_rotations VALUES (1004,1)')
            connection.commit()
        changes = self.move(1003, 108)
        state = self.state()
        self.assertEqual((state[1004]['grid_page_id'], state[1004]['length'], state[1004]['width']),
                         (2, 1, 3))
        self.assertTrue(state[1004]['rotated'])
        content = next(change for change in changes if change['after']['gid'] == 1004)
        self.assertEqual(content['before']['space_width'], 5)

    def test_unequip_is_atomic_when_contents_do_not_fit_warehouse(self):
        self.fill_warehouse(leave=1)
        before = self.state()
        with self.assertRaises(DomainError) as raised:
            self.move(1001, 107)
        self.assertEqual(raised.exception.code, 'WAREHOUSE_FULL')
        self.assertEqual(self.state(), before)
        self.assertEqual(self.receipt_count(), 0)

    def test_purchase_replacement_evacuates_old_layout_contents_and_returns_all_moves(self):
        result = self.purchase_chest()
        state = self.state()
        self.assertEqual(state[1002]['grid_page_id'], 2)
        self.assertEqual(state[1001]['grid_page_id'], 2)
        self.assertEqual(result['props'][0]['grid_page_id'], 107)
        self.assertEqual({change['after']['gid'] for change in result['displaced_props']}, {1001, 1002})
        content = next(change for change in result['displaced_props'] if change['after']['gid'] == 1002)
        self.assertEqual(content['before']['space_width'], 2)

    def test_purchase_replacement_rolls_back_currency_and_equipment_when_contents_do_not_fit(self):
        self.fill_warehouse(leave=1)
        before = self.state()
        currency_before = self.backend.native_lobby_profile(self.token)['currencies']
        with self.assertRaises(DomainError):
            self.purchase_chest()
        self.assertEqual(self.state(), before)
        self.assertEqual(self.backend.native_lobby_profile(self.token)['currencies'], currency_before)

    def test_equipment_move_replacement_evacuates_contents(self):
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.execute('INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)',
                (1005, player_id, SMALL_CHEST_ID, 1, 2, 0, 0, 1, 1))
            connection.commit()
        changes = self.move(1005, 2, 107)
        state = self.state()
        self.assertEqual(state[1002]['grid_page_id'], 2)
        self.assertEqual(state[1005]['grid_page_id'], 107)
        self.assertEqual({change['after']['gid'] for change in changes}, {1001, 1002, 1005})

    def test_old_source_transfer_acknowledges_only_actual_automatic_migration_once(self):
        self.move(1001, 107)
        before = self.state()
        changes = self.move(1002, CHEST)
        self.assertEqual(self.state(), before)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]['before']['grid_page_id'], CHEST)
        self.assertEqual(changes[0]['after']['grid_page_id'], 2)
        with self.assertRaises(DomainError):
            self.move(1002, CHEST)

    def test_migration_receipt_can_move_item_to_another_real_container(self):
        self.move(1001, 107)
        self.move(1002, CHEST, BACKPACK, spec_loc={'pos': BACKPACK, 'space_id': 1})
        self.assertEqual(self.state()[1002]['grid_page_id'], BACKPACK)
        self.assertEqual(self.receipt_count(), 0)

    def test_migration_receipt_rejects_other_source_and_changed_destination_state(self):
        self.move(1001, 107)
        with self.assertRaises(DomainError):
            self.move(1002, BACKPACK)
        self.move(1002, 2, 199997, spec_loc={'pos': 199997, 'space_id': 1})
        before = self.state()
        with self.assertRaises(DomainError):
            self.move(1002, CHEST)
        self.assertEqual(self.state(), before)

    def test_unknown_chest_template_cannot_replace_verified_equipment(self):
        before = self.state()
        with self.assertRaises(DomainError) as raised:
            self.purchase_chest(99999999999)
        self.assertEqual(raised.exception.code, 'INVALID_EQUIPMENT')
        self.assertEqual(self.state(), before)

    def test_corrupt_container_placement_is_rejected_before_unequipping(self):
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_props SET y=4 WHERE gid=1002')
            connection.commit()
        before = self.state()
        with self.assertRaises(DomainError) as raised:
            self.move(1001, 107)
        self.assertEqual(raised.exception.code, 'INVALID_EQUIPMENT')
        self.assertEqual(self.state(), before)

    def test_negative_flattened_coordinate_is_rejected_before_unequipping(self):
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_props SET y=-1 WHERE gid=1002')
            connection.commit()
        before = self.state()
        with self.assertRaises(DomainError):
            self.move(1001, 107)
        self.assertEqual(self.state(), before)

    def test_orphan_contents_cannot_move_without_verified_original_layout(self):
        self.provision([self.prop(1002, MEDICINE_ID, CHEST, x=5, y=3)])
        before = self.state()
        with self.assertRaises(DomainError) as raised:
            self.move(1002, CHEST)
        self.assertEqual(raised.exception.code, 'INVALID_EQUIPMENT')
        self.assertEqual(self.state(), before)

    def test_equipment_cannot_be_placed_inside_its_own_container(self):
        before = self.state()
        with self.assertRaises(DomainError):
            self.move(1001, 107, CHEST)
        self.assertEqual(self.state(), before)

    def test_fresh_equipment_cannot_reinterpret_orphan_contents(self):
        self.provision([self.prop(1002, MEDICINE_ID, CHEST, x=5, y=3)])
        before = self.state()
        with self.assertRaises(DomainError):
            self.purchase_chest()
        self.assertEqual(self.state(), before)

    def test_invalid_later_command_rolls_back_equipment_contents_and_receipts(self):
        before = self.state()
        with self.assertRaises(DomainError):
            self.backend.native_lobby_move_props(self.token, [
                {'prop_id': CHEST_ID, 'prop_gid': 1001, 'src_pos': 107,
                 'target_pos': 2, 'num': 1},
                {'prop_id': BACKPACK_ID, 'prop_gid': 1003, 'src_pos': 107,
                 'target_pos': 2, 'num': 1}])
        self.assertEqual(self.state(), before)
        self.assertEqual(self.receipt_count(), 0)

    def test_expired_receipt_cannot_authorize_a_stale_source(self):
        self.move(1001, 107)
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_container_move_receipts SET created_at=0')
            connection.commit()
        before = self.state()
        with self.assertRaises(DomainError):
            self.move(1002, CHEST)
        self.assertEqual(self.state(), before)

    def test_overlapping_contents_are_rejected_without_equipment_or_quantity_loss(self):
        self.provision([self.prop(1001, CHEST_ID, 107),
                        self.prop(1002, MEDICINE_ID, CHEST, x=5, length=2, width=2),
                        self.prop(1005, MEDICINE_ID, CHEST, x=5, y=1)])
        before = self.state()
        with self.assertRaises(DomainError):
            self.move(1001, 107)
        self.assertEqual(self.state(), before)

    def test_explicit_orphan_recovery_uses_verified_original_templates(self):
        self.provision([self.prop(1002, MEDICINE_ID, CHEST, quantity=3, x=5, y=3),
                        self.prop(1004, MEDICINE_ID, BACKPACK, quantity=2, x=1, y=7)])
        changes = self.backend.native_lobby_recover_orphaned_containers(
            self.token, original_templates={107: CHEST_ID, 108: BACKPACK_ID})
        self.assertEqual({p['grid_page_id'] for p in self.state().values()}, {2})
        self.assertEqual({change['before']['space_width'] for change in changes}, {2, 5})
        self.assertEqual(sum(p['quantity'] for p in self.state().values()), 5)

    def test_orphan_recovery_rejects_unknown_template_and_still_equipped_slot(self):
        before = self.state()
        with self.assertRaises(DomainError):
            self.backend.native_lobby_recover_orphaned_containers(
                self.token, original_templates={107: CHEST_ID})
        self.assertEqual(self.state(), before)
        self.provision([self.prop(1002, MEDICINE_ID, CHEST, x=5, y=3)])
        with self.assertRaises(DomainError):
            self.backend.native_lobby_recover_orphaned_containers(
                self.token, original_templates={107: 99999999999})

    def test_orphan_recovery_rolls_back_all_containers_when_warehouse_is_full(self):
        self.provision([self.prop(1002, MEDICINE_ID, CHEST, quantity=3, x=5, y=3),
                        self.prop(1004, MEDICINE_ID, BACKPACK, quantity=2, x=1, y=7)])
        self.fill_warehouse(leave=1)
        before = self.state()
        with self.assertRaises(DomainError):
            self.backend.native_lobby_recover_orphaned_containers(
                self.token, original_templates={107: CHEST_ID, 108: BACKPACK_ID})
        self.assertEqual(self.state(), before)

    def test_ordinary_warehouse_item_cannot_claim_a_container_source(self):
        self.provision([self.prop(1002, MEDICINE_ID, 2)])
        before = self.state()
        with self.assertRaises(DomainError):
            self.move(1002, CHEST)
        self.assertEqual(self.state(), before)


if __name__ == '__main__':
    unittest.main()
