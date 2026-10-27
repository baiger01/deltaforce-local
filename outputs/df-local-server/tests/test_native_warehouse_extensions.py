from pathlib import Path
import tempfile
import unittest

from dfserver.core import Backend, DomainError
from dfserver.handshake_diagnostic import _candidate_codec
from dfserver import native_warehouse_extensions as extensions
from dfserver.premium_shop import ITEMS


ROOT = Path(__file__).resolve().parent.parent
class NativeWarehouseExtensionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.backend = Backend(Path(self.directory.name) / 'save.sqlite3', ROOT / 'definitions.json')
        self.token = self.backend.register('extensions', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[])
        self.backend.set_native_lobby_devices(self.token, {1010: 2})
        with self.backend.connection() as connection:
            connection.executescript(extensions.SCHEMA)
        self.codec = _candidate_codec()

    def add_box(self, gid=9001, item_id=20010010001, x=0, y=0):
        metadata = ITEMS[str(item_id)]
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.execute('INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)',
                (gid, player_id, item_id, 1, 2, x, y, metadata['length'], metadata['width']))
            connection.commit()

    def fields(self, *, gid=9001, item_id=20010010001, operation=1, src_pos=2, dest_pos=3001):
        return {'operation': operation, 'prop_id': item_id, 'prop_gid': gid,
                'src_pos': src_pos, 'dest_pos': dest_pos}

    def operate(self, fields=None, changes=None):
        fields = self.fields() if fields is None else fields
        decoded = self.codec.decode(self.codec.encode('CSDepositOperateExtensionBoxReq', fields, sequence=11))
        result = extensions.response_fields(decoded, self.backend, self.token, changes=changes)
        self.codec.decode(self.codec.response(decoded, result))
        return result

    def state(self):
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            return extensions.installed_state(connection, player_id)

    def test_catalog_and_cap_follow_completed_warehouse_levels_only(self):
        self.assertEqual(len(extensions.BOXES), 30)
        self.assertEqual(extensions.BOXES[20010010001]['GainPosWidth'], 4)
        self.assertEqual(extensions.BOXES[20010010001]['StorableItemTypeList'], '(10,13,18)')
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            for level in range(1, 11):
                connection.execute('UPDATE native_lobby_devices SET level=? WHERE player_id=? AND device_id=1010',
                                   (level, player_id))
                cap = extensions.capacity(connection, player_id)
                self.assertEqual(cap, {'cur_extension_num': 0, 'max_extension_num': level - 1,
                                       'upperlimit_extension_num': 9})
            connection.execute('UPDATE native_lobby_devices SET level=1 WHERE device_id=1010')
            connection.execute('INSERT INTO native_lobby_safehouse_upgrades VALUES (?,1010,2,1,?)',
                               (player_id, 2**31 - 1))
            self.assertEqual(extensions.capacity(connection, player_id)['max_extension_num'], 0)

    def test_install_preserves_instance_and_projects_original_slot_and_page(self):
        self.add_box()
        changes = {}
        result = self.operate(changes=changes)
        self.assertEqual(result['result'], 0)
        self.assertEqual(result['operation'], 1)
        self.assertEqual(result['extension_pos_order'], [3001])
        self.assertEqual({name: result['changes'][name] for name in
                         ('cur_extension_num', 'max_extension_num', 'upperlimit_extension_num')},
                         {'cur_extension_num': 1, 'max_extension_num': 1, 'upperlimit_extension_num': 9})
        self.assertIn('pos_changes', result['changes'])
        position = result['changes']['pos_changes'][0]
        self.assertEqual((position['change_type'], position['pos_id']), (1, 3))
        self.assertEqual(position['space'], [{'id': 0, 'length': 9, 'width': 4}])
        moved = result['changes']['prop_changes']
        self.assertEqual(len(moved), 1)
        self.assertEqual((moved[0]['change_type'], moved[0]['src']['pos'], moved[0]['dest']['pos']),
                         (5, 2, 3001))
        self.assertEqual(int(moved[0]['prop']['gid']), 9001)
        self.assertEqual(len(changes['inventory_moves']), 1)
        state = self.state()
        slot, page = state['extension_slots'][0], state['in_extension_pages'][0]
        self.assertEqual((slot['position'], slot['load_props'][0]['gid']), (3001, 9001))
        self.assertEqual((page['grid_page_id'], page['grid_length'], page['grid_width']), (3, 9, 4))
        self.assertEqual(page['props'], [])
        self.codec.decode(self.codec.encode('CSDepositGetExtensionPropsRes',
            {'result': 0, 'extension_slots': [slot], 'in_extension_pages': [page]}, sequence=12))

    def test_missing_level_and_locked_slots_do_not_install(self):
        self.add_box()
        self.backend.set_native_lobby_devices(self.token, {1010: 1})
        self.assertNotEqual(self.operate()['result'], 0)
        self.assertEqual(self.state()['extension_slots'], [])
        self.backend.set_native_lobby_devices(self.token, {1010: 2})
        for destination in (1001, 3000, 4001, 97001, 98001):
            with self.subTest(destination=destination):
                self.assertNotEqual(self.operate(self.fields(dest_pos=destination))['result'], 0)
        self.assertEqual(self.state()['extension_slots'], [])

    def test_current_cap_rejects_extra_box_and_keeps_owned_items(self):
        self.add_box()
        self.add_box(9002, x=2)
        self.assertEqual(self.operate()['result'], 0)
        changes = {}
        self.assertNotEqual(self.operate(self.fields(gid=9002, dest_pos=4001), changes)['result'], 0)
        self.assertEqual(changes, {})
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT grid_page_id FROM native_lobby_props '
                'WHERE gid=9002').fetchone()[0], 2)

    def test_ownership_identity_real_box_and_operation_are_checked(self):
        self.add_box()
        for fields in (self.fields(operation=0), self.fields(operation=3), self.fields(src_pos=3),
                       self.fields(item_id=20010020001), self.fields(gid=2**64 - 1)):
            with self.subTest(fields=fields):
                self.assertNotEqual(self.operate(fields)['result'], 0)
        self.token = self.backend.register('extension-other', 'local-password-123')['session']
        self.assertNotEqual(self.operate()['result'], 0)
        self.assertEqual(self.state()['extension_slots'], [])

    def test_nonbox_and_special_vip_box_are_not_ordinary_installations(self):
        for index, item_id in enumerate((15020010028, 20090050001)):
            self.add_box(9100 + index, item_id=item_id, x=index * 3)
            self.assertNotEqual(self.operate(self.fields(gid=9100 + index, item_id=item_id))['result'], 0)

    def test_empty_uninstall_keeps_gid_and_returns_box_to_warehouse(self):
        self.add_box()
        self.assertEqual(self.operate()['result'], 0)
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        self.assertEqual(self.state()['extension_pos_order'], [3001])
        result = self.operate(self.fields(operation=2, src_pos=3001, dest_pos=2))
        self.assertEqual(result['result'], 0)
        self.assertEqual(result['operation'], 2)
        self.assertEqual(result['extension_pos_order'], [])
        self.assertIn('pos_changes', result['changes'])
        self.assertEqual(result['changes']['cur_extension_num'], 0)
        self.assertEqual(result['changes']['pos_changes'][0]['change_type'], 2)
        self.assertEqual(self.state()['extension_slots'], [])
        with self.backend.connection() as connection:
            saved = connection.execute('SELECT * FROM native_lobby_props WHERE gid=9001').fetchone()
            self.assertEqual((saved['grid_page_id'], saved['quantity'], saved['length'], saved['width']),
                             (2, 1, 2, 2))

    def test_nonempty_uninstall_is_rejected_without_moving_box_or_contents(self):
        self.add_box()
        self.operate()
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.execute('INSERT INTO native_lobby_props VALUES (9002,?,?,1,3,0,0,1,1)',
                               (player_id, 15020010028))
            connection.commit()
        changes = {}
        result = self.operate(self.fields(operation=2, src_pos=3001, dest_pos=2), changes)
        self.assertNotEqual(result['result'], 0)
        self.assertEqual(changes, {})
        with self.backend.connection() as connection:
            self.assertEqual([tuple(row) for row in connection.execute(
                'SELECT gid,grid_page_id FROM native_lobby_props ORDER BY gid')], [(9001, 3001), (9002, 3)])

    def test_uninstall_requires_physical_warehouse_space(self):
        self.add_box()
        self.operate()
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            columns, rows = extensions.warehouse_grid(connection, player_id, 2)
            connection.executemany('INSERT INTO native_lobby_props VALUES (?,?,?,1,2,?,?,1,1)',
                [(10000 + y * columns + x, player_id, 15020010028, x, y)
                 for y in range(rows) for x in range(columns)])
            connection.commit()
        self.assertNotEqual(self.operate(self.fields(operation=2, src_pos=3001, dest_pos=2))['result'], 0)
        self.assertEqual(self.state()['extension_pos_order'], [3001])

    def test_order_preserves_other_page_ids_after_removal(self):
        self.backend.set_native_lobby_devices(self.token, {1010: 3})
        self.add_box()
        self.add_box(9002, x=2)
        self.assertEqual(self.operate()['result'], 0)
        self.assertEqual(self.operate(self.fields(gid=9002, dest_pos=4001))['extension_pos_order'], [3001, 4001])
        self.assertEqual(self.operate(self.fields(operation=2, src_pos=3001, dest_pos=2))['extension_pos_order'], [4001])
        self.assertEqual(self.state()['extension_slots'][0]['position'], 4001)

    def test_persistence_failure_rolls_back_box_mapping_and_notifications(self):
        self.add_box()
        with self.backend.connection() as connection:
            connection.execute('CREATE TRIGGER reject_extension BEFORE INSERT ON native_lobby_warehouse_extensions '
                               'BEGIN SELECT RAISE(ABORT, "simulated extension persistence failure"); END')
            connection.commit()
        changes = {}
        self.assertNotEqual(self.operate(changes=changes)['result'], 0)
        self.assertEqual(changes, {})
        self.assertEqual(self.state()['extension_slots'], [])
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT grid_page_id FROM native_lobby_props '
                'WHERE gid=9001').fetchone()[0], 2)


if __name__ == '__main__':
    unittest.main()
