from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from dfserver import native_safehouse
from dfserver import weapon_components
from dfserver.core import Backend
from dfserver.handshake_diagnostic import _candidate_codec, _native_inventory_changes


ROOT = Path(__file__).resolve().parent.parent


class NativeSafehouseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.backend = Backend(Path(self.directory.name) / 'save.sqlite3', ROOT / 'definitions.json')
        self.token = self.backend.register('safehouse', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[
            {'gid': 7001, 'template_id': 15020010028, 'quantity': 3, 'grid_page_id': 2,
             'x': 0, 'y': 0, 'length': 1, 'width': 1},
            {'gid': 7002, 'template_id': 15080050023, 'quantity': 1, 'grid_page_id': 2,
             'x': 1, 'y': 0, 'length': 1, 'width': 1}])
        self.backend.set_native_lobby_devices(self.token, {1007: 1})
        with self.backend.connection() as connection:
            connection.executescript(native_safehouse.SCHEMA)
        self.codec = _candidate_codec()

    def request(self, name, fields=None, changes=None):
        request = self.codec.decode(self.codec.encode(name, fields or {}, sequence=31))
        result = native_safehouse.response_fields(request, self.backend, self.token, changes=changes)
        self.codec.decode(self.codec.response(request, result))
        if changes and changes.get('inventory_moves'):
            self.codec.encode('CSDepositChangeNtf', {'deposit_change':
                _native_inventory_changes(changes['inventory_moves'])}, sequence=32)
        return result

    def start(self, changes=None):
        return self.request('CSSafehouseProduceReq', {'device_id': 1007, 'formula_id': 372830001}, changes)

    def prepare_weapon_recipe(self):
        formula = native_safehouse.FORMULAS[100400900]
        self.backend.set_native_lobby_devices(self.token, {1002: 3})
        materials = native_safehouse._items(formula['MaterialList'])
        props = []
        for item in materials:
            metadata = native_safehouse.ITEMS[str(item['prop_id'])]
            for _ in range(item['num']):
                index = len(props)
                props.append({'gid': 8000 + index, 'template_id': item['prop_id'], 'quantity': 1,
                    'grid_page_id': 2, 'x': (index % 4) * 2, 'y': (index // 4) * 2,
                    'length': metadata['length'], 'width': metadata['width']})
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=props)
        return formula

    def start_weapon(self, changes=None):
        return self.request('CSSafehouseProduceReq', {'device_id': 1002, 'formula_id': 100400900}, changes)

    def test_real_weapon_recipe_retains_preset_and_source_timer_after_restart(self):
        formula = self.prepare_weapon_recipe()
        self.assertEqual(formula['MaterialList'], '15020040001:1;15040010021:2;15020010008:2;;')
        self.assertEqual(formula['Time'], 72000)
        changes = {}
        with patch.object(native_safehouse.time, 'time', return_value=10000000):
            result = self.start_weapon(changes)
        self.assertEqual(result['result'], 0)
        self.assertEqual(result['produce_info'], {'formula_id': 100400900, 'device_id': 1002,
            'start_time': 10000000, 'end_time': 10072000, 'pause_remain_time': 0,
            'products': [{'prop_id': 10040000900, 'num': 1, 'bind_type': 0}]})
        self.assertEqual(self.backend.native_lobby_profile(self.token)['props'], [])
        self.assertEqual(len(changes['inventory_moves']), 5)
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        queried = self.request('CSSafehouseGetInfoReq')['devices'][0]['produce_line']
        self.assertEqual(queried, result['produce_info'])
        with patch.object(native_safehouse.time, 'time', return_value=10071999):
            self.assertEqual(self.request('CSSafehouseReceiveAwardReq', {'device_id': 1002})['result'], 118005)

    def test_real_weapon_claim_delivers_receiver_and_verified_components_once(self):
        self.prepare_weapon_recipe()
        with patch.object(native_safehouse.time, 'time', return_value=10000000):
            self.assertEqual(self.start_weapon()['result'], 0)
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        changes = {}
        with patch.object(native_safehouse.time, 'time', return_value=10072000):
            claimed = self.request('CSSafehouseReceiveAwardReq', {'device_id': 1002}, changes)
        self.assertEqual(claimed['result'], 0)
        self.assertEqual([(item['prop_id'], item['num']) for item in claimed['items']], [(18040000001, 1)])
        props = self.backend.native_lobby_profile(self.token)['props']
        self.assertEqual(len(props), 1)
        weapon = props[0]
        self.assertEqual((weapon['template_id'], weapon['quantity'], weapon['length'], weapon['width']),
                         (18040000001, 1, 5, 2))
        self.assertEqual({(part['slot'], part['prop_data']['id']) for part in weapon['components']},
                         {(2, 13020000413), (1, 13030000139), (3, 13040000160), (5, 13120000269)})
        self.assertEqual(weapon['weapon']['load_bullets'], [])
        self.assertEqual([move['after']['template_id'] for move in changes['inventory_moves']], [18040000001])
        self.assertEqual(changes['inventory_moves'][0]['after']['components'], weapon['components'])
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        self.assertEqual(self.backend.native_lobby_profile(self.token)['props'], props)
        before = self.backend.native_lobby_profile(self.token)
        changes = {}
        with patch.object(native_safehouse.time, 'time', return_value=10072001):
            self.assertEqual(self.request('CSSafehouseReceiveAwardReq', {'device_id': 1002}, changes)['result'], 118005)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)
        self.assertEqual(changes, {})

    def test_real_weapon_missing_material_does_not_debit_or_create_line(self):
        self.prepare_weapon_recipe()
        with self.backend.connection() as connection:
            connection.execute('DELETE FROM native_lobby_props WHERE gid=8004')
            connection.commit()
        before = self.backend.native_lobby_profile(self.token)
        changes = {}
        self.assertEqual(self.start_weapon(changes)['result'], 118009)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)
        self.assertNotIn('produce_line', self.request('CSSafehouseGetInfoReq')['devices'][0])
        self.assertEqual(changes, {})

    def test_weapon_recipe_without_verified_component_tree_is_rejected_before_debit(self):
        self.prepare_weapon_recipe()
        before = self.backend.native_lobby_profile(self.token)
        changes = {}
        with patch.dict(weapon_components.ROWS, {}, clear=True):
            self.assertEqual(self.start_weapon(changes)['result'], 118008)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)
        self.assertNotIn('produce_line', self.request('CSSafehouseGetInfoReq')['devices'][0])
        self.assertEqual(changes, {})

    def test_weapon_claim_fragmented_warehouse_preserves_finished_line(self):
        self.prepare_weapon_recipe()
        with patch.object(native_safehouse.time, 'time', return_value=10000000):
            self.assertEqual(self.start_weapon()['result'], 0)
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.executemany('INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)', [
                (10000 + y * 9 + x, player_id, 15020010028, 1, 2, x, y, 1, 1)
                for y in range(40) for x in range(9) if x != 4])
            connection.commit()
        before = self.backend.native_lobby_profile(self.token)
        changes = {}
        with patch.object(native_safehouse.time, 'time', return_value=10072000):
            claimed = self.request('CSSafehouseReceiveAwardReq', {'device_id': 1002}, changes)
        self.assertNotEqual(claimed['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)
        self.assertEqual(changes, {})
        self.assertIn('produce_line', self.request('CSSafehouseGetInfoReq')['devices'][0])
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_weapon_parts').fetchone()[0], 0)

    def test_weapon_claim_component_failure_rolls_back_receiver_and_all_parts(self):
        self.prepare_weapon_recipe()
        with patch.object(native_safehouse.time, 'time', return_value=10000000):
            self.assertEqual(self.start_weapon()['result'], 0)
        before = self.backend.native_lobby_profile(self.token)
        ensure_parts = self.backend._ensure_weapon_parts
        calls = []

        def fail_after_component_insert(connection, player_id):
            ensure_parts(connection, player_id)
            calls.append(None)
            if len(calls) == 2:
                self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_weapon_parts').fetchone()[0], 4)
                raise sqlite3.IntegrityError('Injected failure after actual component insertion')

        changes = {}
        with patch.object(native_safehouse.time, 'time', return_value=10072000), patch.object(
                self.backend, '_ensure_weapon_parts', side_effect=fail_after_component_insert):
            claimed = self.request('CSSafehouseReceiveAwardReq', {'device_id': 1002}, changes)
        self.assertEqual(claimed['result'], 118002)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)
        self.assertEqual(changes, {})
        self.assertIn('produce_line', self.request('CSSafehouseGetInfoReq')['devices'][0])
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_lobby_weapon_parts').fetchone()[0], 0)

    def test_real_recipe_debits_materials_and_survives_restart(self):
        changes = {}
        with patch.object(native_safehouse.time, 'time', return_value=10000000):
            result = self.start(changes)
        self.assertEqual(result['result'], 0)
        info = result['produce_info']
        self.assertEqual((info['formula_id'], info['start_time'], info['end_time']),
                         (372830001, 10000000, 10027000))
        self.assertEqual(info['products'], [{'prop_id': 37280300001, 'num': 180, 'bind_type': 0}])
        props = self.backend.native_lobby_profile(self.token)['props']
        self.assertEqual([(row['template_id'], row['quantity']) for row in props], [(15020010028, 2)])
        self.assertEqual(len(changes['inventory_moves']), 2)
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        queried = self.request('CSSafehouseGetInfoReq')['devices'][0]['produce_line']
        self.assertEqual(queried, info)
        self.assertEqual(self.start()['result'], 118022)

    def test_missing_material_rolls_back_every_debit_and_line(self):
        with self.backend.connection() as connection:
            connection.execute('DELETE FROM native_lobby_props WHERE gid=7002')
            connection.commit()
        before = self.backend.native_lobby_profile(self.token)
        changes = {}
        self.assertEqual(self.start(changes)['result'], 118009)
        self.assertEqual(changes, {})
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)
        self.assertNotIn('produce_line', self.request('CSSafehouseGetInfoReq')['devices'][0])

    def test_source_device_formula_level_and_expired_date_are_enforced(self):
        before = self.backend.native_lobby_profile(self.token)
        for fields, code in (({'device_id': 1002, 'formula_id': 372830001}, 118013),
                             ({'device_id': 1007, 'formula_id': 372840001}, 118016),
                             ({'device_id': 1007, 'formula_id': 371030002}, 118088)):
            with self.subTest(fields=fields), patch.object(native_safehouse.time, 'time', return_value=1790812800):
                self.assertEqual(self.request('CSSafehouseProduceReq', fields)['result'], code)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_claim_grants_actual_product_once_after_finish(self):
        with patch.object(native_safehouse.time, 'time', return_value=10000000):
            self.assertEqual(self.start()['result'], 0)
            self.assertEqual(self.request('CSSafehouseReceiveAwardReq', {'device_id': 1007})['result'], 118005)
        changes = {}
        with patch.object(native_safehouse.time, 'time', return_value=10027001):
            result = self.request('CSSafehouseReceiveAwardReq', {'device_id': 1007}, changes)
        self.assertEqual(result['result'], 0)
        self.assertEqual(sum(row['num'] for row in result['items']), 180)
        props = self.backend.native_lobby_profile(self.token)['props']
        self.assertEqual(sum(row['quantity'] for row in props if row['template_id'] == 37280300001), 180)
        self.assertNotIn('produce_line', self.request('CSSafehouseGetInfoReq')['devices'][0])
        self.assertNotEqual(self.request('CSSafehouseReceiveAwardReq', {'device_id': 1007})['result'], 0)

    def test_claim_storage_failure_preserves_finished_line_and_no_notification(self):
        with patch.object(native_safehouse.time, 'time', return_value=10000000):
            self.start()
        before = self.backend.native_lobby_profile(self.token)
        changes = {}
        with patch.object(native_safehouse.time, 'time', return_value=10027001), patch.object(
                native_safehouse, '_grant_products', side_effect=native_safehouse.DomainError('WAREHOUSE_FULL', 'Full')):
            self.assertNotEqual(self.request('CSSafehouseReceiveAwardReq', {'device_id': 1007}, changes)['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)
        self.assertEqual(changes, {})
        self.assertIn('produce_line', self.request('CSSafehouseGetInfoReq')['devices'][0])

    def test_claim_partial_physical_grant_rolls_back_when_storage_fills(self):
        with patch.object(native_safehouse.time, 'time', return_value=10000000):
            self.assertEqual(self.start()['result'], 0)
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.executemany('INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)', [
                (10000 + y * 9 + x, player_id, 15020010028, 1, 2, x, y, 1, 1)
                for y in range(40) for x in range(9) if (x, y) not in ((0, 0), (8, 39))])
            connection.commit()
        before = self.backend.native_lobby_profile(self.token)
        changes = {}
        with patch.object(native_safehouse.time, 'time', return_value=10027001):
            result = self.request('CSSafehouseReceiveAwardReq', {'device_id': 1007}, changes)
        self.assertNotEqual(result['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)
        self.assertEqual(changes, {})
        self.assertIn('produce_line', self.request('CSSafehouseGetInfoReq')['devices'][0])

    def test_production_and_claim_are_scoped_to_owned_local_devices(self):
        with patch.object(native_safehouse.time, 'time', return_value=10000000):
            self.assertEqual(self.start()['result'], 0)
        original = self.token
        self.token = self.backend.register('other-safehouse', 'local-password-123')['session']
        self.backend.set_native_lobby_devices(self.token, {1007: 1})
        self.assertNotIn('produce_line', self.request('CSSafehouseGetInfoReq')['devices'][0])
        changes = {}
        with patch.object(native_safehouse.time, 'time', return_value=10027001):
            self.assertEqual(self.request('CSSafehouseReceiveAwardReq', {'device_id': 1007}, changes)['result'], 118005)
            self.assertEqual(self.start(changes)['result'], 118009)
        self.assertEqual(changes, {})
        self.token = original
        self.assertIn('produce_line', self.request('CSSafehouseGetInfoReq')['devices'][0])

    def test_unrecovered_product_layout_is_rejected_without_inventory_grant(self):
        item_id = 10300000002
        self.assertEqual(native_safehouse.ITEMS[str(item_id)]['length'], 0)
        self.assertNotIn(item_id, weapon_components.PRESETS)
        before = self.backend.native_lobby_profile(self.token)
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            with self.assertRaises(native_safehouse.DomainError) as error:
                native_safehouse._grant_products(self.backend, connection, player_id,
                    [{'prop_id': item_id, 'num': 1, 'bind_type': 0}])
        self.assertEqual(error.exception.code, 'SafehouseInvalidFormula')
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_native_cn_date_conversion_has_explicit_eight_hour_offset(self):
        self.assertEqual(native_safehouse._formula_timestamp('2026-04-16 00:00:00'), 1776268800)

    def test_original_cn_date_window_opens_at_its_exact_start(self):
        formula = native_safehouse.FORMULAS[371030002]
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[
            {'gid': 9000 + index, 'template_id': item['prop_id'], 'quantity': item['num'],
             'grid_page_id': 2, 'x': index, 'y': 0, 'length': 1, 'width': 1}
            for index, item in enumerate(native_safehouse._items(formula['MaterialList']))])
        fields = {'device_id': formula['DeviceId'], 'formula_id': formula['Id']}
        with patch.object(native_safehouse.time, 'time', return_value=1776268799):
            self.assertEqual(self.request('CSSafehouseProduceReq', fields)['result'], 118088)
        with patch.object(native_safehouse.time, 'time', return_value=1776268800):
            self.assertEqual(self.request('CSSafehouseProduceReq', fields)['result'], 0)


if __name__ == '__main__':
    unittest.main()
