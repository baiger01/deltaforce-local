import copy
from pathlib import Path
import tempfile
import unittest

from dfserver import weapon_assembly, weapon_pendants
from dfserver.candidate_business import CandidateMessage
from dfserver.core import Backend
from dfserver.handshake_diagnostic import _candidate_codec, _native_inventory_changes
from dfserver.weapon_ammo import CATALOG, magazine_capacity, matches_ammo


ROOT = Path(__file__).resolve().parent.parent
AKM = 18010000006
AKM_BULLET = 37110100001
SKIN = 28010620001
PENDANT = 13460030001


class NativeWeaponDisplacementTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / 'save.sqlite3'
        self.backend = Backend(self.path, ROOT / 'definitions.json')
        self.token = self.backend.register('weapon-displacement', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={17020000010: 100000}, props=[
                self.prop(1001, AKM, 111, length=5, width=2),
                self.prop(1002, AKM, 2, length=5, width=2),
                self.prop(1003, AKM_BULLET, 199997, quantity=60, x=1)])
        self.assertTrue(matches_ammo(AKM, AKM_BULLET))
        self.backend.native_lobby_operate_bullets(self.token, [{
            'op_type': 1, 'bullet_id': AKM_BULLET, 'bullet_gid': 1003,
            'bullet_op_num': 20, 'target_gun_rec_id': AKM, 'target_gun_rec_gid': 1001}])
        equipped = weapon_pendants.apply(self.backend, self.token, {'data_type': 0, 'cmds': [{
            'weapon_id': AKM, 'weapon_gid': 1001, 'skin_id': SKIN, 'pendant_id': PENDANT}]})
        self.assertEqual(equipped['result'], 0)

    @staticmethod
    def prop(gid, template_id, position, *, quantity=1, x=0, length=1, width=1):
        return {'gid': gid, 'template_id': template_id, 'quantity': quantity,
                'grid_page_id': position, 'x': x, 'y': 0, 'length': length, 'width': width}

    def state(self):
        return {prop['gid']: prop for prop in self.backend.native_lobby_profile(self.token)['props']}

    def assert_displaced_state(self, moves, expected):
        move = next(move for move in moves if move['before'] and move['before']['gid'] == 1001)
        self.assertEqual(move['before']['grid_page_id'], 111)
        self.assertEqual(move['after']['grid_page_id'], 2)
        self.assertTrue(expected['components'])
        self.assertEqual(sum(row['num'] for row in expected['weapon']['load_bullets']), 20)
        self.assertEqual(expected['weapon']['skin_id'], SKIN)
        self.assertEqual(expected['weapon']['pendant_id'], PENDANT)
        for row in (move['before'], move['after']):
            self.assertIn('components', row)
            self.assertIn('weapon', row)
            self.assertEqual(row['components'], expected['components'])
            self.assertEqual(row['weapon'], expected['weapon'])

        wire = _native_inventory_changes([move])
        change = wire['prop_changes'][0]
        self.assertEqual(change['src']['pos'], 111)
        self.assertEqual(change['dest']['pos'], 2)
        self.assertEqual(change['prop']['components'], expected['components'])
        self.assertEqual(change['prop']['weapon'], expected['weapon'])
        codec = _candidate_codec()
        codec.encode('CSDepositChangeNtf', {'deposit_change': wire}, sequence=19)
        stored = self.state()[1001]
        self.assertEqual(stored['components'], expected['components'])
        self.assertEqual(stored['weapon'], expected['weapon'])
        self.backend = Backend(self.path, ROOT / 'definitions.json')
        self.assertEqual(self.state()[1001], stored)

    def test_equipment_move_returns_complete_displaced_weapon_before_and_after(self):
        expected = self.state()[1001]
        moves = self.backend.native_lobby_move_props(self.token, [{
            'prop_id': AKM, 'prop_gid': 1002, 'src_pos': 2, 'target_pos': 111,
            'target_prop_gid': 1001, 'num': 1}])
        self.assertEqual(self.state()[1002]['grid_page_id'], 111)
        self.assert_displaced_state(moves, expected)

    def test_equipped_purchase_returns_complete_displaced_weapon_before_and_after(self):
        expected = self.state()[1001]
        purchase = self.backend.native_lobby_purchase(self.token, template_id=AKM,
            quantity=1, unit_price=1000, currency_id=17020000010,
            length=5, width=2, target_position=111)
        self.assertEqual(purchase['props'][0]['grid_page_id'], 111)
        self.assertEqual(purchase['currency_delta'], -1000)
        self.assert_displaced_state(purchase['displaced_props'], expected)


class WeaponAssemblyCapacityTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / 'save.sqlite3'
        self.backend = Backend(self.path, ROOT / 'definitions.json')
        self.token = self.backend.register('assembly-capacity', 'local-password-123')['session']
        # Recovered native default slot 5: 15-round magazine; receiver base is 10.
        self.weapon_id = 18050000003
        self.bullet_id = 37140300001
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={17020000010: 100000}, props=[
                NativeWeaponDisplacementTests.prop(2001, self.weapon_id, 111, length=4, width=2),
                NativeWeaponDisplacementTests.prop(2002, self.bullet_id, 199997, quantity=60, x=1)])
        self.assertTrue(matches_ammo(self.weapon_id, self.bullet_id))
        self.assertEqual(CATALOG['weapons'][str(self.weapon_id)]['base_capacity'], 10)
        self.assertEqual(CATALOG['magazines']['13120000252']['capacity'], 15)

    def load(self, count):
        self.backend.native_lobby_operate_bullets(self.token, [{
            'op_type': 1, 'bullet_id': self.bullet_id, 'bullet_gid': 2002,
            'bullet_op_num': count, 'target_gun_rec_id': self.weapon_id, 'target_gun_rec_gid': 2001}])

    def profile(self):
        return self.backend.native_lobby_profile(self.token)

    def proposal(self):
        weapon = next(prop for prop in self.profile()['props'] if prop['gid'] == 2001)
        self.assertEqual(weapon['weapon']['magazine_capacity'], 15)
        components = copy.deepcopy(weapon['components'])
        magazine = next(part for part in components if part['slot'] == 5)
        self.assertEqual(magazine['prop_data']['id'], 13120000252)
        components.remove(magazine)
        self.assertEqual(magazine_capacity(components, self.weapon_id), 10)
        return {'prop': {'id': self.weapon_id, 'gid': 2001, 'num': 1, 'components': components},
                'data_type': 0}, magazine['prop_data']['gid']

    def reply(self, fields):
        codec = _candidate_codec()
        request = CandidateMessage('CSWAssemblyDepositPropUpdateReq',
            codec.services['CSWAssemblyDepositPropUpdateReq'], 20, fields)
        codec.encode(request.name, fields, sequence=20)
        response = weapon_assembly.response_fields(request, self.backend, self.token)
        codec.response(request, response)
        return response

    def test_loaded_rounds_above_proposed_capacity_reject_and_rollback(self):
        self.load(11)
        fields, _ = self.proposal()
        before = self.profile()
        with self.backend.connection() as connection:
            rows_before = {table: [tuple(row) for row in connection.execute(
                'SELECT * FROM ' + table + ' ORDER BY rowid')] for table in (
                    'native_lobby_props', 'native_lobby_weapon_parts',
                    'native_lobby_weapon_bullets', 'native_lobby_assembled_weapons',
                    'native_lobby_currencies')}
        response = self.reply(fields)
        self.assertNotEqual(response['result'], 0)
        self.assertIn('Unload ammunition', response['errmsg'])
        self.assertEqual(self.profile(), before)
        with self.backend.connection() as connection:
            for table, rows in rows_before.items():
                self.assertEqual([tuple(row) for row in connection.execute(
                    'SELECT * FROM ' + table + ' ORDER BY rowid')], rows)
        self.backend = Backend(self.path, ROOT / 'definitions.json')
        self.assertEqual(self.profile(), before)

    def test_loaded_rounds_equal_proposed_capacity_keep_ammo_without_materializing_model_magazine(self):
        self.load(10)
        fields, magazine_gid = self.proposal()
        before = next(prop for prop in self.profile()['props'] if prop['gid'] == 2001)
        response = self.reply(fields)
        self.assertEqual(response['result'], 0)
        state = {prop['gid']: prop for prop in self.profile()['props']}
        self.assertEqual(state[2001]['weapon']['magazine_capacity'], 10)
        self.assertEqual(state[2001]['weapon']['load_bullets'], before['weapon']['load_bullets'])
        # GameItem marks this default magazine IsModelOnly with a zero price.
        self.assertNotIn(magazine_gid, state)
        self.backend = Backend(self.path, ROOT / 'definitions.json')
        restored = {prop['gid']: prop for prop in self.profile()['props']}
        self.assertEqual(restored, state)


if __name__ == '__main__':
    unittest.main()
