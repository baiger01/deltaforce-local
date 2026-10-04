import copy
from pathlib import Path
import tempfile
import unittest

from dfserver.core import Backend
from dfserver.gcp_data import decode_data_frame
from dfserver.handshake_diagnostic import _candidate_codec, _candidate_local_commerce_response


ROOT = Path(__file__).resolve().parent.parent
WEAPON = 4101
BARREL = 4201
FOREGRIP = 4202
SECOND_BARREL = 4203
MEDICINE = 4104
SIGHT = 4301
DEFAULT_PARTS = (
    (4102, 1, 13030000138),
    (4103, 3, 13040000143),
    (4104, 4, 13050000201),
    (4105, 5, 13120000302),
    (4106, 2, 13020000353),
)


class NativeDragAssemblyTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.database = Path(directory.name) / 'save.sqlite3'
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.token = self.backend.register('native-drag-test', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=60,
            currencies={17020000010: 100000}, props=[
                {'gid': WEAPON, 'template_id': 18010000006, 'quantity': 1,
                 'grid_page_id': 112, 'x': 0, 'y': 0, 'length': 5, 'width': 2},
                {'gid': MEDICINE, 'template_id': 14020000005, 'quantity': 1,
                 'grid_page_id': 2, 'x': 0, 'y': 0, 'length': 1, 'width': 3},
                {'gid': BARREL, 'template_id': 13020000356, 'quantity': 1,
                 'grid_page_id': 2, 'x': 2, 'y': 9, 'length': 2, 'width': 1},
                {'gid': FOREGRIP, 'template_id': 13040000224, 'quantity': 1,
                 'grid_page_id': 2, 'x': 4, 'y': 9, 'length': 2, 'width': 1},
                {'gid': SECOND_BARREL, 'template_id': 13020000356, 'quantity': 1,
                 'grid_page_id': 2, 'x': 6, 'y': 9, 'length': 2, 'width': 1},
            ])
        # Map the trial's instance IDs to local fixture IDs. The old model socket
        # shares MEDICINE's ID, reproducing an existing save's separate namespaces.
        self.profile()
        with self.backend.connection() as connection:
            connection.execute('DELETE FROM native_lobby_weapon_parts WHERE weapon_gid=?', (WEAPON,))
            connection.executemany('INSERT INTO native_lobby_weapon_parts VALUES (?,?,?,?,?)',
                [(gid, WEAPON, WEAPON, slot, item_id) for gid, slot, item_id in DEFAULT_PARTS])
            connection.commit()
        self.codec = _candidate_codec()

    def profile(self):
        return self.backend.native_lobby_profile(self.token)

    def props(self):
        return {prop['gid']: prop for prop in self.profile()['props']}

    def snapshot(self):
        with self.backend.connection() as connection:
            return {table: [tuple(row) for row in connection.execute(
                f'SELECT * FROM {table} ORDER BY 1')]
                for table in ('native_lobby_props', 'native_lobby_weapon_parts',
                              'native_lobby_assembled_weapons', 'native_lobby_currencies',
                              'native_lobby_prop_rotations')}

    @staticmethod
    def location(x):
        return {'loc': {'pos': 2, 'start_x': x, 'start_y': 9,
                        'x': 2, 'y': 1, 'space_id': 1}}

    @staticmethod
    def component(slot, item_id, gid=None):
        prop = {'id': item_id, 'num': 1}
        if gid is not None:
            prop['gid'] = gid
        return {'slot': slot, 'prop_data': prop}

    def actual_request(self, sequence):
        # Business shapes of native trial requests 2186 and 2195. Empty protobuf
        # structs are omitted; all template IDs and socket numbers are unchanged.
        parts = [self.component(slot, item_id, gid) for gid, slot, item_id in DEFAULT_PARTS]
        if sequence == 2186:
            parts = [part for part in parts if part['slot'] not in (2, 4)]
            parts += [self.component(2, 13020000356, BARREL),
                      self.component(4, 13050000202)]
            x = 2
        else:
            parts = [part for part in parts if part['slot'] != 3]
            parts += [self.component(3, 13040000224, FOREGRIP)]
            x = 4
        return {'prop': {'id': 18010000006, 'gid': WEAPON, 'num': 1, 'components': parts},
                'unequip_pos': [self.location(x)], 'source': 4, 'swapped_peer_gun': {}}

    def apply(self, fields, sequence=2186):
        key = b'0123456789abcdef'
        message = b'ABCD' + self.codec.encode('CSWAssemblyDepositPropUpdateReq',
            fields, sequence=sequence)
        frame = _candidate_local_commerce_response(message, self.backend, self.token, key,
            header_word4=12, header_word9=sequence)
        decoded = decode_data_frame(frame, key, direction='server_to_client', compression_method=1)
        response = self.codec.decode(decoded.messages[0])
        self.assertEqual(response.name, 'CSWAssemblyDepositPropUpdateRes')
        self.assertEqual(response.sequence, sequence)
        return response.fields

    def attached(self, slot):
        return next(part['prop_data'] for part in self.props()[WEAPON]['components']
                    if part['slot'] == slot)

    def assert_no_model_inventory(self):
        self.assertFalse(any(str(prop['template_id']).startswith('13')
            and prop['template_id'] in {item_id for _, _, item_id in DEFAULT_PARTS} | {13050000202}
            for prop in self.profile()['props']))
        self.assertEqual(self.props()[MEDICINE]['template_id'], 14020000005)
        self.assertEqual(self.props()[MEDICINE]['quantity'], 1)

    def assert_reopen_unchanged(self):
        before = self.snapshot()
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.profile()
        self.assertEqual(self.snapshot(), before)

    def install_owned_barrel_fixture(self):
        with self.backend.connection() as connection:
            connection.execute('DELETE FROM native_lobby_props WHERE gid=?', (BARREL,))
            connection.execute('DELETE FROM native_lobby_weapon_parts WHERE weapon_gid=? AND slot=2',
                               (WEAPON,))
            connection.execute('INSERT INTO native_lobby_weapon_parts VALUES (?,?,?,?,?)',
                               (BARREL, WEAPON, WEAPON, 2, 13020000356))
            connection.execute('INSERT OR IGNORE INTO native_lobby_assembled_weapons VALUES (?)',
                               (WEAPON,))
            connection.commit()

    def replacing_owned_barrel(self):
        self.install_owned_barrel_fixture()
        fields = {'prop': {'id': 18010000006, 'gid': WEAPON, 'num': 1,
                          'components': copy.deepcopy(self.props()[WEAPON]['components'])},
                  'unequip_pos': [self.location(6)], 'source': 4, 'swapped_peer_gun': {}}
        part = next(part for part in fields['prop']['components'] if part['slot'] == 2)
        part['prop_data'] = {'id': 13020000356, 'gid': SECOND_BARREL, 'num': 1}
        return fields

    def model_parent_with_owned_child(self):
        # WeaponNode preset 10010000123, source offsets 129290/129869,
        # binds model-only 13050000202 to physical 13140000021 at socket 8.
        # Source export SHA256: 0075368148ad3c2ffcaec020bfee36b1ac0bacd13506af1502c744ada5b137b5.
        with self.backend.connection() as connection:
            player_id = connection.execute('SELECT player_id FROM native_lobby_props WHERE gid=?',
                                           (WEAPON,)).fetchone()[0]
            connection.execute('INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)',
                               (SIGHT, player_id, 13140000021, 1, 2, 8, 9, 1, 1))
            connection.commit()
        fields = self.actual_request(2186)
        parent = next(part for part in fields['prop']['components'] if part['slot'] == 4)
        parent['prop_data']['components'] = [self.component(8, 13140000021, SIGHT)]
        return fields

    def test_actual_barrel_drag_accepts_missing_model_gid_and_preserves_colliding_medicine(self):
        response = self.apply(self.actual_request(2186))
        self.assertEqual(response['result'], 0, response.get('errmsg'))
        self.assertEqual(self.attached(2)['gid'], BARREL)
        self.assertEqual(self.attached(4)['id'], 13050000202)
        self.assertNotIn(BARREL, self.props())
        self.assertEqual(int(response['local_prop']['gid']), WEAPON)
        self.assert_no_model_inventory()
        self.assert_reopen_unchanged()

    def test_actual_foregrip_drag_does_not_materialize_removed_model(self):
        response = self.apply(self.actual_request(2195), 2195)
        self.assertEqual(response['result'], 0, response.get('errmsg'))
        self.assertEqual(self.attached(3)['gid'], FOREGRIP)
        self.assertNotIn(FOREGRIP, self.props())
        self.assert_no_model_inventory()
        self.assert_reopen_unchanged()

    def test_owned_replacement_returns_removed_part_to_the_incoming_vacated_cell(self):
        fields = self.replacing_owned_barrel()
        response = self.apply(fields)
        self.assertEqual(response['result'], 0, response.get('errmsg'))
        self.assertEqual(self.attached(2)['gid'], SECOND_BARREL)
        self.assertNotIn(SECOND_BARREL, self.props())
        removed = self.props()[BARREL]
        self.assertEqual((removed['grid_page_id'], removed['x'], removed['y'],
                          removed['length'], removed['width']), (2, 6, 9, 2, 1))
        self.assert_no_model_inventory()
        self.assert_reopen_unchanged()

    def test_rotated_drag_return_reports_the_committed_rotation_and_persists(self):
        fields = self.replacing_owned_barrel()
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_props SET length=1,width=2 WHERE gid=?',
                               (SECOND_BARREL,))
            connection.execute('INSERT INTO native_lobby_prop_rotations VALUES (?,?)',
                               (SECOND_BARREL, 1))
            connection.commit()
        fields['unequip_pos'][0]['loc'].update(x=1, y=2, rotate=True)
        response = self.apply(fields)
        self.assertEqual(response['result'], 0, response.get('errmsg'))
        with self.backend.connection() as connection:
            removed = connection.execute(
                'SELECT p.x,p.y,p.length,p.width,r.rotated FROM native_lobby_props p '
                'JOIN native_lobby_prop_rotations r ON r.gid=p.gid WHERE p.gid=?',
                (BARREL,)).fetchone()
        self.assertEqual(tuple(removed), (6, 9, 1, 2, 1))
        self.assert_reopen_unchanged()
        change = next(change for change in response['changes']['prop_changes']
                      if int(change['prop']['gid']) == BARREL)
        self.assertTrue(change['prop']['loc']['rotate'])
        self.assertEqual((change['prop']['loc']['start_x'], change['prop']['loc']['start_y'],
                          change['prop']['loc']['x'], change['prop']['loc']['y']), (6, 9, 1, 2))

    def test_repeated_actual_foregrip_drag_does_not_create_items_or_reallocate_models(self):
        fields = self.actual_request(2195)
        response = self.apply(fields, 2195)
        self.assertEqual(response['result'], 0, response.get('errmsg'))
        before = self.snapshot()
        for sequence in (2195, 2196):
            response = self.apply(fields, sequence)
            self.assertEqual(response['result'], 0, response.get('errmsg'))
            self.assertEqual(self.snapshot(), before)
        self.assert_no_model_inventory()
        self.assert_reopen_unchanged()

    def test_source_model_parent_accepts_owned_physical_child_and_persists(self):
        fields = self.model_parent_with_owned_child()
        response = self.apply(fields)
        self.assertEqual(response['result'], 0, response.get('errmsg'))
        parent = self.attached(4)
        self.assertEqual(parent['id'], 13050000202)
        self.assertEqual([(part['slot'], part['prop_data']['id'], part['prop_data']['gid'])
                          for part in parent['components']], [(8, 13140000021, SIGHT)])
        self.assertNotIn(SIGHT, self.props())
        self.assert_no_model_inventory()
        self.assert_reopen_unchanged()

    def test_removing_model_parent_returns_owned_physical_child_without_materializing_model(self):
        response = self.apply(self.model_parent_with_owned_child())
        self.assertEqual(response['result'], 0, response.get('errmsg'))
        fields = {'prop': {'id': 18010000006, 'gid': WEAPON, 'num': 1,
                          'components': copy.deepcopy(self.props()[WEAPON]['components'])},
                  'unequip_pos': [], 'source': 4, 'swapped_peer_gun': {}}
        fields['prop']['components'] = [part for part in fields['prop']['components'] if part['slot'] != 4]
        response = self.apply(fields, 2195)
        self.assertEqual(response['result'], 0, response.get('errmsg'))
        self.assertEqual(self.props()[SIGHT]['template_id'], 13140000021)
        self.assertEqual(self.props()[SIGHT]['grid_page_id'], 2)
        self.assertFalse(any(part['slot'] == 4 for part in self.props()[WEAPON]['components']))
        self.assert_no_model_inventory()
        self.assert_reopen_unchanged()

    def test_invalid_return_locations_roll_back_the_complete_component_transaction(self):
        fields = self.replacing_owned_barrel()
        before = self.snapshot()
        bad_locations = ({'pos': 111}, {'start_x': 9}, {'start_y': 40},
                         {'start_x': 0, 'start_y': 0}, {'space_id': 2}, {'x': 1})
        for bad in bad_locations:
            with self.subTest(location=bad):
                request = copy.deepcopy(fields)
                request['unequip_pos'][0]['loc'].update(bad)
                response = self.apply(request)
                self.assertNotEqual(response['result'], 0)
                self.assertEqual(self.snapshot(), before)

    def test_unowned_or_missing_real_component_gid_rolls_back(self):
        before = self.snapshot()
        for gid in (None, 999999):
            with self.subTest(gid=gid):
                fields = self.actual_request(2195)
                part = next(part for part in fields['prop']['components'] if part['slot'] == 3)
                if gid is None:
                    part['prop_data'].pop('gid')
                else:
                    part['prop_data']['gid'] = gid
                response = self.apply(fields)
                self.assertNotEqual(response['result'], 0)
                self.assertEqual(self.snapshot(), before)

    def test_peer_weapon_operation_remains_rejected_without_any_inventory_change(self):
        fields = self.actual_request(2195)
        fields['swapped_peer_gun'] = {'id': 18010000006, 'gid': WEAPON, 'num': 1}
        before = self.snapshot()
        response = self.apply(fields)
        self.assertNotEqual(response['result'], 0)
        self.assertEqual(self.snapshot(), before)


if __name__ == '__main__':
    unittest.main()
