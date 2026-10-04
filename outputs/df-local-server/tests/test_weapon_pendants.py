import json
from pathlib import Path
import tempfile
import unittest

from dfserver.candidate_business import CandidateMessage
from dfserver.core import Backend
from dfserver.handshake_diagnostic import _candidate_codec
from dfserver import weapon_pendants


ROOT = Path(__file__).resolve().parent.parent
PENDANT = 13460030001
MYSTICAL = 13466450001
WEAPON = 18050000002
SKIN = 28050220002


class WeaponPendantTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.backend = Backend(Path(directory.name) / 'save.sqlite3', ROOT / 'definitions.json')
        self.token = self.backend.register('pendant', 'local-password-123')['session']
        with self.backend.connection() as connection:
            connection.executescript(weapon_pendants.SCHEMA)
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[
            {'gid': 1001, 'template_id': WEAPON, 'quantity': 1,
             'grid_page_id': 111, 'x': 0, 'y': 0, 'length': 4, 'width': 2},
            {'gid': 1002, 'template_id': WEAPON, 'quantity': 1,
             'grid_page_id': 111, 'x': 4, 'y': 0, 'length': 4, 'width': 2}])
        self.codec = _candidate_codec()

    def response(self, fields, name='CSWAssemblyApplySkinReq'):
        request = CandidateMessage(name, self.codec.services[name], 19, fields)
        response = weapon_pendants.response_fields(request, self.backend, self.token)
        self.assertIsNotNone(response)
        self.codec.response(request, response)
        return response

    def command(self, **fields):
        return {'weapon_id': WEAPON, 'weapon_gid': 1001, 'skin_id': SKIN,
                'pendant_id': PENDANT, **fields}

    def state(self, gid=1001):
        with self.backend.connection() as connection:
            player = self.backend._authorize(connection, self.token)
            prop = connection.execute('SELECT * FROM native_lobby_props WHERE gid=?', (gid,)).fetchone()
            return weapon_pendants.weapon_state(connection, player, prop)

    def test_catalog_ids_and_local_grants_have_independent_client_sources(self):
        items = json.loads((ROOT / 'protocol/game_item_catalog.json').read_text())['rows']
        self.assertEqual(len(weapon_pendants.PENDANTS), 283)
        self.assertEqual(len(weapon_pendants.ORDINARY), 80)
        self.assertTrue(all(str(item) in items for item in weapon_pendants.PENDANTS))
        self.assertNotIn(MYSTICAL, weapon_pendants.ORDINARY)
        self.assertIn(13460030127, weapon_pendants.PENDANTS)
        self.assertFalse(weapon_pendants.PENDANTS[13460030127]['is_mystical'])
        collection = weapon_pendants.collection(self.backend, self.token)
        self.assertEqual({row['id'] for row in collection}, weapon_pendants.ORDINARY)
        self.assertTrue(all(row['gid'] == 0 for row in collection))

    def test_equip_unequip_restart_preserves_components_bullets_and_skin(self):
        before = self.backend.native_lobby_profile(self.token)['props'][0]
        response = self.response({'data_type': 0, 'cmds': [self.command()]})
        prop = response['changes']['prop_changes'][0]['prop']
        self.assertEqual(response['result'], 0)
        self.assertEqual(prop['weapon']['pendant_id'], PENDANT)
        self.assertEqual(prop['weapon']['skin_id'], SKIN)
        self.assertEqual(prop['components'], before['components'])
        self.assertEqual(prop['weapon']['load_bullets'], before['weapon']['load_bullets'])
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        self.assertEqual(self.state(), {'pendant_id': PENDANT, 'pendant_gid': 0})
        response = self.response({'cmds': [self.command(pendant_id=0)]})
        self.assertEqual(response['result'], 0)
        self.assertEqual(self.state(), {'pendant_id': 0, 'pendant_gid': 0})
        self.assertEqual(response['changes']['prop_changes'][0]['prop']['weapon']['skin_id'], SKIN)

    def test_pendant_apply_all_is_independent_of_skin_apply_all(self):
        response = self.response({'cmds': [self.command(pendant_apply_all=True)]})
        self.assertEqual(response['result'], 0)
        self.assertEqual(self.state(1002)['pendant_id'], PENDANT)
        after = self.backend.native_lobby_profile(self.token)['props']
        self.assertEqual(after[0]['weapon']['skin_id'], SKIN)
        self.assertEqual(after[1]['weapon'].get('skin_id', 0), 0)
        with self.backend.connection() as connection:
            player = self.backend._authorize(connection, self.token)
            self.assertEqual(weapon_pendants.setups(connection, player), [
                {'weapon_id': WEAPON, 'pendant_id': PENDANT, 'pendant_gid': 0}])
        self.assertEqual(response['changes']['weapon_skin_setup'], [
            {'weapon_id': WEAPON, 'pendant_id': PENDANT, 'pendant_gid': 0}])

    def test_skin_apply_all_preserves_pendant_of_other_instances(self):
        self.response({'cmds': [self.command(weapon_gid=1002)]})
        response = self.response({'cmds': [self.command(pendant_id=0, apply_all=True)]})
        self.assertEqual(response['result'], 0)
        self.assertEqual(self.state(1001)['pendant_id'], 0)
        self.assertEqual(self.state(1002)['pendant_id'], PENDANT)

    def test_receiver_default_without_instance_and_explicit_empty_override(self):
        response = self.response({'cmds': [self.command(weapon_gid=0,
            pendant_apply_all=True, skin_id=0)]})
        self.assertEqual(response['result'], 0)
        response = self.response({'cmds': [self.command(pendant_id=0)]})
        self.assertEqual(response['result'], 0)
        self.assertEqual(self.state()['pendant_id'], 0)
        self.assertEqual(self.state(1002)['pendant_id'], PENDANT)

    def test_bow_skin_default_uses_its_recovered_receiver_without_creating_parts(self):
        before = self.backend.native_lobby_profile(self.token)['props']
        for weapon_id in (18150000001, 10150000001):
            with self.subTest(weapon_id=weapon_id):
                request = self.codec.decode(self.codec.encode('CSWAssemblyApplySkinReq', {
                    'data_type': 0, 'cmds': [{'weapon_id': weapon_id, 'skin_id': 28150150001,
                        'skin_gid': 0, 'apply_all': True, 'pendant_id': 0,
                        'pendant_gid': 0, 'pendant_apply_all': False}]}, sequence=81))
                result = weapon_pendants.response_fields(request, self.backend, self.token)
                self.codec.response(request, result)
                self.assertEqual(result['result'], 0)
                self.assertEqual(result['changes'], {'prop_changes': [], 'weapon_skin_setup': [{
                    'weapon_id': 18150000001, 'skin_id': 28150150001, 'skin_gid': 0}]})
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        profile = self.backend.native_lobby_profile(self.token)
        self.assertEqual(profile['props'], before)
        self.assertIn({'weapon_id': 18150000001, 'skin_id': 28150150001, 'skin_gid': 0},
                      profile['weapon_skin_setup'])
        cleared = self.response({'cmds': [{'weapon_id': 18150000001, 'skin_id': 0,
                                          'apply_all': True}]})
        self.assertEqual(cleared['result'], 0)
        self.assertEqual(cleared['changes']['weapon_skin_setup'], [{
            'weapon_id': 18150000001, 'skin_id': 0, 'skin_gid': 0}])
        self.assertEqual(self.backend.native_lobby_profile(self.token)['props'], before)

    def test_bow_unowned_mismatched_or_foreign_skin_does_not_write_defaults(self):
        before = self.backend.native_lobby_profile(self.token)
        for skin_id, skin_gid in ((28150130002, 0), (SKIN, 0),
                                  (28150150001, 12345), (999999, 0)):
            with self.subTest(skin_id=skin_id, skin_gid=skin_gid):
                result = self.response({'cmds': [{'weapon_id': 18150000001,
                    'skin_id': skin_id, 'skin_gid': skin_gid, 'apply_all': True}]})
                self.assertNotEqual(result['result'], 0)
                self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_bow_pendant_commands_without_recovered_attachments_rollback_batch(self):
        self.assertIn(18150000001, weapon_pendants.RECEIVERS)
        self.assertNotIn(18150000001, weapon_pendants.PENDANT_RECEIVERS)
        self.assertIn(WEAPON, weapon_pendants.PENDANT_RECEIVERS)
        before = self.backend.native_lobby_profile(self.token)
        for pendant in ({'pendant_id': PENDANT}, {'pendant_apply_all': True},
                        {'pendant_gid': 12345}):
            with self.subTest(pendant=pendant):
                result = self.response({'cmds': [self.command(), {
                    'weapon_id': 18150000001, 'skin_id': 28150150001,
                    'apply_all': True, **pendant}]})
                self.assertNotEqual(result['result'], 0)
                self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_unknown_receiver_cannot_create_an_empty_skin_default(self):
        before = self.backend.native_lobby_profile(self.token)
        result = self.response({'cmds': [{'weapon_id': 18159999999, 'skin_id': 0,
                                          'apply_all': True}]})
        self.assertNotEqual(result['result'], 0)
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_unknown_unowned_foreign_or_unrestored_instance_rejects_batch(self):
        ungranted = next(item for item, row in weapon_pendants.PENDANTS.items()
                         if not row['is_mystical'] and item not in weapon_pendants.ORDINARY)
        for bad in (self.command(pendant_id=999999), self.command(pendant_id=ungranted),
                    self.command(pendant_id=MYSTICAL, pendant_gid=12345),
                    self.command(pendant_gid=12345), self.command(weapon_gid=999999)):
            response = self.response({'cmds': [self.command(), bad]})
            self.assertNotEqual(response['result'], 0)
            self.assertEqual(self.state(), {})

    def test_normal_guid_is_zero_or_original_ui_template_id(self):
        response = self.response({'cmds': [self.command(pendant_gid=PENDANT)]})
        self.assertEqual(response['result'], 0)
        self.assertEqual(self.state()['pendant_gid'], 0)

    def test_mystical_paged_query_is_empty_without_actual_instances(self):
        response = self.response({'page': 0}, 'CSCollectionLoadMysticalPendantPropsReq')
        self.assertEqual(response, {'result': 0, 'cur_page': 0, 'sum_page': 1,
                                    'mystical_pendant_props': []})

    def test_real_mystical_instance_is_account_scoped_and_persisted(self):
        appearance = {'rarity': 1, 'wear': 100, 'unique_no': 77}
        with self.backend.connection() as connection:
            player = self.backend._authorize(connection, self.token)
            connection.execute('INSERT INTO native_lobby_pendant_instances VALUES (?,?,?,?)',
                               (player, MYSTICAL, 8001, json.dumps(appearance)))
            connection.commit()
        response = self.response({'cmds': [self.command(pendant_id=MYSTICAL, pendant_gid=8001)]})
        self.assertEqual(response['result'], 0)
        self.assertEqual(self.state(), {'pendant_id': MYSTICAL, 'pendant_gid': 8001})
        query = self.response({'page': 0}, 'CSCollectionLoadMysticalPendantPropsReq')
        self.assertEqual(query['mystical_pendant_props'][0]['mystical_pendant_data'], appearance)
        token = self.backend.register('other-pendant', 'local-password-123')['session']
        self.assertFalse(any(row['gid'] for row in weapon_pendants.collection(self.backend, token)))
        self.backend.set_native_lobby_profile(token, level=60, currencies={}, props=[
            {'gid': 2001, 'template_id': WEAPON, 'quantity': 1,
             'grid_page_id': 111, 'x': 0, 'y': 0, 'length': 4, 'width': 2}])
        self.token = token
        rejected = self.response({'cmds': [self.command(weapon_gid=2001,
            pendant_id=MYSTICAL, pendant_gid=8001)]})
        self.assertNotEqual(rejected['result'], 0)

    def test_default_update_returns_complete_combined_setup(self):
        self.response({'cmds': [self.command(apply_all=True, pendant_apply_all=True)]})
        response = self.response({'cmds': [self.command(pendant_id=0, pendant_apply_all=True)]})
        self.assertEqual(response['changes']['weapon_skin_setup'], [
            {'weapon_id': WEAPON, 'skin_id': SKIN, 'skin_gid': 0,
             'pendant_id': 0, 'pendant_gid': 0}])

    def test_nonweapon_prop_cannot_receive_a_pendant(self):
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[
            {'gid': 1001, 'template_id': 14020000003, 'quantity': 1,
             'grid_page_id': 111, 'x': 0, 'y': 0, 'length': 1, 'width': 1}])
        response = self.response({'cmds': [self.command(weapon_id=14020000003, skin_id=0)]})
        self.assertNotEqual(response['result'], 0)

    def test_unsupported_mode_and_missing_current_instance_do_not_write(self):
        for fields in ({'data_type': 1, 'cmds': [self.command()]},
                       {'cmds': [self.command(weapon_gid=0)]}, {'cmds': []}):
            self.assertNotEqual(self.response(fields)['result'], 0)
            self.assertEqual(self.state(), {})


if __name__ == '__main__':
    unittest.main()
