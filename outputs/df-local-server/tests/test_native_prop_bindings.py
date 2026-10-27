from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from dfserver.core import Backend, DomainError, POCKET_POSITION
from dfserver import native_prop_bindings as bindings
from dfserver.native_safehouse import _grant_products, _physical_product, QUEST_WEAPON_PRESETS
from dfserver.premium_shop import ITEMS


ROOT = Path(__file__).resolve().parent.parent
AMMO = 37190000001


class NativePropBindingTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.database = Path(directory.name) / 'save.sqlite3'
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.token = self.backend.register('bindings', 'local-password-123')['session']
        self.native_id = self.backend.native_identity(self.token)['native_id']
        self.provision([self.prop(1001)])

    @staticmethod
    def prop(gid, *, quantity=20, x=0, **fields):
        return {'gid': gid, 'template_id': AMMO, 'quantity': quantity,
                'grid_page_id': 2, 'x': x, 'y': 0, 'length': 1, 'width': 1, **fields}

    def provision(self, props):
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=props)

    def state(self):
        return {prop['gid']: prop for prop in self.backend.native_lobby_profile(self.token)['props']}

    def grant(self, *, bind_type=0, bind_player=0, count=5, preserve_binding=True):
        with self.backend.connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            player_id = self.backend._authorize(connection, self.token)
            result = _grant_products(self.backend, connection, player_id,
                [{'prop_id': AMMO, 'num': count, 'bind_type': bind_type, 'bind_player': bind_player}],
                preserve_binding=preserve_binding)
            connection.commit()
        return result

    def test_explicit_binding_round_trips_through_profile_and_restart(self):
        self.provision([self.prop(1001, bind_type=0, bind_player=self.native_id), self.prop(1002, x=1)])
        state = self.state()
        self.assertIn('bind_type', state[1001])
        self.assertEqual((state[1001]['bind_type'], state[1001]['bind_player']), (0, self.native_id))
        self.assertNotIn('bind_type', state[1002])
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.assertEqual(self.state(), state)

    def test_legacy_binding_uses_source_default_without_persisting_wire_fields(self):
        with self.backend.connection() as connection:
            self.assertEqual(bindings.binding(connection, 1001), (1, 0))
            self.assertEqual(bindings.persisted_fields(connection, 1001), {})
        self.assertNotIn('bind_type', self.state()[1001])

    def test_binding_api_validates_values_and_cascades_with_owned_instance(self):
        with self.backend.connection() as connection:
            for bind_type, bind_player in ((True, 0), (-1, 0), (3, 0), ('0', 0), (0, True),
                                           (0, -1), (0, 2**63), (0, '1')):
                with self.subTest(bind_type=bind_type, bind_player=bind_player), self.assertRaises(DomainError):
                    bindings.set_binding(connection, 1001, bind_type, bind_player)
            for bind_type in (0, 1, 2):
                bindings.set_binding(connection, 1001, bind_type, self.native_id)
                self.assertEqual(bindings.binding(connection, 1001), (bind_type, self.native_id))
            self.assertEqual(bindings.persisted_fields(connection, 1001),
                             {'bind_type': 2, 'bind_player': self.native_id})
            with self.assertRaises(sqlite3.IntegrityError):
                bindings.set_binding(connection, 999999, 0)
            connection.execute('DELETE FROM native_lobby_props WHERE gid=1001')
            self.assertEqual(bindings.persisted_fields(connection, 1001), {})
            connection.commit()

    def test_container_split_copies_binding_to_every_new_gid(self):
        self.provision([self.prop(1001, quantity=30, bind_type=0, bind_player=self.native_id)])
        snapshots = [{'pos': POCKET_POSITION, 'space': space, 'props': [{
            'id': AMMO, 'gid': 1001, 'num': 10, 'loc': {
                'pos': POCKET_POSITION, 'space_id': space}}]} for space in (1, 2)]
        self.backend.native_lobby_sync_body_containers(self.token, snapshots)
        state = self.state()
        self.assertEqual(sum(prop['quantity'] for prop in state.values()), 30)
        self.assertEqual(len(state), 3)
        self.assertTrue(all('bind_type' in prop for prop in state.values()))
        self.assertEqual({(prop['bind_type'], prop['bind_player']) for prop in state.values()},
                         {(0, self.native_id)})
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.assertEqual(self.state(), state)

    def test_quest_grant_does_not_merge_different_binding_or_player(self):
        self.provision([self.prop(1001), self.prop(1002, x=1, bind_type=0, bind_player=self.native_id)])
        self.grant(bind_type=0, bind_player=0)
        state = self.state()
        self.assertEqual((state[1001]['quantity'], state[1002]['quantity']), (20, 20))
        new = next(prop for gid, prop in state.items() if gid not in (1001, 1002))
        self.assertEqual((new['quantity'], new['bind_type'], new['bind_player']), (5, 0, 0))

    def test_quest_grant_merges_matching_binding_only(self):
        self.provision([self.prop(1001, bind_type=0, bind_player=self.native_id)])
        result = self.grant(bind_type=0, bind_player=self.native_id)
        self.assertEqual([row['gid'] for row in result], [1001])
        self.assertEqual(self.state()[1001]['quantity'], 25)
        self.assertEqual(self.state()[1001]['bind_player'], self.native_id)

    def test_real_11001_weapon_preset_reward_is_nonstackable_and_keeps_source_binding(self):
        from dfserver.native_quests import CATALOG
        quest = next(row for row in CATALOG['quests'] if row['QuestID'] == 11001)
        reward = next(row for row in CATALOG['rewards']
                      if row['RewardID'] in quest['RewardList'] and row['Type'] == 1)
        self.assertEqual(reward['ItemID'], 10010001050)
        # GunPreset entry 4567, root rows 1167615-1170510.
        receiver = 18010000031
        original_limit = ITEMS[str(receiver)]['max_stack_count']
        self.provision([])
        with self.backend.connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            player_id = self.backend._authorize(connection, self.token)
            for _ in range(2):
                try:
                    _grant_products(self.backend, connection, player_id, [{
                        'prop_id': reward['ItemID'], 'num': reward['Number'],
                        'bind_type': reward['bindType']}], preserve_binding=True)
                except DomainError as error:
                    self.fail('Real quest preset was rejected: ' + error.message)
            connection.commit()
        weapons = list(self.state().values())
        self.assertEqual(len(weapons), 2)
        self.assertEqual({row['template_id'] for row in weapons}, {receiver})
        self.assertTrue(all(row['quantity'] == 1 and row['bind_type'] == reward['bindType']
                            and row['components'] for row in weapons))
        expected = self.component_shape(QUEST_WEAPON_PRESETS[str(reward['ItemID'])]['prop']['components'])
        self.assertTrue(all(self.component_shape(row['components']) == expected for row in weapons))
        before = self.state()
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.assertEqual(self.state(), before)
        self.assertEqual(ITEMS[str(receiver)]['max_stack_count'], original_limit)

    @staticmethod
    def component_shape(components):
        return [(row['slot'], row['prop_data']['id'],
                 NativePropBindingTests.component_shape(row['prop_data']['components'])) for row in components]

    def test_every_verified_ordinary_quest_preset_grants_its_exact_original_tree(self):
        self.assertEqual(len(QUEST_WEAPON_PRESETS), 42)
        for preset_id, source in QUEST_WEAPON_PRESETS.items():
            with self.subTest(preset_id=preset_id):
                self.provision([])
                reward = source['reward_contexts'][0]
                with self.backend.connection() as connection:
                    connection.execute('BEGIN IMMEDIATE')
                    player_id = self.backend._authorize(connection, self.token)
                    _grant_products(self.backend, connection, player_id, [{'prop_id': int(preset_id),
                        'num': reward['number'], 'bind_type': reward['bind_type']}], preserve_binding=True)
                    connection.commit()
                weapons = list(self.state().values())
                self.assertEqual(len(weapons), reward['number'])
                for weapon in weapons:
                    self.assertEqual(weapon['template_id'], source['receiver_id'])
                    self.assertEqual(weapon['bind_type'], reward['bind_type'])
                    self.assertEqual(self.component_shape(weapon['components']),
                                     self.component_shape(source['prop']['components']))

    def test_original_zero_stack_rule_normalizes_a_copy_of_verified_receiver_metadata(self):
        receiver = QUEST_WEAPON_PRESETS['10010001050']['receiver_id']
        source = {**ITEMS[str(receiver)], 'max_stack_count': 0}
        with patch.dict(ITEMS, {str(receiver): source}):
            actual_receiver, actual_metadata = _physical_product(10010001050)
            self.assertEqual(actual_receiver, receiver)
            self.assertEqual(actual_metadata['max_stack_count'], 1)
            self.assertEqual(ITEMS[str(receiver)]['max_stack_count'], 0)

    def test_production_without_binding_policy_keeps_bound_reward_stacks_separate(self):
        self.provision([self.prop(1001, bind_type=0, bind_player=self.native_id)])
        self.grant(preserve_binding=False)
        state = self.state()
        self.assertEqual(state[1001]['quantity'], 20)
        produced = next(prop for gid, prop in state.items() if gid != 1001)
        self.assertEqual(produced['quantity'], 5)
        self.assertNotIn('bind_type', produced)

    @staticmethod
    def bullet_command(*, operation=1, bullet_gid=1001, count=17):
        return {'op_type': operation, 'bullet_id': AMMO, 'bullet_gid': bullet_gid,
                'bullet_op_num': count, 'target_gun_rec_id': 18020000003,
                'target_gun_rec_gid': 2001}

    def test_loaded_bound_ammo_survives_restart_and_unloads_into_separate_stack(self):
        self.provision([self.prop(1001, quantity=17, bind_type=0, bind_player=self.native_id),
            self.prop(1002, quantity=10, x=1), self.prop(2001, template_id=18020000003,
                quantity=1, grid_page_id=111, x=0, length=4, width=2)])
        self.backend.native_lobby_operate_bullets(self.token, [self.bullet_command()])
        loaded = self.state()[2001]['weapon']['load_bullets'][0]
        self.assertIn('bind_type', loaded)
        self.assertEqual((loaded['bind_type'], loaded['bind_player']), (0, self.native_id))
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.assertEqual(self.state()[2001]['weapon']['load_bullets'], [loaded])
        self.backend.native_lobby_operate_bullets(self.token, [self.bullet_command(
            operation=2, bullet_gid=loaded['gid'])])
        state = self.state()
        self.assertEqual(state[1002]['quantity'], 10)
        unloaded = next(prop for gid, prop in state.items() if gid not in (1002, 2001))
        self.assertEqual((unloaded['quantity'], unloaded['bind_type'], unloaded['bind_player']),
                         (17, 0, self.native_id))

    def test_partial_load_and_unload_merge_with_matching_explicit_binding(self):
        self.provision([self.prop(1001, quantity=30, bind_type=0, bind_player=self.native_id),
            self.prop(2001, template_id=18020000003, quantity=1, grid_page_id=111,
                      x=0, length=4, width=2)])
        self.backend.native_lobby_operate_bullets(self.token, [self.bullet_command()])
        loaded = self.state()[2001]['weapon']['load_bullets'][0]
        self.backend.native_lobby_operate_bullets(self.token, [self.bullet_command(
            operation=2, bullet_gid=loaded['gid'])])
        state = self.state()
        self.assertEqual(len(state), 2)
        self.assertEqual(state[1001]['quantity'], 30)
        self.assertIn('bind_type', state[1001])
        self.assertEqual((state[1001]['bind_type'], state[1001]['bind_player']), (0, self.native_id))


if __name__ == '__main__':
    unittest.main()
