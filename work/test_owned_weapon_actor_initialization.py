"""Actual EmptyHand layout vectors and immutable admission initialization."""
from dataclasses import replace
import hashlib
import json
import unittest

from dfserver.legacy_ds_bit_archive import BitReader
from dfserver.legacy_ds_match_admission import LocalMatchTicket
import portable_map_owned_weapon as producer
import owned_weapon_values_codec as values
from test_portable_map_inventory import frozen


def ticket(cookie='0123456789abcdef'):
    document = frozen()
    document['selected_hero_id'] = 88000000025
    document['selected_fashion_id'] = 30000060007
    raw = json.dumps(document, sort_keys=True).encode()
    return LocalMatchTicket(123, 321, 2201, 1, 88000000025, cookie, 0.0, 120.0,
        30000060007, 73, raw)


class OwnedWeaponActorInitializationTests(unittest.TestCase):
    def binding(self):
        loader = getattr(values, 'actor_schema_binding', None)
        self.assertTrue(callable(loader), 'Actor initialization needs its actual layout schema')
        return loader()

    def build(self, value=None, **changes):
        factory = getattr(producer, 'empty_hand_initialization', None)
        self.assertTrue(callable(factory), 'The portable EmptyHand initialization producer is missing')
        kwargs = dict(pawn_guid=2, weapon_guid=100, manager_component_guid=12,
            replicate_component_guid=14, weapon_slot=0, pawn_open_acknowledged=True,
            weapon_open_acknowledged=True, initial_state_is_fresh=True,
            manager_binding_snapshot_complete=True, used_unique_ids=(), activate_empty_hand=False)
        kwargs.update(changes)
        return factory(ticket() if value is None else value, **kwargs)

    def test_missing_business_slot_keeps_source_closed_actor_and_manager_subset(self):
        try:
            result = self.build(weapon_slot=None)
        except ValueError as error:
            self.fail('The qualified Actor/manager subset must not require a fabricated slot: '+str(error))
        self.assertEqual([s.name for s in result.stages],
            ['weapon_actor', 'replicate_owner', 'manager_bindings'])
        self.assertIsNone(result.pair)
        self.assertGreater(result.unique_id, 0)
        self.assertFalse(result.qualification['weapon_info_created'])
        self.assertIsNone(result.qualification['weapon_slot_origin'])
        with self.assertRaises(ValueError):
            self.build(weapon_slot=None, activate_empty_hand=True)

    def test_actor_state_is_not_an_empty_probe(self):
        result = self.build()
        body = result.stages[0].actor_content
        reader = BitReader(body.payload, bit_count=body.payload_bit_count)
        self.assertFalse(reader.read_bool())
        # These are current BP_EmptyHand_C layout handles, not ClassNetCache indices.
        def fields(rows):
            for handle, value, width in rows:
                self.assertEqual(reader.read_packed_int(), handle)
                self.assertEqual(reader.read_packed_int() if width == 'packed' else reader.read_bits(width), value)
        fields(((6, 1, 2), (14, 2, 'packed'), (17, result.weapon_rec_id, 64), (20, 0, 8)))
        # ModularReplicateInfo: one recipe-less root node, required by the
        # client ready gate before it initializes first/third person.
        self.assertEqual(reader.read_packed_int(), 36)
        self.assertEqual(reader.read_bits(16), 1)
        # Root node: all PartsDataRow ids are the client default row's zeros.
        fields(((1, result.weapon_rec_id, 64), (8, result.weapon_rec_id, 64), (9, 1, 7)))
        self.assertEqual(reader.read_packed_int(), 11)  # SocketName None
        self.assertTrue(reader.read_bool())
        self.assertEqual(reader.read_packed_int(), 0)
        fields(((12, 0xffffffff, 32),))
        self.assertEqual(reader.read_packed_int(), 13)  # no child sockets
        self.assertEqual(reader.read_bits(16), 0)
        self.assertEqual(reader.read_packed_int(), 0)
        fields(((14, 1, 8), (16, (1 << 63)-1, 64), (18, 1, 8), (21, 1, 3)))
        self.assertEqual(reader.read_packed_int(), 23)  # FunctionIds == (0,)
        self.assertEqual(reader.read_bits(16), 1)
        fields(((1, 0, 64),))
        self.assertEqual(reader.read_packed_int(), 0)
        self.assertEqual(reader.read_packed_int(), 35)  # bDefaultMergeMesh
        self.assertTrue(reader.read_bool())
        self.assertEqual(reader.read_packed_int(), 0)
        self.assertEqual(reader.read_packed_int(), 37)
        self.assertEqual(reader.read_bits(64), 0)
        self.assertEqual(reader.read_packed_int(), 38)
        self.assertEqual(reader.read_bits(32), 1)  # native default skin
        fields(((40, result.pair.unique_id, 32), (41, 2, 'packed')))
        self.assertEqual(reader.read_packed_int(), 0)
        self.assertEqual(reader.remaining, 0)
        self.assertGreater(body.payload_bit_count, 9)

    def test_current_schema_is_reproducible_and_has_no_process_pointers(self):
        from export_owned_weapon_actor_schema import derive
        schema = self.binding()
        self.assertEqual(derive(), schema)
        self.assertEqual(schema['actor']['cache_exclusive_maximum'], 58)
        self.assertEqual(schema['actor']['fields']['ServerWeaponIdentity']['inner_handle'], 40)
        self.assertEqual(schema['actor']['fields']['WeaponID']['wire_bits'], 64)
        self.assertEqual(schema['actor']['fields']['Owner']['ordinary_handle'], 14)
        self.assertEqual(schema['empty_hand']['rec_id_origin'], 'source_packaged_gp_weapon_globals')
        serialized = json.dumps(schema)
        for private_key in ('descriptor_address', 'driver_address', 'class_key', 'pid', 'created_at'):
            self.assertNotIn('"'+private_key+'"', serialized)

    def test_default_stages_bind_identity_without_overriding_carried_active_weapon(self):
        result = self.build()
        self.assertEqual([s.name for s in result.stages],
            ['weapon_actor', 'replicate_owner', 'manager_bindings', 'weapon_info'])
        self.assertEqual([s.after_stage for s in result.stages], [None, 0, 1, 2])
        self.assertEqual(result.stages[0].required_open_guids, (2, 100))
        self.assertEqual(result.stages[0].actor_guid, 100)
        self.assertEqual([s.updates[0].name for s in result.stages[1:]],
            ['WeaponReplicate', 'WeaponManager', 'WeaponReplicate'])
        self.assertFalse(result.stages[3].updates[0].has_rep_layout)
        self.assertFalse(result.qualification['active_weapon_overridden'])
        self.assertTrue(result.qualification['manager_complete_lists_replaced'])
        self.assertFalse(result.qualification['native_gameplay_verified'])

    def test_same_ticket_replays_same_identity_but_new_ticket_has_new_namespace(self):
        first, retry = self.build(), self.build()
        self.assertEqual(first, retry)
        self.assertNotEqual(first.pair.unique_id, self.build(ticket('different-cookie')).pair.unique_id)
        collision = self.build(used_unique_ids=(first.pair.unique_id,))
        self.assertNotEqual(first.pair.unique_id, collision.pair.unique_id)
        self.assertEqual(first.qualification['snapshot_sha256'], hashlib.sha256(ticket().loadout_snapshot).hexdigest())
        self.assertNotIn('0123456789abcdef', json.dumps(first.qualification))

    def test_explicit_active_stage_reuses_exact_created_identity(self):
        result = self.build(activate_empty_hand=True)
        self.assertEqual(result.stages[-1].name, 'active_empty_hand')
        self.assertEqual(result.stages[-1].after_stage, 3)
        self.assertTrue(result.qualification['active_weapon_overridden'])
        self.assertEqual(result.pair.common_class_id, self.binding()['empty_hand']['common_class_id'])

    def test_actor_optional_inventory_gid_is_not_replaced_by_local_identity(self):
        block = values.build_weapon_actor_initial_content(self.binding(), pawn_guid=2,
            unique_id=77, weapon_rec_id=18110000000, inventory_gid=6400000000000000059,
            equip_position=112, pawn_open_acknowledged=True)
        reader = BitReader(block.payload, bit_count=block.payload_bit_count)
        self.assertFalse(reader.read_bool())
        for handle, value, bits in ((6, 1, 2), (14, 2, None), (17, 18110000000, 64),
                (18, 6400000000000000059, 64), (19, 112, 32), (40, 77, 32), (41, 2, None)):
            self.assertEqual(reader.read_packed_int(), handle)
            self.assertEqual(reader.read_packed_int() if bits is None else reader.read_bits(bits), value)
        self.assertEqual(reader.read_packed_int(), 0)
        self.assertEqual(reader.remaining, 0)

    def test_carried_weapon_selection_is_not_fabricated_or_activated(self):
        document = frozen()
        document.update(selected_hero_id=ticket().selected_hero_id,
            selected_fashion_id=ticket().selected_fashion_id)
        document['props'][0]['weapon'] = {'native_mapping_not_recovered': True}
        value = replace(ticket(), loadout_snapshot=json.dumps(document).encode())
        result = self.build(value, weapon_slot=None)
        self.assertFalse(result.qualification['carried_weapon_actor_selection_qualified'])
        self.assertEqual(result.qualification['carried_gun_count'], 1)
        with self.assertRaises(ValueError):
            self.build(value, activate_empty_hand=True)

    def test_changed_actor_schema_cannot_change_a_wire_handle(self):
        from copy import deepcopy
        schema = deepcopy(self.binding())
        schema['actor']['fields']['Owner']['ordinary_handle'] = 15
        with self.assertRaises(ValueError):
            self.build(actor_schema=schema)

    def test_unacknowledged_or_cross_admission_inputs_are_refused(self):
        for changes in (dict(pawn_open_acknowledged=False), dict(weapon_open_acknowledged=False),
                dict(weapon_guid=2), dict(manager_component_guid=100), dict(used_unique_ids=(True,)),
                dict(weapon_slot=True), dict(activate_empty_hand=1), dict(initial_state_is_fresh=False),
                dict(manager_binding_snapshot_complete=False)):
            with self.assertRaises(ValueError):
                self.build(**changes)
        for value in (replace(ticket(), loadout_snapshot=b'{}'),
                replace(ticket(), selected_hero_id=88000000026),
                replace(ticket(), selected_fashion_id=30000060008)):
            with self.assertRaises(ValueError):
                self.build(value)

    def test_manager_complete_lists_keep_actor_identity_and_recid_parallel(self):
        schema = self.binding()
        builder = getattr(values, 'manager_weapon_bindings_update', None)
        self.assertTrue(callable(builder), 'Complete manager reference/identity lists are missing')
        update = builder(schema, pawn_guid=2, component_guid=12,
            bindings=((100, 77, 18110000000), (102, 78, 18170000000)),
            empty_hand_guid=100, actor_opens_acknowledged=True)
        reader = BitReader(update.payload, bit_count=update.payload_bit_count)
        self.assertFalse(reader.read_bool())
        # Flattened array handles advance by one per scalar element.
        for handle, expected, width in ((3, (100, 102), 'packed'),
                (4, (77, 78), 32), (5, (18110000000, 18170000000), 64)):
            self.assertEqual(reader.read_packed_int(), handle)
            self.assertEqual(reader.read_bits(16), 2)
            for index, value in enumerate(expected, 1):
                self.assertEqual(reader.read_packed_int(), index)
                self.assertEqual(reader.read_packed_int() if width == 'packed' else reader.read_bits(width), value)
            self.assertEqual(reader.read_packed_int(), 0)
        self.assertEqual(reader.read_packed_int(), 7)
        self.assertEqual(reader.read_packed_int(), 100)
        self.assertEqual(reader.read_packed_int(), 0)
        self.assertEqual(reader.remaining, 0)
        with self.assertRaises(ValueError):
            builder(schema, pawn_guid=2, component_guid=12,
                bindings=((100, 77, 18110000000), (102, 77, 18170000000)),
                empty_hand_guid=100, actor_opens_acknowledged=True)


if __name__ == '__main__':
    unittest.main()
