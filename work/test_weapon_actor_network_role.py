"""Weapon initialization must assign the native receiver role before ownership."""
from types import SimpleNamespace
import unittest

from dfserver.legacy_ds_bit_archive import BitReader


class WeaponActorNetworkRoleTests(unittest.TestCase):
    def check_prefix(self, block):
        reader = BitReader(block.payload, bit_count=block.payload_bit_count)
        self.assertFalse(reader.read_bool())
        self.assertEqual(reader.read_packed_int(), 6, 'RemoteRole must precede Actor ownership')
        self.assertEqual(reader.read_bits(2), 1, 'The remote weapon must be a SimulatedProxy')
        self.assertEqual(reader.read_packed_int(), 14)
        self.assertEqual(reader.read_packed_int(), 2)

    def test_empty_hand_actor_receives_a_network_role(self):
        from owned_weapon_values_codec import actor_schema_binding, build_weapon_actor_initial_content
        self.check_prefix(build_weapon_actor_initial_content(actor_schema_binding(), pawn_guid=2,
            unique_id=77, weapon_rec_id=18110000000, pawn_open_acknowledged=True,
            weapon_slot=0, root_recipe=True))

    def test_modular_actor_receives_a_network_role(self):
        from portable_modular_weapon_initialization import _actor_content, schema_binding
        self.check_prefix(_actor_content(schema_binding(), pawn_guid=2, unique_id=77,
            gun=SimpleNamespace(weapon_rec_id=18010000043, inventory_gid=99), slot=0))

    def test_initialization_works_under_the_real_admission_source_lease(self):
        from portable_source_guard import qualification_scope
        from portable_modular_weapon_initialization import _actor_content, schema_binding
        with qualification_scope():
            self.check_prefix(_actor_content(schema_binding(), pawn_guid=2, unique_id=77,
                gun=SimpleNamespace(weapon_rec_id=18010000043, inventory_gid=99), slot=0))

    def test_melee_actor_receives_a_network_role(self):
        from portable_melee_weapon import CarriedMeleeSelection, catalog, initial_content
        rec = 18100000002
        skin = next(k for k, v in catalog()['skins'].items() if v == rec)
        path = catalog()['rows'][rec]['class_path']
        selection = CarriedMeleeSelection(rec, 99, 113, skin, path,
            path.rsplit('.', 1)[0]+'.Default__'+path.rsplit('.', 1)[1], 1, 4)
        self.check_prefix(initial_content(selection, pawn_guid=2, unique_id=77, slot=0))


if __name__ == '__main__':
    unittest.main()
