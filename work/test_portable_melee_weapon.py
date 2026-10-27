"""Original cooked melee rows and frozen admission identity regression tests."""
import json
import unittest
from dataclasses import replace

from test_portable_carried_weapon_selection import ticket


class MeleeWeaponSourcesTest(unittest.TestCase):
    def test_actor_open_waits_for_the_original_archetype_mapping(self):
        from portable_melee_weapon import actor_probe
        from test_portable_character_initialization import admission_fixture
        from dfserver.legacy_ds_actor_manifest import preflight_actor_manifest
        from dfserver.legacy_ds_bit_archive import BitReader
        from dfserver.legacy_ds_guid_exports import read_guid_exports
        admitted, (pawn,), _ = admission_fixture()
        data = json.loads(admitted.loadout_snapshot)
        data['selected_melee'] = dict(gid=6300000000000000099, grid_page_id=113,
            template_id=18100000027, quantity=1, weapon=dict(skin_id=28101250027, skin_gid=0))
        admitted = replace(admitted, loadout_snapshot=json.dumps(data).encode())
        used = tuple(sorted({pawn.actor_guid} | {b.guid for b in pawn.path_bindings}))
        manifest, _ = actor_probe(admitted, parent_manifest=pawn, package_guid=301,
            class_guid=303, archetype_guid=305, actor_guid=302, channel_index=14,
            allocated_guids=used, allocated_channels=(pawn.channel_index,),
            location=pawn.location, rotation=pawn.rotation, scale=pawn.scale, velocity=pawn.velocity)
        preflight = preflight_actor_manifest(manifest, channel_sequence=1, max_packet_bytes=1024)
        self.assertTrue(preflight.bunch.must_be_mapped)
        reader = BitReader(preflight.bunch.payload, bit_count=preflight.bunch.payload_bits)
        read_guid_exports(reader)
        self.assertEqual(reader.read_bits(16), 1)
        self.assertEqual(reader.read_packed_int(), manifest.archetype_guid)
        self.assertEqual(reader.read_packed_int(), manifest.actor_guid)
        self.assertEqual(reader.read_packed_int(), manifest.archetype_guid)

    def test_selected_nepal_uses_its_original_specialized_blueprint(self):
        from portable_melee_weapon import select
        admitted = ticket()
        data = json.loads(admitted.loadout_snapshot)
        data['selected_melee'] = dict(gid=6300000000000000099, grid_page_id=113,
            template_id=18100000027, quantity=1,
            weapon=dict(skin_id=28101250027, skin_gid=0))
        value = select(replace(admitted, loadout_snapshot=json.dumps(data).encode()))
        self.assertEqual(value.weapon_rec_id, 18100000027)
        self.assertEqual(value.business_position, 113)
        self.assertEqual(value.skin_id, 28101250027)
        self.assertTrue(value.class_path.endswith('BP_WeaponMeleeNoModular_Nepal_C'))
        self.assertEqual((value.path_type, value.path_id), (3, 18100000027))

    def test_knife_content_carries_one_root_recipe_node(self):
        # The client ready gate 590ce90 sets first/third person only after a
        # nonzero ModularReplicateInfo.WeaponPartNodes count arrives.
        from portable_melee_weapon import select, initial_content
        from owned_weapon_values_codec import actor_schema_binding
        from dfserver.legacy_ds_bit_archive import BitReader
        admitted = ticket()
        data = json.loads(admitted.loadout_snapshot)
        data['selected_melee'] = dict(gid=6300000000000000099, grid_page_id=113,
            template_id=18100000027, quantity=1,
            weapon=dict(skin_id=28101250027, skin_gid=0))
        value = select(replace(admitted, loadout_snapshot=json.dumps(data).encode()))
        block = initial_content(value, pawn_guid=2, unique_id=77, slot=0)
        fields = actor_schema_binding()['actor']['fields']
        reader = BitReader(block.payload, bit_count=block.payload_bit_count)
        self.assertFalse(reader.read_bool())
        self.assertEqual(reader.read_packed_int(), 6)
        self.assertEqual(reader.read_bits(2), 1)
        for name, width in (('Owner', None), ('WeaponID', 64), ('WeaponGuid', 64),
                            ('WeaponEquipPosition', 32), ('WeaponSlot', 8)):
            self.assertEqual(reader.read_packed_int(), fields[name]['ordinary_handle'])
            reader.read_packed_int() if width is None else reader.read_bits(width)
        self.assertEqual(reader.read_packed_int(), 36)
        self.assertEqual(reader.read_bits(16), 1)
        self.assertEqual(reader.read_packed_int(), 1)
        self.assertEqual(reader.read_bits(64), 18100000027)
        self.assertEqual(reader.read_packed_int(), 8)
        self.assertEqual(reader.read_bits(64), 6300000000000000099)

    def test_base_knife_and_inconsistent_skin(self):
        from portable_melee_weapon import select
        admitted = ticket()
        data = json.loads(admitted.loadout_snapshot)
        data['selected_melee'] = dict(gid=6300000000000000099, grid_page_id=113,
            template_id=18100000002, quantity=1,
            weapon=dict(skin_id=28101200002, skin_gid=0))
        value = select(replace(admitted, loadout_snapshot=json.dumps(data).encode()))
        self.assertTrue(value.class_path.endswith('BP_WeaponMeleeNoModular_C'))
        self.assertEqual((value.path_type, value.path_id), (1, 4))
        data['selected_melee']['weapon']['skin_id'] = 28101250027
        with self.assertRaises(ValueError):
            select(replace(admitted, loadout_snapshot=json.dumps(data).encode()))

    def test_no_selection_stays_empty(self):
        from portable_melee_weapon import select
        admitted = ticket()
        data = json.loads(admitted.loadout_snapshot)
        data['selected_melee'] = None
        self.assertIsNone(select(replace(admitted, loadout_snapshot=json.dumps(data).encode())))

    def test_original_table_class_reference_wire(self):
        from dfserver.legacy_ds_bit_archive import BitReader, BitWriter
        from owned_weapon_values_codec import (WeaponPair, schema_binding,
            write_weapon_pair, read_weapon_pair)
        pair = WeaponPair(False, 0, 123, 18100000027, 0, 0, path_type=3)
        writer = BitWriter()
        write_weapon_pair(writer, pair, schema=schema_binding())
        self.assertEqual(writer.bit_count, 149)
        reader = BitReader(writer.to_bytes(), bit_count=writer.bit_count)
        self.assertFalse(reader.read_bool())
        self.assertEqual(reader.read_bits(4), 0)
        self.assertEqual(reader.read_bits(32), 123)
        self.assertEqual(reader.read_bits(8), 3)
        self.assertEqual(reader.read_bits(64), 18100000027)
        self.assertEqual(read_weapon_pair(BitReader(writer.to_bytes(),
            bit_count=writer.bit_count), schema=schema_binding()), pair)


if __name__ == '__main__':
    unittest.main()
