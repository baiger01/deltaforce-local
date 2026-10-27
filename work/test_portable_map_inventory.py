from copy import deepcopy
import json
import unittest

import portable_map_inventory as adapter
from dfserver.legacy_ds_bit_archive import BitReader,BitWriter
from dfserver.legacy_ds_inventory_state import InventoryStateProfile,CLIENT_SHA256,SCHEMA_SHA256,write_inventory_repdata,read_inventory_repdata
from dfserver.legacy_ds_inventory_items import InventoryFastArrayDelta
from dfserver.legacy_ds_inventory_stack import StackedInventoryItem
from dfserver.legacy_ds_inventory_keychain import KeychainInventoryItem
from dfserver.legacy_ds_inventory_condition import ConditionInventoryItem,write_inventory_custom_delta,read_inventory_custom_delta


def frozen():
    return dict(kind='local_account_carried_loadout_v1',
        source_item_catalog_sha256=adapter.CATALOG_PINS['protocol/game_item_catalog.json'],
        source_slot_catalog_sha256=adapter.CATALOG_PINS['protocol/deposit_slot_catalog.json'],
        props=[dict(gid=901,template_id=11010001001,quantity=1,grid_page_id=101,x=0,y=0,length=2,width=2,rotated=0),
            dict(gid=902,template_id=11080004006,quantity=1,grid_page_id=108,x=0,y=0,length=4,width=5,rotated=0),
            dict(gid=903,template_id=15200000073,quantity=60,grid_page_id=108001,x=1,y=3,length=1,width=1,rotated=0,space_width=2)],
        selected_melee=None,body_layouts=[])


class PortableMapInventoryTests(unittest.TestCase):
    def test_local_revision_is_explicit_positive_int32_and_roundtrips(self):
        for value in (0,-1,True,1<<31):
            with self.subTest(value=value),self.assertRaises(ValueError):
                adapter.build(frozen(),value_fields=(0,0,0,0,0,0,0),space_revision=value)
        result=adapter.build(frozen(),value_fields=(0,0,0,0,0,0,0),space_revision=7)
        self.assertEqual({s.server_update_count for s in result.repdata.spaces},{7})
        self.assertEqual(result.qualification['space_revision'],7)
        self.assertIn('not_official_constant',result.qualification['space_revision_policy'])

    def test_first_space_revision_crosses_the_actual_item_slot_zero_gate(self):
        # ItemSlot.Ctor sets 0; LootingServer._InitTargetSpace skips equal revisions.
        snapshot=json.loads((adapter.ROOT/'work/evidence/map-system-audit-20261018/carried-snapshot-offline.json').read_bytes())
        result=adapter.build(snapshot,value_fields=(0,0,0,0,0,0,0))
        initial_item_slot_revision=0
        initialized=[s for s in result.repdata.spaces if s.server_update_count!=initial_item_slot_revision]
        self.assertEqual(len(initialized),13,'The original Lua equality gate skips every initial space')
        self.assertEqual(sum(len(s.grids) for s in initialized),23)

    def test_actual_guns_preserve_receiver_components_ammo_and_skin(self):
        snapshot=json.loads((adapter.ROOT/'work/evidence/map-system-audit-20261018/carried-snapshot-offline.json').read_bytes())
        result=adapter.build(snapshot,value_fields=(0,0,0,0,0,0,0))
        guns=[e.item for e in result.items if e.item.item_gid in (6400000000000000059,6400000000000000060)]
        self.assertEqual(len(guns),2)
        self.assertTrue(all(hasattr(item,'description') for item in guns),'Actual carried weapons lack GunDesc')
        self.assertEqual(sorted(len(item.description.rows) for item in guns),[6,7])
        self.assertEqual(sum(a.num for item in guns for a in item.description.ammo),20)
        self.assertEqual({item.description.skin.skin_id for item in guns},{28010050280,28014350004})

    def test_keeps_all_gids_quantities_and_equipment_display_cells(self):
        result=adapter.build(frozen(),value_fields=(0,0,0,0,0,0,0))
        self.assertEqual([e.item.item_gid for e in result.items],[901,902,903])
        self.assertIsInstance(result.items[2].item,StackedInventoryItem)
        self.assertEqual((result.items[2].item.stack.item_count,result.items[2].item.stack.item_num_max),(60,60))
        self.assertEqual((adapter.base_item(result.items[0].item).location.length,adapter.base_item(result.items[0].item).location.height),(1,1))
        self.assertEqual((result.items[2].item.item.location.x,result.items[2].item.item.location.y,
            result.items[2].item.item.location.grid_index),(1,1,1))
        self.assertEqual(result.qualification['quantity_sum'],62)
        self.assertFalse(result.qualification['optional_features_complete'])

    def test_real_backpack_and_pocket_geometry_keep_half_unit_coordinates(self):
        result=adapter.build(frozen(),value_fields=(1,2,3,4,5,6,7))
        spaces={s.space_type:s for s in result.repdata.spaces}
        self.assertEqual((spaces[108001].grids[0].logic_half_unit_x,spaces[108001].grids[0].logic_half_unit_y),(2,1))
        self.assertEqual([(g.grid_id,g.length,g.height,g.logic_half_unit_x,g.logic_half_unit_y)
            for g in spaces[199997].grids],[(1,1,1,1,1),(2,1,1,3,1),(3,1,1,5,1),(4,1,1,7,1),(5,1,1,9,1)])
        profile=InventoryStateProfile(CLIENT_SHA256,SCHEMA_SHA256,13,True,False)
        writer=BitWriter(maximum_bits=8192)
        write_inventory_repdata(writer,result.repdata,profile=profile)
        self.assertEqual(read_inventory_repdata(BitReader(writer.to_bytes(),bit_count=writer.bit_count),profile=profile),result.repdata)
        delta=InventoryFastArrayDelta(1,-1,(),result.items)
        writer=BitWriter(maximum_bits=8192)
        write_inventory_custom_delta(writer,delta,profile=profile)
        self.assertEqual(read_inventory_custom_delta(BitReader(writer.to_bytes(),bit_count=writer.bit_count),profile=profile),delta)

    def test_does_not_guess_item_maximum_or_oversized_stack(self):
        for key,value in (('template_id',1),('quantity',61),('quantity',True)):
            snapshot=frozen()
            snapshot['props'][2][key]=value
            before=deepcopy(snapshot)
            with self.assertRaises(ValueError):
                adapter.build_items(snapshot)
            self.assertEqual(snapshot,before)

    def test_refuses_wrong_flattening_width_and_layout_mismatch(self):
        snapshot=frozen()
        snapshot['props'][2]['space_width']=3
        with self.assertRaises(ValueError):
            adapter.build_items(snapshot)
        snapshot=frozen()
        snapshot['body_layouts']=[dict(business_position=108001,spaces=[dict(business_space_id=1,width=1,height=1)])]
        with self.assertRaises(ValueError):
            adapter.build_items(snapshot)

    def test_missing_keychain_parent_and_duplicate_gids_are_explicit(self):
        snapshot=frozen()
        snapshot['props'][2].update(grid_page_id=116001,x=2201)
        with self.assertRaisesRegex(ValueError,'Keychain contents'):
            adapter.build_items(snapshot)

    def test_keychain_uses_map_id_not_keybox_row_index_and_keeps_card(self):
        snapshot=frozen()
        snapshot['props'].extend([
            dict(gid=904,template_id=11120000001,quantity=1,grid_page_id=116,x=0,y=0,length=1,width=1),
            dict(gid=905,template_id=15050500001,quantity=1,grid_page_id=116001,x=88,y=1,
                length=1,width=1,space_width=4)])
        result=adapter.build(snapshot,value_fields=(0,0,0,0,0,0,0))
        self.assertIsInstance(result.items[3].item,KeychainInventoryItem)
        self.assertEqual([s.index for s in result.items[3].item.spaces],[19,22,39,81,88,89])
        self.assertEqual((result.items[4].item.item_gid,result.items[4].item.location.grid_index,
            result.items[4].item.location.x,result.items[4].item.location.y),(905,88,1,0))
        self.assertNotIn(116001,[s.space_type for s in result.repdata.spaces])
        snapshot['props'][-1]['x']=22
        with self.assertRaisesRegex(ValueError,'keycard MapID'):
            adapter.build_items(snapshot)
        snapshot=frozen()
        snapshot['props'][2]['gid']=901
        with self.assertRaisesRegex(ValueError,'Repeated carried GID'):
            adapter.build_items(snapshot)

    def test_optional_snapshot_features_are_reported_without_dropping_parent_item(self):
        snapshot=frozen()
        snapshot['props'][0].update(health=5,health_max=10)
        snapshot['props'][1]['weapon']={'load_bullets':[]}
        result=adapter.build(snapshot,value_fields=(0,0,0,0,0,0,0))
        self.assertEqual(len(result.items),3)
        gaps={g['gid']:g['unserialized_snapshot_fields'] for g in result.qualification['optional_feature_gaps']}
        self.assertEqual(gaps[901],[])
        self.assertIsInstance(result.items[0].item,ConditionInventoryItem)
        self.assertEqual(result.items[0].item.durability,(5.,10.))
        self.assertEqual(gaps[902],['weapon'])


if __name__=='__main__':
    unittest.main()
