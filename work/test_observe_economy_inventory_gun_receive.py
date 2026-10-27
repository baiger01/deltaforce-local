"""Bounded GunDesc reads through fake native memory; no process access."""
import json
from pathlib import Path
import struct
import unittest

import portable_map_inventory
import observe_economy_inventory_gun_receive as observer
from dfserver.legacy_ds_inventory_gun_desc import from_snapshot_prop


ROOT=Path(__file__).resolve().parent.parent
SNAPSHOT=ROOT/'work/native-client-tests/1792311694804456800/admitted-loadout-snapshot.json'


class NativeFixture:
    def __init__(self):
        self.snapshot=SNAPSHOT.read_bytes()
        self.manager=0x810000
        self.item_base=0x820000
        self.regions={}
        self.calls=[]
        descriptions=[from_snapshot_prop(p) for p in json.loads(self.snapshot)['props'] if p.get('weapon')]
        self.regions[self.manager+0x3f8]=struct.pack('<Qii',self.item_base,2,2)
        for index,desc in enumerate(descriptions):
            item=bytearray(0x800)
            struct.pack_into('<Q',item,0x28,desc.rows[0].gid)
            nodes_at=0x830000+index*0x10000
            ammo_at=0x840000+index*0x10000
            struct.pack_into('<Qii',item,0x90,nodes_at,len(desc.rows),len(desc.rows))
            struct.pack_into('<Qii',item,0xd0,ammo_at if desc.ammo else 0,len(desc.ammo),len(desc.ammo))
            struct.pack_into('<QQ',item,0xf8,1,1)
            struct.pack_into('<QQQ',item,0x110,desc.skin.skin_gid,desc.skin.skin_id,0)
            nodes=bytearray(136*len(desc.rows))
            for number,row in enumerate(desc.rows):
                at=number*136
                struct.pack_into('<H',nodes,at+0x20,row.index)
                struct.pack_into('<QQH',nodes,at+0x28,row.item_id,row.gid,row.parent_index)
                struct.pack_into('<I',nodes,at+0x3c,row.parent_socket_id)
            self.regions[nodes_at]=nodes
            if desc.ammo:
                ammo=bytearray(56*len(desc.ammo))
                for number,row in enumerate(desc.ammo):
                    struct.pack_into('<QQi',ammo,number*56,row.item_id,row.gid,row.num)
                self.regions[ammo_at]=ammo
            self.regions[self.item_base+index*0x800]=item

    def stable(self,at,size):
        self.calls.append((at,size))
        for base,data in self.regions.items():
            if base<=at and at+size<=base+len(data):
                return bytes(data[at-base:at-base+size])
        raise AssertionError('Read outside source-qualified fixture: '+hex(at))


class GunReceiveTests(unittest.TestCase):
    def test_two_complete_trees_ammo_and_skin_are_read_beyond_the_old_prefix(self):
        fixture=NativeFixture()
        reads={}
        rows=observer.read_guns(fixture,fixture.manager,fixture.snapshot,reads)
        self.assertEqual([r['rows_count'] for r in rows],[6,7])
        self.assertTrue(all(r['original_nodes_match'] and r['original_ammo_match'] and
            r['original_skin_match'] for r in rows))
        self.assertEqual(rows[1]['ammo'][0]['num'],20)
        self.assertEqual(rows[1]['ammo'][0]['gid'],6400000000000000401)
        self.assertEqual(rows[0]['skin']['skin_id'],28010050280)
        self.assertEqual(rows[1]['skin']['skin_id'],28014350004)
        self.assertEqual(rows[0]['modify_timestamp'],1)
        self.assertIn((fixture.item_base+0x90,336),fixture.calls)
        observer.recheck_values(fixture,reads)

    def test_missing_description_is_an_explicit_mismatch(self):
        fixture=NativeFixture()
        struct.pack_into('<Qii',fixture.regions[fixture.item_base],0x90,0,0,0)
        rows=observer.read_guns(fixture,fixture.manager,fixture.snapshot,{})
        self.assertEqual(rows[0]['nodes'],[])
        self.assertFalse(rows[0]['original_nodes_match'])

    def test_native_array_bounds_are_checked_before_following_pointer(self):
        fixture=NativeFixture()
        struct.pack_into('<Qii',fixture.regions[fixture.item_base],0x90,0x830000,65,65)
        with self.assertRaisesRegex(ValueError,'scope'):
            observer.read_guns(fixture,fixture.manager,fixture.snapshot,{})
        self.assertNotIn((0x830000,136),fixture.calls)

    def test_current_owner_declaration_must_match_native_storage(self):
        field=dict(name='OwnerCharacter',storage_offset=0x218,element_bytes=8,array_dimension=1,
            native_property_type='FEncryptedObjectProperty',declared_native_class='DFMCharacter',
            field_vtable_rva=0x1ab613b0)
        metadata=dict(declarations=[dict(class_name='InventoryManager',fields=[field])])
        self.assertEqual(observer._field(metadata,'OwnerCharacter','InventoryManager',0x218,8,
            vtable=0x1ab613b0)['native_property_type'],'FEncryptedObjectProperty')
        field['storage_offset']=0x220
        with self.assertRaisesRegex(ValueError,'differs'):
            observer._field(metadata,'OwnerCharacter','InventoryManager',0x218,8)


if __name__=='__main__':
    unittest.main()
