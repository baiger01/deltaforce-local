from copy import deepcopy
import json
import unittest

import portable_map_inventory as adapter
import portable_map_inventory_content as content
from test_portable_map_inventory import frozen
from dfserver.legacy_ds_actor_content import ActorContentBlock
from dfserver.legacy_ds_actor_fields import NormalClassFieldProfile,read_class_field_content
from dfserver.legacy_ds_bit_archive import BitReader
from dfserver.legacy_ds_inventory_gun import GunInventoryItem,read_inventory_custom_delta
from dfserver.legacy_ds_inventory_state import read_inventory_repdata


class ContentTests(unittest.TestCase):
    def test_replayout_handle_and_class_cache_index_remain_separate(self):
        result=content.build(frozen(),pawn_guid=8,component_guid=22,
            value_fields=(0,0,0,0,0,0,0),owner_player_id=123)
        self.assertEqual([len(g) for g in result.groups],[1,1])
        first=result.groups[0][0]
        self.assertTrue(first.has_rep_layout)
        reader=BitReader(first.payload,bit_count=first.payload_bit_count)
        self.assertFalse(reader.read_bool())
        self.assertEqual(reader.read_packed_int(),10)
        self.assertTrue(read_inventory_repdata(reader,profile=content.PROFILE).initialized)
        self.assertEqual(reader.read_packed_int(),0)
        self.assertEqual(reader.remaining,0)
        last=result.groups[1][0]
        self.assertFalse(last.has_rep_layout)
        fields=read_class_field_content(ActorContentBlock(False,last.payload,last.payload_bit_count),
            profile=NormalClassFieldProfile(53,False))
        self.assertEqual([f.rep_index for f in fields],[7])
        delta=read_inventory_custom_delta(BitReader(fields[0].payload,bit_count=fields[0].payload_bit_count),profile=content.PROFILE)
        self.assertEqual((delta.array_replication_key,delta.base_replication_key),(1,-1))
        self.assertEqual([e.item.item_gid for e in delta.changed],[901,902,903])

    def test_actual_frozen_snapshot_keeps_every_gid_and_quantity(self):
        path=adapter.ROOT/'work/evidence/map-system-audit-20261018/carried-snapshot-offline.json'
        snapshot=json.loads(path.read_text(encoding='utf8'))
        before=deepcopy(snapshot)
        result=content.build(snapshot,pawn_guid=8,component_guid=22,
            value_fields=(0,0,0,0,0,0,0),owner_player_id=123)
        self.assertEqual(snapshot,before)
        self.assertEqual(len(result.groups),16)
        self.assertEqual(result.qualification['top_level_item_count'],52)
        self.assertEqual(result.qualification['quantity_sum'],544)
        self.assertEqual(result.qualification['ordinary_space_count'],13)
        self.assertEqual(result.qualification['ordinary_grid_count'],23)
        self.assertEqual(result.qualification['repdata_content_bits'],5793)
        accumulated={}
        recent={}
        guns=[]
        for n,group in enumerate(result.groups[1:],1):
            update=group[0]
            fields=read_class_field_content(ActorContentBlock(False,update.payload,update.payload_bit_count),
                profile=NormalClassFieldProfile(53,False))
            delta=read_inventory_custom_delta(BitReader(fields[0].payload,bit_count=fields[0].payload_bit_count),profile=content.PROFILE)
            self.assertEqual((delta.array_replication_key,delta.base_replication_key),(n,n-1 if n>1 else -1))
            # Native cacaaf0 implicit deletion interval excludes prior ACKed items.
            self.assertFalse([k for k,v in recent.items() if delta.base_replication_key<v<delta.array_replication_key])
            for element in delta.changed:
                self.assertNotIn(element.element_id,accumulated)
                accumulated[element.element_id]=element.item.item_gid
                recent[element.element_id]=delta.array_replication_key
                if type(element.item) is GunInventoryItem:
                    self.assertEqual(len(delta.changed),1)
                    guns.append(element.item)
            self.assertLess(update.payload_bit_count,8192)
        expected={p['gid'] for p in snapshot['props']}|{snapshot['selected_melee']['gid']}
        self.assertEqual(set(accumulated.values()),expected)
        self.assertEqual(len(guns),2)
        self.assertEqual(sum(a.num for item in guns for a in item.description.ammo),20)
        self.assertEqual(max(g[0].payload_bit_count for g in result.groups),6089)

    def test_schema_drift_wrong_guid_and_implicit_policy_rejected(self):
        for kwargs in (dict(component_guid=8),dict(pawn_guid=9),dict(value_fields=(1,0,0,0,0,0,0)),
                dict(schema=b'{}'),dict(owner_player_id=True)):
            options=dict(pawn_guid=8,component_guid=22,value_fields=(0,0,0,0,0,0,0),owner_player_id=123)
            options.update(kwargs)
            with self.assertRaises(ValueError):
                content.build(frozen(),**options)


if __name__=='__main__':
    unittest.main()
