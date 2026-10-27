"""Bounded tests for the production GunDesc payload, without transport."""
from dataclasses import replace
from copy import deepcopy
import json
from pathlib import Path
import struct
import unittest

import portable_map_inventory
from dfserver import legacy_ds_inventory_gun_desc as codec

ROOT = Path(__file__).resolve().parent.parent


class GunDescTests(unittest.TestCase):
    def test_fresh_description_crosses_the_real_zero_cache_equality_gate(self):
        prop={'template_id':18010000006,'gid':1,'quantity':1,'components':[],
            'weapon':{'load_bullets':[]}}
        desc=codec.from_snapshot_prop(prop)
        raw=codec.encode(desc)
        # One row(69), attr/owner/ammo header(16), heat(12), PoorItemId(8).
        revisions=struct.unpack_from('<2Q',raw,105)
        self.assertNotEqual(revisions,(0,0),'ItemBase.Ctor caches both zero; equal counters skip RawDescObj conversion')
        self.assertEqual(revisions,(1,1))

    def test_local_revision_is_explicit_bounded_and_not_a_fabricated_timestamp(self):
        prop={'template_id':18010000006,'gid':1,'quantity':1,'components':[],
            'weapon':{'load_bullets':[]}}
        desc=codec.from_snapshot_prop(prop,desc_revision=7,attr_revision=9)
        self.assertEqual((desc.modify_revision,desc.attr_modify_revision),(7,9))
        self.assertEqual(codec.decode(codec.encode(desc)),desc)
        for bad in (True,0,-1,1<<31,1.0):
            for argument in ('desc_revision','attr_revision'):
                with self.subTest(argument=argument,value=bad),self.assertRaises(ValueError):
                    codec.from_snapshot_prop(prop,**{argument:bad})

    def test_historical_zero_revisions_decode_without_becoming_the_fresh_policy(self):
        desc=codec.GunDescription((codec.GunDescRow(1,18010000006,1,0,0),),(),
            codec.GunSkin(0,0),modify_revision=0,attr_modify_revision=0)
        self.assertEqual(codec.decode(codec.encode(desc)),desc)
        for bad in (True,-1,1<<31):
            with self.subTest(value=bad),self.assertRaises(ValueError):
                codec.encode(replace(desc,modify_revision=bad))

    def test_unknown_nondefault_fields_and_nested_skin_are_never_discarded(self):
        prop={'template_id':18010000006,'gid':1,'quantity':1,'components':[],
            'weapon':{'load_bullets':[]}}
        variants=[]
        unknown=deepcopy(prop)
        unknown['weapon']['future_native_feature']=1
        variants.append(unknown)
        nested=deepcopy(prop)
        nested['components']=[{'slot':1,'prop_data':{'id':13030000138,'gid':2,'num':1,
            'weapon':{'load_bullets':[],'skin_id':28010050280}}}]
        variants.append(nested)
        ammo=deepcopy(prop)
        ammo['weapon']['load_bullets']=[{'id':37110400001,'gid':3,'num':1,'future_ammo_feature':1}]
        variants.append(ammo)
        for value in variants:
            with self.subTest(value=value),self.assertRaises(ValueError):
                codec.from_snapshot_prop(value)
        with self.assertRaises(ValueError):
            codec.from_snapshot_prop(dict(prop,template_id=11080004006))

    def test_one_row_exact_raw_layout(self):
        row = codec.GunDescRow(1, 18010000006, 6400000000000000059, 0, 0)
        desc = codec.GunDescription((row,), (), codec.GunSkin(28010050280, 6400000000000000225))
        raw = codec.encode(desc)
        expected_row = struct.pack('<QHQQHIIHBffBQIii', 0, 1, row.item_id,
            row.gid, 0, 0, 0, 0, 0, 0.0, 0.0, 1, 0, 0, 0, 0)
        self.assertEqual(len(expected_row), 68)
        self.assertEqual(raw[:69], b'\x01'+expected_row)
        self.assertEqual(raw[69:97], struct.pack('<iii4i', 0, 0, 1, 0, 0, 0, 0))
        self.assertEqual(len(raw), 193)
        self.assertEqual(codec.decode(raw), desc)

    def test_actual_two_snapshot_trees_roundtrip(self):
        snapshot = json.loads((ROOT/'work/evidence/map-system-audit-20261018/carried-snapshot-offline.json').read_bytes())
        props = [p for p in snapshot['props'] if p.get('weapon')]
        descriptions = [codec.from_snapshot_prop(p) for p in props]
        self.assertEqual([len(d.rows) for d in descriptions], [6, 7])
        self.assertEqual([len(codec.encode(d)) for d in descriptions], [533, 637])
        for prop, desc in zip(props, descriptions):
            self.assertEqual(codec.decode(codec.encode(desc)), desc)
            self.assertEqual(desc.rows[0].gid, prop['gid'])
            self.assertEqual(desc.rows[0].item_id, prop['template_id'])
        second = descriptions[1]
        self.assertEqual((second.rows[3].parent_index, second.rows[3].parent_socket_id), (3, 6))
        self.assertEqual((second.ammo[0].gid, second.ammo[0].num), (6400000000000000401, 20))
        self.assertEqual(second.skin, codec.GunSkin(28014350004, 0))

    def test_raw_bool_width_and_ammo_binding(self):
        row = codec.GunDescRow(1, 18010000043, 6400000000000000060, 0, 0, raw_bound=True)
        ammo = codec.GunAmmo(37110400001, 6400000000000000401, 20, 17, (17,))
        desc = codec.GunDescription((row,), (ammo,), codec.GunSkin(28014350004, 0))
        raw = codec.encode(desc)
        self.assertEqual(raw[57:61], struct.pack('<I', 1))
        self.assertEqual(len(raw), 237)
        self.assertEqual(codec.decode(raw), desc)

    def test_invalid_tree_and_values_rejected(self):
        root = codec.GunDescRow(1, 18010000043, 6400000000000000060, 0, 0)
        child = codec.GunDescRow(2, 13030000190, 6400000000000000049, 1, 1)
        valid = codec.GunDescription((root, child), (), codec.GunSkin(0, 0))
        for rows in ((replace(root, index=0),), (root, replace(child, parent_index=2)),
                     (root, replace(child, gid=root.gid)),
                     (root, replace(child, parent_socket_id=0)),
                     (root, replace(child, durability=float('nan')))):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                codec.encode(replace(valid, rows=rows))
        with self.assertRaises(ValueError):
            codec.encode(replace(valid, ammo=(codec.GunAmmo(37110400001, 1, 0),)))

    def test_decoder_rejects_truncation_bounds_and_unsupported_nondefaults(self):
        raw = codec.encode(codec.GunDescription((codec.GunDescRow(1, 18010000006, 1, 0, 0),), (), codec.GunSkin(0, 0)))
        for value in (raw[:-1], raw+b'\x00', b'\xff'+raw[1:]):
            with self.subTest(length=len(value)), self.assertRaises(ValueError):
                codec.decode(value)
        for offset in (1, 69, 73, 81, len(raw)-4):
            changed = bytearray(raw)
            changed[offset:offset+4] = struct.pack('<i', 1)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                codec.decode(bytes(changed))

    def test_snapshot_unknown_template_and_optional_tunes_rejected(self):
        prop = {'template_id': 18010000006, 'gid': 1, 'quantity': 1,
                'components': [], 'weapon': {'load_bullets': []}}
        self.assertEqual(codec.from_snapshot_prop(prop).rows[0].item_id, 18010000006)
        with self.assertRaises(ValueError):
            codec.from_snapshot_prop(dict(prop, template_id=123456789))
        with self.assertRaises(ValueError):
            codec.from_snapshot_prop(dict(prop, tune_info={'id': 1}))
        with self.assertRaises(ValueError):
            codec.from_snapshot_prop(dict(prop, bind_type=2))
        with self.assertRaises(ValueError):
            codec.from_snapshot_prop(dict(prop, weapon={'load_bullets': [], 'skin_info': {'wear': 1}}))
        with self.assertRaises(ValueError):
            codec.from_snapshot_prop(dict(prop, components=[{'slot': 1, 'prop_data': {'id': 13030000138, 'gid': 1, 'num': 1}}]))

    def test_actual_business_optional_field_names_do_not_silently_drop_values(self):
        prop = {'template_id': 18010000006, 'gid': 1, 'quantity': 1,
                'components': [], 'weapon': {'load_bullets': []}}
        variants = []
        skin = deepcopy(prop)
        skin['weapon']['skinInfo'] = {'transmog': True}
        variants.append(('weapon.skinInfo', skin))
        mystical = deepcopy(prop)
        mystical['mystical_skin_data'] = {'wear': 1}
        variants.append(('mystical_skin_data', mystical))
        tuning = deepcopy(prop)
        tuning['components'] = [{'slot': 1, 'prop_data': {'id': 13030000138,
            'gid': 2, 'num': 1, 'weapon': {'attr_set': [{'id': 1, 'value': 2}]}}}]
        variants.append(('component.weapon.attr_set', tuning))
        for field, value in variants:
            with self.subTest(field=field), self.assertRaises(ValueError):
                codec.from_snapshot_prop(value)
        defaults = deepcopy(prop)
        defaults['weapon'].update(skinInfo={}, attr_set=[])
        defaults['mystical_skin_data'] = {}
        self.assertEqual(codec.from_snapshot_prop(defaults), codec.from_snapshot_prop(prop))


if __name__ == '__main__':
    unittest.main()
