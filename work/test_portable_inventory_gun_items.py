"""GunDesc selector splicing through the actual frozen 52-item projection."""
from dataclasses import replace
import json
from pathlib import Path
import unittest

import portable_map_inventory as projection
import portable_map_inventory_content as content
from dfserver import legacy_ds_inventory_gun_desc as desc_codec
from dfserver import legacy_ds_inventory_gun as codec
from dfserver.legacy_ds_bit_archive import BitReader, BitWriter
from dfserver.legacy_ds_inventory_items import InventoryFastArrayDelta, InventoryFastArrayElement
from dfserver.legacy_ds_inventory_condition import ConditionInventoryItem
from dfserver.legacy_ds_inventory_stack import StackedInventoryItem

ROOT = Path(__file__).resolve().parent.parent


class GunItemsTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = json.loads((ROOT/'work/evidence/map-system-audit-20261018/carried-snapshot-offline.json').read_bytes())
        self.projected = projection.build(self.snapshot, value_fields=(0, 0, 0, 0, 0, 0, 0), owner_player_id=123)
        self.descriptions = {p['gid']: desc_codec.from_snapshot_prop(p) for p in self.snapshot['props'] if p.get('weapon')}

    def gun_items(self):
        return self.projected.items

    def test_full_original_52_items_mixed_features_roundtrip(self):
        elements = self.gun_items()
        writer = BitWriter()
        delta = InventoryFastArrayDelta(1, -1, (), elements)
        codec.write_inventory_custom_delta(writer, delta, profile=content.PROFILE)
        reader = BitReader(writer.to_bytes(), bit_count=writer.bit_count)
        actual = codec.read_inventory_custom_delta(reader, profile=content.PROFILE)
        self.assertEqual(reader.remaining, 0)
        self.assertEqual(actual, delta)
        self.assertEqual(len(actual.changed), 52)
        self.assertEqual(sum(type(e.item) is codec.GunInventoryItem for e in actual.changed), 2)
        self.assertEqual(sum(type(e.item) is ConditionInventoryItem for e in actual.changed), 6)
        def count(item):
            if type(item) in (ConditionInventoryItem, codec.GunInventoryItem):
                return count(item.item)
            return item.stack.item_count if type(item) is StackedInventoryItem else 1
        self.assertEqual(sum(count(e.item) for e in actual.changed), 544)

    def test_unaligned_archive_and_exact_selector(self):
        item = next(e.item for e in self.gun_items() if type(e.item) is codec.GunInventoryItem)
        writer = BitWriter()
        writer.write_bits(5, 3)
        written = codec.write_inventory_item(writer, item, profile=content.PROFILE)
        self.assertEqual(written, 810+len(desc_codec.encode(item.description))*8)
        reader = BitReader(writer.to_bytes(), bit_count=writer.bit_count)
        self.assertEqual(reader.read_bits(3), 5)
        reader.position = 3+635
        self.assertTrue(reader.read_bool())
        reader.position = 3
        self.assertEqual(codec.read_inventory_item(reader, profile=content.PROFILE), item)
        self.assertEqual(reader.remaining, 0)

    def test_condition_offsets_and_atomic_truncation(self):
        item = next(e.item for e in self.gun_items() if type(e.item) is codec.GunInventoryItem)
        # Synthetic condition values exercise offset movement only, never source account state.
        item = replace(item, item=ConditionInventoryItem(item.item, (3.0, 5.0), (2.0, 4.0)))
        writer = BitWriter()
        codec.write_inventory_item(writer, item, profile=content.PROFILE)
        reader = BitReader(writer.to_bytes(), bit_count=writer.bit_count)
        self.assertEqual(codec.read_inventory_item(reader, profile=content.PROFILE), item)
        for bits in (636, writer.bit_count-1):
            short = BitReader(writer.to_bytes(), bit_count=bits)
            with self.assertRaises(ValueError):
                codec.read_inventory_item(short, profile=content.PROFILE)
            self.assertEqual(short.position, 0)

    def test_description_root_must_match_original_inventory_identity(self):
        item = next(e.item for e in self.gun_items() if type(e.item) is codec.GunInventoryItem)
        wrong = replace(item.description, rows=(replace(item.description.rows[0], gid=1),)+item.description.rows[1:])
        writer = BitWriter()
        with self.assertRaises(ValueError):
            codec.write_inventory_item(writer, replace(item, description=wrong), profile=content.PROFILE)
        self.assertEqual(writer.bit_count, 0)


if __name__ == '__main__':
    unittest.main()
