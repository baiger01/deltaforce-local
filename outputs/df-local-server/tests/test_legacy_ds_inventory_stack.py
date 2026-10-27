from dataclasses import replace
import struct
import unittest

from dfserver.legacy_ds_bit_archive import BitReader, BitWriter
from dfserver.legacy_ds_inventory_items import (
    InventoryItemLocation, MinimalInventoryItem, InventoryFastArrayElement, InventoryFastArrayDelta,
)
from dfserver.legacy_ds_inventory_state import InventoryStateProfile, CLIENT_SHA256, SCHEMA_SHA256
from dfserver import legacy_ds_inventory_stack as codec


class InventoryStackTests(unittest.TestCase):
    def setUp(self):
        self.profile = InventoryStateProfile(CLIENT_SHA256, SCHEMA_SHA256, 13, True, False)
        self.item = MinimalInventoryItem(1508005, 6, 0x123456789abcdef0, 302,
            InventoryItemLocation(0,0,1,1,False,0), 0.0,0,0,False,0,0,0,0.0,False,0,0,False)

    def test_stack60_is_one_gid_and_native_raw32_payload(self):
        item = codec.StackedInventoryItem(self.item, codec.InventoryStackData(60,60,(),()))
        writer = BitWriter()
        self.assertEqual(codec.write_inventory_item(writer,item,profile=self.profile),938)
        reader = BitReader(writer.to_bytes(),bit_count=writer.bit_count)
        prefix = reader.read_bytes(79)
        self.assertEqual(struct.unpack_from('<Q',prefix,8)[0],self.item.item_gid)
        self.assertTrue(reader.read_bool())
        self.assertEqual(reader.read_bytes(16),struct.pack('<4i',60,60,0,0))
        reader = BitReader(writer.to_bytes(),bit_count=writer.bit_count)
        self.assertEqual(codec.read_inventory_item(reader,profile=self.profile),item)

    def test_nonempty_arrays_have_raw_counts_and_original_widths(self):
        stack = codec.InventoryStackData(60,100,(0xfedcba9876543210,3),(10,50))
        item = codec.StackedInventoryItem(self.item,stack)
        writer = BitWriter()
        codec.write_inventory_item(writer,item,profile=self.profile)
        reader = BitReader(writer.to_bytes(),bit_count=writer.bit_count)
        reader.read_bytes(79)
        self.assertTrue(reader.read_bool())
        self.assertEqual(reader.read_bytes(12),struct.pack('<3i',60,100,2))
        self.assertEqual(reader.read_bytes(16),struct.pack('<2Q',0xfedcba9876543210,3))
        self.assertEqual(reader.read_bytes(12),struct.pack('<3i',2,10,50))
        self.assertEqual(writer.bit_count,938+64*2+32*2)

    def test_mixed_array_keeps_unaligned_next_id_and_one_false_prefix(self):
        stack = codec.StackedInventoryItem(self.item,codec.InventoryStackData(60,100,(),()))
        single = replace(self.item,item_gid=77)
        delta = InventoryFastArrayDelta(1,-1,(),(InventoryFastArrayElement(0,stack),InventoryFastArrayElement(1,single)))
        writer = BitWriter()
        codec.write_inventory_custom_delta(writer,delta,profile=self.profile)
        self.assertEqual(writer.bit_count,1+128+32+938+32+810)
        reader = BitReader(writer.to_bytes(),bit_count=writer.bit_count)
        self.assertEqual(codec.read_inventory_custom_delta(reader,profile=self.profile),delta)
        self.assertEqual(reader.remaining,0)

    def test_maximum_gt_one_must_be_present_even_for_one_item(self):
        item = codec.StackedInventoryItem(self.item,codec.InventoryStackData(1,60,(),()))
        writer = BitWriter()
        codec.write_inventory_item(writer,item,profile=self.profile)
        reader = BitReader(writer.to_bytes(),bit_count=writer.bit_count)
        self.assertEqual(codec.read_inventory_item(reader,profile=self.profile),item)
        for stack in (codec.InventoryStackData(0,60,(),()),codec.InventoryStackData(61,60,(),()),
                      codec.InventoryStackData(True,60,(),()),codec.InventoryStackData(1,1,(),())):
            with self.assertRaises(ValueError):
                codec.write_inventory_item(writer,codec.StackedInventoryItem(self.item,stack),profile=self.profile)
        self.assertEqual(writer.bit_count,938)

    def test_truncation_and_unqualified_optional_blocks_restore_reader(self):
        item = codec.StackedInventoryItem(self.item,codec.InventoryStackData(60,60,(),()))
        writer = BitWriter()
        codec.write_inventory_item(writer,item,profile=self.profile)
        reader = BitReader(writer.to_bytes(),bit_count=writer.bit_count-1)
        with self.assertRaises(ValueError):
            codec.read_inventory_item(reader,profile=self.profile)
        self.assertEqual(reader.position,0)
        raw = bytearray(writer.to_bytes())
        raw[(633+128)//8] |= 1 << ((633+128)%8)  # Durability selector, after actual stack.
        reader = BitReader(bytes(raw),bit_count=writer.bit_count)
        with self.assertRaises(ValueError):
            codec.read_inventory_item(reader,profile=self.profile)
        self.assertEqual(reader.position,0)


if __name__ == '__main__':
    unittest.main()
