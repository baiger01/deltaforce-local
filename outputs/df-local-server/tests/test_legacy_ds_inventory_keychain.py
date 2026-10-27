import unittest

from dfserver.legacy_ds_bit_archive import BitReader,BitWriter
from dfserver.legacy_ds_inventory_items import MinimalInventoryItem,InventoryItemLocation,InventoryFastArrayElement,InventoryFastArrayDelta
from dfserver.legacy_ds_inventory_state import InventoryStateProfile,CLIENT_SHA256,SCHEMA_SHA256
from dfserver.legacy_ds_inventory_keychain import (InventoryKeychainSpace,KeychainInventoryItem,
    write_inventory_item,read_inventory_item,write_inventory_custom_delta,read_inventory_custom_delta)


def item():
    return MinimalInventoryItem(1112000,1,123,116,InventoryItemLocation(0,0,1,1,False,1),
        0.,0,0,False,0,0,0,0.,False,0,0,False)


class KeychainTests(unittest.TestCase):
    def setUp(self):
        self.profile=InventoryStateProfile(CLIENT_SHA256,SCHEMA_SHA256,13,True,False)

    def test_exact_native_optional_array_width_and_roundtrip(self):
        value=KeychainInventoryItem(item(),(InventoryKeychainSpace(88,4,4,(0,0,0,0),(0,0,0,0)),))
        writer=BitWriter()
        write_inventory_item(writer,value,profile=self.profile)
        self.assertEqual(writer.bit_count,810+32+24+64+64)
        self.assertEqual(read_inventory_item(BitReader(writer.to_bytes(),bit_count=writer.bit_count),profile=self.profile),value)

    def test_mixed_array_keeps_independent_instance_and_element_ids(self):
        value=KeychainInventoryItem(item(),(InventoryKeychainSpace(22,4,4,(),()),))
        delta=InventoryFastArrayDelta(3,2,(),(InventoryFastArrayElement(5,value),InventoryFastArrayElement(6,item())))
        writer=BitWriter()
        write_inventory_custom_delta(writer,delta,profile=self.profile)
        self.assertFalse(BitReader(writer.to_bytes(),bit_count=writer.bit_count).read_bool())
        self.assertEqual(read_inventory_custom_delta(BitReader(writer.to_bytes(),bit_count=writer.bit_count),profile=self.profile),delta)

    def test_outside_byte_range_duplicate_or_overlarge_arrays_rejected_atomically(self):
        for spaces in ((InventoryKeychainSpace(2201,4,4,(),()),),
                (InventoryKeychainSpace(22,4,4,(),()),)*2,
                (InventoryKeychainSpace(22,4,4,(0,)*2049,()),)):
            writer=BitWriter()
            writer.write_bits(5,3)
            with self.assertRaises(ValueError):
                write_inventory_item(writer,KeychainInventoryItem(item(),spaces),profile=self.profile)
            self.assertEqual(writer.bit_count,3)

    def test_truncation_rolls_back_reader(self):
        value=KeychainInventoryItem(item(),(InventoryKeychainSpace(22,4,4,(),()),))
        writer=BitWriter()
        write_inventory_item(writer,value,profile=self.profile)
        reader=BitReader(writer.to_bytes(),bit_count=writer.bit_count-1)
        with self.assertRaises(ValueError):
            read_inventory_item(reader,profile=self.profile)
        self.assertEqual(reader.position,0)


if __name__=='__main__':
    unittest.main()
