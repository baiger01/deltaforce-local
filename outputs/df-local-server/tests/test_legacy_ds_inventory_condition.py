import unittest
from dfserver.legacy_ds_bit_archive import BitReader,BitWriter
from dfserver.legacy_ds_inventory_items import MinimalInventoryItem,InventoryItemLocation,InventoryFastArrayElement,InventoryFastArrayDelta
from dfserver.legacy_ds_inventory_state import InventoryStateProfile,CLIENT_SHA256,SCHEMA_SHA256
from dfserver.legacy_ds_inventory_stack import StackedInventoryItem,InventoryStackData
from dfserver.legacy_ds_inventory_keychain import KeychainInventoryItem,InventoryKeychainSpace
from dfserver.legacy_ds_inventory_condition import (ConditionInventoryItem,write_inventory_item,
    read_inventory_item,write_inventory_custom_delta,read_inventory_custom_delta)


def item():
    return MinimalInventoryItem(1505050,1,901,116001,InventoryItemLocation(1,0,1,1,False,88),
        0.,0,0,False,0,0,0,0.,False,0,0,False)


class ConditionTests(unittest.TestCase):
    def setUp(self):
        self.profile=InventoryStateProfile(CLIENT_SHA256,SCHEMA_SHA256,13,True,False)

    def test_raw_float32_durability_and_armor_are_independent(self):
        value=ConditionInventoryItem(item(),(20.,40.),(90.,100.))
        writer=BitWriter()
        write_inventory_item(writer,value,profile=self.profile)
        self.assertEqual(writer.bit_count,810+128)
        self.assertEqual(read_inventory_item(BitReader(writer.to_bytes(),bit_count=writer.bit_count),profile=self.profile),value)

    def test_stack_and_keychain_dynamic_offsets_still_roundtrip(self):
        for base in (StackedInventoryItem(item(),InventoryStackData(20,60,(123,),(20,))),
                KeychainInventoryItem(item(),(InventoryKeychainSpace(88,4,4,(0,0,0,0),(0,0,0,0)),))):
            value=ConditionInventoryItem(base,(20.,40.),None)
            writer=BitWriter()
            write_inventory_item(writer,value,profile=self.profile)
            self.assertEqual(read_inventory_item(BitReader(writer.to_bytes(),bit_count=writer.bit_count),profile=self.profile),value)

    def test_mixed_fastarray_keeps_original_gid_and_count(self):
        value=ConditionInventoryItem(item(),(20.,40.),None)
        delta=InventoryFastArrayDelta(2,1,(),(InventoryFastArrayElement(3,value),InventoryFastArrayElement(4,item())))
        writer=BitWriter()
        write_inventory_custom_delta(writer,delta,profile=self.profile)
        self.assertEqual(read_inventory_custom_delta(BitReader(writer.to_bytes(),bit_count=writer.bit_count),profile=self.profile),delta)

    def test_unknown_or_invalid_condition_rejected_without_partial_write(self):
        for pair in ((1.,0.),(50.,40.),(float('nan'),40.),(True,40.)):
            writer=BitWriter()
            writer.write_bits(5,3)
            with self.assertRaises(ValueError):
                write_inventory_item(writer,ConditionInventoryItem(item(),pair,None),profile=self.profile)
            self.assertEqual(writer.bit_count,3)


if __name__=='__main__':
    unittest.main()
