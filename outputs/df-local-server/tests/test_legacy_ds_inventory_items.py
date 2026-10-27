import dataclasses
import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

from dfserver.legacy_ds_bit_archive import BitReader, BitWriter

try:
    from dfserver import legacy_ds_inventory_items as subject
except ImportError:
    subject = None


class InventoryItemWireTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(subject, 'The bounded inventory codec is not implemented')

    def profile(self):
        return subject.InventoryWireProfile(subject.SHIPPING_SHA256, subject.CONTRACT_SHA256,
                                             delta_struct_mode=False, no_byteswap=True)

    def item(self):
        # Actual SafeBox HighValueItemList template, distinct local diagnostic gid.
        return subject.MinimalInventoryItem(category=1508005, sequence=6, item_gid=0x123456789,
            attach_position=0, location=subject.InventoryItemLocation(0, 0, 1, 1, False, 0),
            modified_timestamp=0.0, last_update_reason=0, temp_last_search_uin=0,
            is_raw_bound=False, bind_player_id=0, item_state=0, using_player_uin=0,
            cooldown_start_time=0.0, is_in_container=True, owner_player_id=0x1234,
            fallout_type=0, is_wanted_item=False)

    def encoded(self):
        writer = BitWriter()
        subject.write_minimal_item(writer, self.item(), profile=self.profile())
        return writer

    def test_runtime_contract_is_pinned_and_missing_or_changed_source_is_refused(self):
        pins = subject.inventory_source_pins()
        self.assertEqual(pins['protocol/portable-map-spawn/inventory-item-wire-contract.json'],
                         subject.CONTRACT_SHA256)
        root = subject.SERVER_ROOT
        raw = (root/next(iter(pins))).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), subject.CONTRACT_SHA256)
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            with self.assertRaises(ValueError): subject.inventory_source_pins(base)
            target = base/next(iter(pins)); target.parent.mkdir(parents=True)
            target.write_bytes(raw+b' ')
            with self.assertRaises(ValueError): subject.inventory_source_pins(base)

    def test_native_raw_prefix_and_unaligned_suffix_have_source_fixed_offsets(self):
        writer = self.encoded()
        self.assertEqual(writer.bit_count, 810)
        prefix = struct.pack('<IIQI4BI BfBQIQB QfIII'.replace(' ', ''),
            1508005, 6, 0x123456789, 0, 0, 0, 1, 1, 0, 0, 0.0, 0, 0, 0, 0, 0, 0, 0.0, 1, 0, 0)
        self.assertEqual(len(prefix), 79)
        self.assertEqual(writer.to_bytes()[:79], prefix)
        raw_value = int.from_bytes(writer.to_bytes(), 'little')
        self.assertEqual((raw_value >> 639) & ((1 << 64)-1), 0x1234)
        self.assertEqual(raw_value >> 703, 0)
        reader = BitReader(writer.to_bytes(), bit_count=writer.bit_count)
        decoded = subject.read_minimal_item(reader, profile=self.profile())
        self.assertEqual(decoded, self.item())
        self.assertEqual((decoded.item_count, decoded.item_num_max), (1, 1))
        self.assertEqual(reader.remaining, 0)

    def test_fastarray_header_and_element_id_are_raw32_and_separate_from_item_id_and_gid(self):
        delta = subject.InventoryFastArrayDelta(7, -1, (42,),
            (subject.InventoryFastArrayElement(99, self.item()),))
        writer = BitWriter(); writer.write_bool(True)
        subject.write_standard_fast_array(writer, delta, profile=self.profile())
        self.assertEqual(writer.bit_count, 1+128+32+32+810)
        reader = BitReader(writer.to_bytes(), bit_count=writer.bit_count)
        self.assertTrue(reader.read_bool())
        self.assertEqual(reader.read_bytes(24), struct.pack('<6i', 7, -1, 1, 1, 42, 99))
        reader.position = 1
        decoded = subject.read_standard_fast_array(reader, profile=self.profile())
        self.assertEqual(decoded, delta)
        self.assertEqual(decoded.changed[0].item.template_id, 15080050006)
        self.assertNotEqual(decoded.changed[0].element_id, decoded.changed[0].item.item_gid)
        self.assertEqual(reader.remaining, 0)

    def test_multiple_elements_keep_the_second_raw_id_unaligned(self):
        delta = subject.InventoryFastArrayDelta(8, 7, (),
            (subject.InventoryFastArrayElement(1, self.item()),
             subject.InventoryFastArrayElement(2, dataclasses.replace(self.item(), item_gid=0x12345678a))))
        writer = BitWriter(); subject.write_standard_fast_array(writer, delta, profile=self.profile())
        self.assertEqual((int.from_bytes(writer.to_bytes(), 'little') >> (128+32+810)) & 0xffffffff, 2)
        reader = BitReader(writer.to_bytes(), bit_count=writer.bit_count)
        self.assertEqual(subject.read_standard_fast_array(reader, profile=self.profile()), delta)

    def test_multicount_optional_stack_is_refused_without_mutating_writer(self):
        for item in (dataclasses.replace(self.item(), item_count=2),
                     dataclasses.replace(self.item(), item_num_max=2),
                     dataclasses.replace(self.item(), item_count=True)):
            writer = BitWriter(); writer.write_bool(True)
            with self.assertRaises(ValueError): subject.write_minimal_item(writer, item, profile=self.profile())
            self.assertEqual((writer.bit_count, writer.to_bytes()), (1, b'\x01'))

    def test_truncation_and_unimplemented_optional_blocks_restore_reader_cursor(self):
        writer = self.encoded()
        for cut in (0, 31, 631, 638, 700, 809):
            reader = BitReader(writer.to_bytes(), bit_count=cut)
            with self.assertRaises(ValueError): subject.read_minimal_item(reader, profile=self.profile())
            self.assertEqual(reader.position, 0)
        for bit in (568, 600, 632, 706, 738, 772, 774, 806):
            value = int.from_bytes(writer.to_bytes(), 'little') | (1 << bit)
            reader = BitReader(value.to_bytes(len(writer.to_bytes()), 'little'), bit_count=810)
            with self.assertRaises(ValueError): subject.read_minimal_item(reader, profile=self.profile())
            self.assertEqual(reader.position, 0)

    def test_wrong_profile_and_capacity_do_not_mutate_writer(self):
        for profile in (dataclasses.replace(self.profile(), client_sha256='0'*64),
                        dataclasses.replace(self.profile(), source_sha256='0'*64),
                        dataclasses.replace(self.profile(), delta_struct_mode=True),
                        dataclasses.replace(self.profile(), no_byteswap=False)):
            writer = BitWriter(); writer.write_bool(True)
            with self.assertRaises(ValueError): subject.write_minimal_item(writer, self.item(), profile=profile)
            self.assertEqual((writer.bit_count, writer.to_bytes()), (1, b'\x01'))
        writer = BitWriter(maximum_bits=810); writer.write_bool(True)
        with self.assertRaises(ValueError): subject.write_minimal_item(writer, self.item(), profile=self.profile())
        self.assertEqual(writer.bit_count, 1)

    def test_duplicate_ids_negative_ids_and_native_count_bounds_are_refused(self):
        for delta in (subject.InventoryFastArrayDelta(1, 0, (1, 1), ()),
                      subject.InventoryFastArrayDelta(1, 0, (-1,), ()),
                      subject.InventoryFastArrayDelta(1, 0, (1,), (subject.InventoryFastArrayElement(1, self.item()),)),
                      subject.InventoryFastArrayDelta(1, 0, tuple(range(2049)), ())):
            writer = BitWriter()
            with self.assertRaises(ValueError): subject.write_standard_fast_array(writer, delta, profile=self.profile())
            self.assertEqual(writer.bit_count, 0)
        for count in (-1, 2049):
            reader = BitReader(struct.pack('<4i', 1, 0, count, 0))
            with self.assertRaises(ValueError): subject.read_standard_fast_array(reader, profile=self.profile())
            self.assertEqual(reader.position, 0)


if __name__ == '__main__':
    unittest.main()
