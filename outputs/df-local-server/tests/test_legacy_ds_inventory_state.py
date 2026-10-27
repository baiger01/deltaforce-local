from dataclasses import replace
from pathlib import Path
import struct
import tempfile
import unittest

from dfserver.legacy_ds_bit_archive import BitReader, BitWriter
from dfserver.legacy_ds_inventory_items import InventoryFastArrayDelta
from dfserver import legacy_ds_inventory_state as codec


class InventoryStateTests(unittest.TestCase):
    def setUp(self):
        self.profile = codec.InventoryStateProfile(codec.CLIENT_SHA256, codec.SCHEMA_SHA256, 13, True, False)
        self.state = codec.InventoryManagerRepData(True, 11, 12, 13, 14, 15, 16, 17, ())

    def test_empty_repdata_matches_independent_raw_grammar(self):
        writer = BitWriter()
        writer.write_bool(True)
        count = codec.write_inventory_repdata(writer, self.state, profile=self.profile)
        self.assertEqual(count, 480)
        reader = BitReader(writer.to_bytes(), bit_count=writer.bit_count)
        self.assertTrue(reader.read_bool())
        self.assertEqual(reader.read_bytes(60), struct.pack('<i6qii', 1, 11, 12, 13, 14, 15, 16, 17, 0))
        self.assertEqual(reader.remaining, 0)

    def test_real_equipment_space_types_and_signed_grid_bytes(self):
        grid = codec.InventorySpaceGrid(7, 0, 0, 1, 1, -1, -128)
        spaces = (codec.InventorySpace(101, 9, (grid,)), codec.InventorySpace(108, 10, ()))
        writer = BitWriter()
        codec.write_inventory_repdata(writer, replace(self.state, spaces=spaces), profile=self.profile)
        reader = BitReader(writer.to_bytes(), bit_count=writer.bit_count)
        self.assertEqual(codec.read_inventory_repdata(reader, profile=self.profile), replace(self.state, spaces=spaces))
        self.assertEqual(writer.bit_count, 480+96*2+176)
        self.assertEqual(reader.remaining, 0)

    def test_legacy_array_prefix_is_exactly_one_false_bit(self):
        delta = InventoryFastArrayDelta(4, -1, (), ())
        writer = BitWriter()
        self.assertEqual(codec.write_inventory_custom_delta(writer, delta, profile=self.profile), 129)
        reader = BitReader(writer.to_bytes(), bit_count=writer.bit_count)
        self.assertFalse(reader.read_bool())
        self.assertEqual(reader.read_bytes(16), struct.pack('<4i', 4, -1, 0, 0))
        reader = BitReader(writer.to_bytes(), bit_count=writer.bit_count)
        self.assertEqual(codec.read_inventory_custom_delta(reader, profile=self.profile), delta)

    def test_invalid_profile_or_space_is_atomic(self):
        writer = BitWriter()
        writer.write_bits(5, 3)
        for profile in (replace(self.profile, archive_network_version=10),
                        replace(self.profile, delta_struct_mode=True), replace(self.profile, no_byteswap=False)):
            with self.assertRaises(ValueError):
                codec.write_inventory_repdata(writer, self.state, profile=profile)
        with self.assertRaises(ValueError):
            codec.write_inventory_repdata(writer, replace(self.state, spaces=(codec.InventorySpace(987654, 0, ()),)), profile=self.profile)
        self.assertEqual((writer.to_bytes(), writer.bit_count), (b'\x05', 3))

    def test_bad_prefix_truncated_state_and_count_restore_cursor(self):
        reader = BitReader(b'\x01', bit_count=1)
        with self.assertRaises(ValueError):
            codec.read_inventory_custom_delta(reader, profile=self.profile)
        self.assertEqual(reader.position, 0)
        reader = BitReader(struct.pack('<i6qii', 1, 0, 0, 0, 0, 0, 0, 0, 65), bit_count=480)
        with self.assertRaises(ValueError):
            codec.read_inventory_repdata(reader, profile=self.profile)
        self.assertEqual(reader.position, 0)
        reader = BitReader(b'\x00', bit_count=8)
        with self.assertRaises(ValueError):
            codec.read_inventory_repdata(reader, profile=self.profile)
        self.assertEqual(reader.position, 0)

    def test_runtime_schema_source_pin_fails_closed(self):
        expected = {codec.SCHEMA_RELATIVE_PATH: codec.SCHEMA_SHA256}
        self.assertEqual(codec.inventory_state_source_pins(), expected)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/codec.SCHEMA_RELATIVE_PATH
            path.parent.mkdir(parents=True)
            path.write_bytes(b'{}')
            with self.assertRaises(ValueError):
                codec.inventory_state_source_pins(temp)


if __name__ == '__main__':
    unittest.main()
