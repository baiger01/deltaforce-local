"""A dynamic instance followup must retain its actual creation binding."""
from dataclasses import replace
import unittest

from dfserver.legacy_ds_bit_archive import BitReader, BitWriter


class DynamicObjectUpdateTests(unittest.TestCase):
    def module(self):
        from dfserver import legacy_ds_dynamic_object_update
        return legacy_ds_dynamic_object_update

    def update(self):
        return self.module().DynamicObjectUpdate(2, 44, 77,
            '/Game/BluePrints/Characters/CharacterFSM/DFMCharacterFSM_Main.DFMCharacterFSM_Main_C',
            'a' * 64, b'\0\0', 9)

    def test_dynamic_followup_retains_guid_and_class_without_name_export(self):
        update = self.update()
        writer = BitWriter(maximum_bits=256)
        self.module().write_update(writer, update, actor_guids=(2, 4),
            object_bindings=((44, 2, 77, update.class_path),))
        reader = BitReader(writer.to_bytes(), bit_count=writer.bit_count)
        self.assertTrue(reader.read_bool())
        self.assertFalse(reader.read_bool())
        self.assertEqual(reader.read_packed_int(), 44)
        self.assertFalse(reader.read_bool())
        self.assertEqual(reader.read_packed_int(), 77)
        self.assertEqual(reader.read_packed_int(), 9)
        self.assertEqual(reader.read_bits(9), 0)
        self.assertEqual(reader.remaining, 0)

    def test_missing_creation_foreign_actor_class_or_guid_reject_before_writing(self):
        update = self.update()
        for bindings in ((), ((46, 2, 77, update.class_path),),
                ((44, 4, 77, update.class_path),), ((44, 2, 79, update.class_path),),
                ((44, 2, 77, '/Script/CoreUObject.Object'),)):
            writer = BitWriter(maximum_bits=256)
            with self.subTest(bindings=bindings), self.assertRaises(ValueError):
                self.module().write_update(writer, update, actor_guids=(2, 4),
                    object_bindings=bindings)
            self.assertEqual(writer.bit_count, 0)

    def test_payload_width_bounds_and_noncanonical_padding_are_checked(self):
        update = self.update()
        for bad in (replace(update, payload=b'\0'), replace(update, payload=b'\0\xff'),
                replace(update, payload_bit_count=8193), replace(update, guid=77),
                replace(update, actor_guid=44), replace(update, source_sha256='invalid')):
            writer = BitWriter(maximum_bits=256)
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.module().write_update(writer, bad, actor_guids=(2, 4),
                    object_bindings=((44, 2, 77, update.class_path),))
            self.assertEqual(writer.bit_count, 0)


if __name__ == '__main__':
    unittest.main()
