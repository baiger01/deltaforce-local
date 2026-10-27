import struct
import unittest

from extract_native_safehouse_catalog import field_value


class DepartmentFieldTests(unittest.TestCase):
    def test_unsigned_objective_item_list_keeps_full_width(self):
        raw = struct.pack('<iQQ', 2, 10010001050, 14020000004)
        self.assertEqual(field_value(raw, {'value_start': 0, 'end': len(raw), 'metadata_bytes': 8},
                                     'TArray<uint64>'), [10010001050, 14020000004])

    def test_objective_enum_name_arrays_remain_opaque(self):
        raw = struct.pack('<iII', 1, 122, 0)
        self.assertEqual(field_value(raw, {'value_start': 0, 'end': len(raw), 'metadata_bytes': 8},
                                     'TArray<EInGameBattleClassType>'),
                         [{'fname_hex': '7a00000000000000'}])

    def test_objective_vector_requires_struct_metadata_and_three_floats(self):
        raw = struct.pack('<fff', 1.0, 2.0, 3.0)
        self.assertEqual(field_value(raw, {'value_start': 0, 'end': len(raw), 'metadata_bytes': 24},
                                     'FVector'), [1.0, 2.0, 3.0])
        with self.assertRaises(ValueError):
            field_value(raw, {'value_start': 0, 'end': len(raw), 'metadata_bytes': 0}, 'FVector')
