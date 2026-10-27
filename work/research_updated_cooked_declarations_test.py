"""Pure malformed-package checks for the independent cooked declaration audit."""
import struct
import unittest
import copy
import json
from pathlib import Path

from research_updated_cooked_declarations import parse_package
from research_updated_cooked_field_stream import parse_class_stream


def fixture():
    names = ['None', '/Game/Test/BP_Test', '/Script/CoreUObject', 'Package',
        '/Script/Engine', 'Class', 'BlueprintGeneratedClass', 'BP_Test_C',
        'Default__BP_Test_C', '/Script/GPGameplay', 'NativeParent']
    encoded = b''.join(struct.pack('<i', len(n)+1)+n.encode()+b'\0'+bytes(4) for n in names)
    io = 96+len(encoded)
    eo = io+4*28
    header = bytearray(eo+2*104)
    header[:4] = bytes.fromhex('c1832a9e')
    struct.pack_into('<i', header, 20, 0)
    struct.pack_into('<ii', header, 41, len(names), 96)
    struct.pack_into('<5i', header, 57, 2, eo, 4, io, len(header))
    header[96:io] = encoded

    def name(at, value):
        struct.pack_into('<ii', header, at, names.index(value), 0)

    for index, (cls, outer, value) in enumerate((
            ('Package', 0, '/Script/Engine'), ('Class', -1, 'BlueprintGeneratedClass'),
            ('Class', -4, 'NativeParent'), ('Package', 0, '/Script/GPGameplay'))):
        at = io+index*28
        name(at, '/Script/CoreUObject'); name(at+8, cls)
        struct.pack_into('<i', header, at+16, outer); name(at+20, value)
    for index, (cls, sup, flags, value, size, offset) in enumerate((
            (-2, -3, 1, 'BP_Test_C', 10, 0), (1, 0, 0x10, 'Default__BP_Test_C', 8, 10))):
        at = eo+index*104
        struct.pack_into('<4i', header, at, cls, sup, 0, 0)
        name(at+16, value)
        struct.pack_into('<Iqq', header, at+24, flags, size, len(header)+offset)
    return bytes(header), bytes(8)+b'\xaa\xbb'+bytes(8)+bytes.fromhex('c1832a9e'), eo


class CookedDeclarationTests(unittest.TestCase):
    def test_serialized_class_cdo_and_native_parent_are_distinct_from_runtime(self):
        h, p, _ = fixture()
        report = parse_package(h, p, 'BP_Test')
        self.assertEqual(report['package_path'], '/Game/Test/BP_Test')
        self.assertEqual(report['class_export']['super_reference'], ['/Script/GPGameplay', 'NativeParent'])
        self.assertEqual(report['cdo_export']['class_index'], report['class_export']['index'])
        self.assertEqual(report['class_export']['remaining_export_bytes'], 2)
        self.assertEqual(report['cdo_export']['tagged_properties'], [])
        self.assertFalse(report['runtime_cached_cdo_pointer_observed'])

    def test_nonsequential_or_truncated_exports_are_rejected(self):
        h, p, eo = fixture()
        for offset in (len(h)-1, len(h)+1, len(h)+100):
            broken = bytearray(h)
            struct.pack_into('<q', broken, eo+36, offset)
            with self.assertRaises(ValueError): parse_package(bytes(broken), p, 'BP_Test')
        with self.assertRaises(ValueError): parse_package(h, p[:-1], 'BP_Test')
        with self.assertRaises(ValueError): parse_package(h, p[:-4]+b'x'+p[-4:], 'BP_Test')

    def test_wrong_cdo_class_flags_and_ambiguous_root_fail_closed(self):
        h, p, eo = fixture()
        for field, value in ((eo+104, -3), (eo+104+24, 0)):
            broken = bytearray(h)
            struct.pack_into('<i', broken, field, value)
            with self.assertRaises(ValueError): parse_package(bytes(broken), p, 'BP_Test')
        with self.assertRaises(ValueError): parse_package(h, p, 'WrongPackage')

    def test_outside_references_and_reference_cycles_are_rejected(self):
        h, p, eo = fixture()
        for offset, value in ((eo+4, -100), (eo+4, 1), (eo+12, 2)):
            broken = bytearray(h)
            struct.pack_into('<i', broken, offset, value)
            with self.assertRaises(ValueError): parse_package(bytes(broken), p, 'BP_Test')


class CookedFieldStreamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        report = Path(__file__).with_name('research_updated_cooked_declarations_79fb7b10_v5.json')
        cls.packages = json.loads(report.read_bytes())['packages']

    def test_complete_pc_gs_ps_fields_and_empty_own_interfaces(self):
        for stem, count in (('BP_DFMPlayerController', 15), ('BP_GameState_PVPVE', 5), ('BP_SOLPlayerState', 1)):
            package = next(p for p in self.packages if p['package_path'].endswith('/'+stem))
            result = parse_class_stream(package)
            self.assertTrue(result['complete'])
            self.assertEqual(result['declared_field_count'], count)
            self.assertEqual(result['own_net_property_count'], 0)
            self.assertEqual(result['own_interfaces'], [])
            self.assertFalse(result['class_net_cache_indices_recovered'])

    def test_unknown_branch_or_conflicting_duplicate_versions_fail_closed(self):
        package = copy.deepcopy(self.packages[-1])
        package['custom_versions'][0]['value'] = -1
        # A duplicate GUID is ambiguous even if another occurrence is expected.
        package['custom_versions'].append(copy.deepcopy(self.packages[-1]['custom_versions'][0]))
        with self.assertRaises(ValueError): parse_class_stream(package)

    def test_wrong_super_cdo_or_extra_native_bytes_fail_closed(self):
        for mutation in ('super', 'cdo', 'extra'):
            package = copy.deepcopy(self.packages[-1])
            raw = bytearray.fromhex(package['class_export']['remaining_export_bytes_hex'])
            if mutation == 'super': struct.pack_into('<i', raw, 4, 0)
            elif mutation == 'cdo': struct.pack_into('<i', raw, len(raw)-4, package['class_export']['index'])
            else: raw.extend(b'\0\0')
            package['class_export']['remaining_export_bytes_hex'] = raw.hex()
            with self.assertRaises(ValueError): parse_class_stream(package)

    def test_property_net_flag_does_not_publish_serialized_zero_as_handle(self):
        package = copy.deepcopy(self.packages[-1])
        raw = bytearray.fromhex(package['class_export']['remaining_export_bytes_hex'])
        flags, = struct.unpack_from('<Q', raw, 44)
        struct.pack_into('<Q', raw, 44, flags|0x20)
        package['class_export']['remaining_export_bytes_hex'] = raw.hex()
        result = parse_class_stream(package)
        self.assertEqual(result['own_net_property_count'], 1)
        self.assertEqual(result['fields'][0]['serialized_rep_index'], 0)
        self.assertFalse(result['fields'][0]['serialized_rep_index_is_current_wire_handle'])

    def test_nonempty_interface_branch_is_outside_this_qualified_subset(self):
        package = copy.deepcopy(self.packages[-1])
        raw = bytearray.fromhex(package['class_export']['remaining_export_bytes_hex'])
        struct.pack_into('<i', raw, 99, 1)
        raw[103:103] = struct.pack('<iii', -8, 8, 0)
        package['class_export']['remaining_export_bytes_hex'] = raw.hex()
        with self.assertRaises(ValueError): parse_class_stream(package)


if __name__ == '__main__':
    unittest.main()
