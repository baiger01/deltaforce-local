"""Synthetic pointer-array tests; no fixture is a game metadata binding."""
import struct
import unittest

from research_updated_native_registration import decode_property_tree, derive_bool_storage, literal_bool
from research_updated_metadata_roots import decoder


class Fixture:
    def __init__(self):
        self.data = bytearray(8192)
        self.next_string = 4096

    def read(self, rva, size):
        if not 0 <= rva <= rva+size <= len(self.data):
            raise ValueError('Synthetic read outside fixture')
        return bytes(self.data[rva:rva+size])

    def field(self, rva, name, tag, offset=0, flags=0, dim=1):
        at = self.next_string
        raw = name.encode('ascii')+b'\0'
        self.data[at:at+len(raw)] = raw
        self.next_string += len(raw)
        struct.pack_into('<3Q4i', self.data, rva, at, 0, flags, tag, 0x45, dim, offset)

    def pointers(self, fields):
        for index, rva in enumerate(fields):
            struct.pack_into('<Q', self.data, 256+index*8, rva)
        return 256, len(fields)


GRAMMAR = {
    0: dict(kind='ByteProperty', nested_count=0, callback_offsets=[40], record_bytes=48),
    1: dict(kind='IntProperty', nested_count=0, callback_offsets=[], record_bytes=40),
    2: dict(kind='ArrayProperty', nested_count=1, callback_offsets=[], record_bytes=40),
    3: dict(kind='MapProperty', nested_count=2, callback_offsets=[], record_bytes=40),
}


class NativeRegistrationTreeTests(unittest.TestCase):
    def test_only_explicit_constant_boolean_leaves_are_accepted(self):
        self.assertIs(literal_bool(list(decoder().disasm(bytes.fromhex('b001c3'), 0))), True)
        self.assertIs(literal_bool(list(decoder().disasm(bytes.fromhex('30c0c3'), 0))), False)
        with self.assertRaises(ValueError): literal_bool(list(decoder().disasm(bytes.fromhex('c3'), 0)))
        with self.assertRaises(ValueError): literal_bool(list(decoder().disasm(bytes.fromhex('b002c3'), 0)))

    def test_bool_size_argument_is_not_reported_as_a_field_offset(self):
        fixture = Fixture(); fixture.field(512, 'Flag', 12, offset=1)
        struct.pack_into('<QQ', fixture.data, 512+40, 0x200, 0x300)
        first, count = fixture.pointers((512,))
        grammar = {12:dict(kind='FBoolProperty', nested_count=0, callback_offsets=[48], record_bytes=56)}
        field = decode_property_tree(fixture.read, first, count, grammar, image_base=0)['fields'][0]
        self.assertNotIn('constructor_offset_argument', field)
        self.assertEqual(field['bool_field_size_argument'], 1)
        self.assertEqual(field['bool_owner_size_argument'], 0x200)

    def test_bool_setter_is_interpreted_as_zero_buffer_write_without_execution(self):
        instructions = list(decoder().disasm(bytes.fromhex('80893412000002c3'), 0))
        self.assertEqual(derive_bool_storage(instructions, 0x2000),
            dict(storage_offset=0x1234, byte_mask=2))
        with self.assertRaises(ValueError): derive_bool_storage(instructions, 64)
        unsafe = list(decoder().disasm(bytes.fromhex('ff10c3'), 0))
        with self.assertRaises(ValueError): derive_bool_storage(unsafe, 64)

    def test_nested_records_do_not_alias_top_level_declarations(self):
        fixture = Fixture()
        fixture.field(512, 'Values', 2, offset=128)
        fixture.field(576, 'Inner', 1)
        fixture.field(640, 'Other', 1, offset=132, flags=0x20)
        first, count = fixture.pointers((512, 576, 640))
        report = decode_property_tree(fixture.read, first, count, GRAMMAR, image_base=0)
        self.assertEqual([r['name'] for r in report['fields']], ['Other', 'Values'])
        self.assertEqual(report['top_level_count'], 2)
        self.assertEqual(report['parameter_record_count'], 3)
        self.assertEqual(report['fields'][1]['children'][0]['name'], 'Inner')

    def test_map_consumes_both_nested_records_before_next_outer_field(self):
        fixture = Fixture()
        for rva, name, tag in ((512, 'Map', 3), (576, 'Key', 1), (640, 'Value', 2),
                (704, 'Inner', 1), (768, 'After', 1)):
            fixture.field(rva, name, tag)
        first, count = fixture.pointers((512, 576, 640, 704, 768))
        report = decode_property_tree(fixture.read, first, count, GRAMMAR, image_base=0)
        self.assertEqual([r['name'] for r in report['fields']], ['After', 'Map'])
        self.assertEqual([r['name'] for r in report['fields'][1]['children']], ['Key', 'Value'])

    def test_missing_children_and_unknown_tags_fail_closed(self):
        fixture = Fixture(); fixture.field(512, 'Values', 2)
        first, count = fixture.pointers((512,))
        with self.assertRaises(ValueError): decode_property_tree(fixture.read, first, count, GRAMMAR, image_base=0)
        fixture.field(512, 'Unknown', 36)
        with self.assertRaises(ValueError): decode_property_tree(fixture.read, first, count, GRAMMAR, image_base=0)

    def test_duplicate_record_identity_and_unbounded_dimensions_fail_closed(self):
        fixture = Fixture(); fixture.field(512, 'Field', 1)
        first, count = fixture.pointers((512, 512))
        with self.assertRaises(ValueError): decode_property_tree(fixture.read, first, count, GRAMMAR, image_base=0)
        fixture.field(512, 'Field', 1, dim=1000000)
        first, count = fixture.pointers((512,))
        with self.assertRaises(ValueError): decode_property_tree(fixture.read, first, count, GRAMMAR, image_base=0)


if __name__ == '__main__':
    unittest.main()
