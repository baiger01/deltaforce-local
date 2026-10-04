"""Literal offline report-to-value tests; no metadata or process API is called."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
import json
import unittest

from native_scalar_command_binding import bind_scalar_command
from dfserver.legacy_ds_bit_archive import BitReader, BitWriter
from dfserver.legacy_ds_scalar_serializers import (
    SHIPPING_SHA256, BOOL_SERIALIZER_RVA, INT32_SERIALIZER_RVA,
    INT32_SCALAR_LEAF_RVA, INT32_PROPERTY_VTABLE_RVA, OBJECT_SERIALIZER_RVA,
)


SOURCE = 'work/tests/literal-scalar-metadata.json'
CLASS_NAME = 'BP_DFMCharacter_C'
CLASS_ADDRESS = 0x600020000
DRIVER_ADDRESS = 0x600040000
MODULE_BASE = 0x140000000


def hook(slot, target, table):
    return dict(slot=slot, status='observed_pinned_image_method',
                inside_pinned_image=True, identity_rechecked=True,
                target_module_sha256=SHIPPING_SHA256,
                target_address=MODULE_BASE+target, target_rva=target,
                vtable_address=MODULE_BASE+table, vtable_rva=table)


def literal_report():
    # Keys are independent literal little-endian index/i32 + serial/u32 bytes.
    klass = dict(name=CLASS_NAME, address=CLASS_ADDRESS, object_index=33,
                 serial=0xffffffff, key='21000000ffffffff')
    driver = dict(address=DRIVER_ADDRESS, object_index=47, serial=500,
                  key='2f000000f4010000')
    commands = [
        dict(command_index=7, descriptor_address=0x700010000,
             descriptor_name='SyntheticBool', relative_handle=731, parent_index=6,
             dispatch_opcode=3,
             property_serializer_hook=hook(0x90, BOOL_SERIALIZER_RVA, 0x15a868a0)),
        dict(command_index=12, descriptor_address=0x700020000,
             descriptor_name='SyntheticInt', relative_handle=905, parent_index=9,
             dispatch_opcode=5,
             property_serializer_hook=hook(0x90, INT32_SERIALIZER_RVA, INT32_PROPERTY_VTABLE_RVA),
             property_scalar_leaf_hook=hook(0x88, INT32_SCALAR_LEAF_RVA, INT32_PROPERTY_VTABLE_RVA)),
        dict(command_index=19, descriptor_address=0x700030000,
             descriptor_name='SyntheticObject', relative_handle=1115, parent_index=11,
             dispatch_opcode=8,
             property_serializer_hook=hook(0x90, OBJECT_SERIALIZER_RVA, 0x15a869d0)),
    ]
    return dict(kind='existing_native_replication_metadata_export',
                status='metadata_export_complete', client_sha256=SHIPPING_SHA256,
                roots=dict(selected_roots_rechecked=True, classes=[klass], drivers=[driver]),
                driver_class_exports=[dict(class_address=CLASS_ADDRESS,
                    class_name=CLASS_NAME, driver_address=DRIVER_ADDRESS,
                    class_key='21000000ffffffff', layout_status='exported_existing',
                    native_getter_invoked=False, layout=dict(commands=commands))])


def encode(report):
    return json.dumps(report, sort_keys=True, separators=(',', ':')).encode('utf-8')


def bind(report=None, index=7, **changes):
    raw = encode(literal_report() if report is None else report)
    arguments = dict(source_relative_path=SOURCE, source_sha256=hashlib.sha256(raw).hexdigest(),
                     class_name=CLASS_NAME, driver_address=DRIVER_ADDRESS, command_index=index)
    arguments.update(changes)
    return bind_scalar_command(raw, **arguments)


def command(report, ordinal=0):
    return report['driver_class_exports'][0]['layout']['commands'][ordinal]


class NativeScalarCommandBindingTests(unittest.TestCase):
    def test_observed_bool_binding_retains_actual_label_handle_and_source(self):
        binding = bind()
        self.assertEqual((binding.class_name, binding.driver_address, binding.command_index),
                         (CLASS_NAME, DRIVER_ADDRESS, 7))
        self.assertEqual((binding.descriptor_name, binding.relative_handle, binding.parent_index),
                         ('SyntheticBool', 731, 6))
        self.assertEqual(binding.scalar_kind, 'bool')
        self.assertEqual(binding.metadata_source_relative_path, SOURCE)
        self.assertEqual(binding.metadata_source_sha256, hashlib.sha256(encode(literal_report())).hexdigest())
        with self.assertRaises(FrozenInstanceError):
            binding.relative_handle = 1

    def test_binding_appends_bool_value_only_at_current_cursor(self):
        writer = BitWriter()
        writer.write_bits(5, 3)
        self.assertEqual(bind().write_value(writer, True), 1)
        self.assertEqual((writer.to_bytes(), writer.bit_count), (b'\x0d', 4))

    def test_exact_generic_leaf_and_table_bind_raw32_value_only(self):
        binding = bind(index=12)
        self.assertEqual(binding.scalar_kind, 'int32')
        self.assertEqual(binding.native_binding.scalar_leaf_target_rva, 0x286bf70)
        self.assertEqual(binding.native_binding.property_vtable_rva, 0x15a863c0)
        writer = BitWriter()
        writer.write_bits(5, 3)
        self.assertEqual(binding.write_value(writer, 258, no_byteswap=True), 32)
        # prefix5/3b + raw02010000/32b; neither handle905 nor parent9 is emitted.
        self.assertEqual((writer.to_bytes(), writer.bit_count), (bytes.fromhex('1508000000'), 35))

    def test_resolved_object_binding_emits_ordinary_guid_only(self):
        writer = BitWriter()
        writer.write_bits(5, 3)
        binding = bind(index=19)
        self.assertEqual(binding.scalar_kind, 'object_reference')
        self.assertEqual(binding.write_value(writer, 255, export_mode=False,
            reference_resolved=True, exports_acknowledged=True), 16)
        self.assertEqual((writer.to_bytes(), writer.bit_count), (bytes.fromhex('fd1700'), 19))

    def test_multiple_bound_values_have_literal_cursor_and_no_property_framing(self):
        writer = BitWriter()
        writer.write_bits(5, 3)
        bind().write_value(writer, True)
        bind(index=12).write_value(writer, 0x12345678, no_byteswap=True)
        bind(index=19).write_value(writer, 255, export_mode=False,
            reference_resolved=True, exports_acknowledged=True)
        writer.write_bits(0xa5, 8)
        self.assertEqual((writer.to_bytes(), writer.bit_count),
                         (bytes.fromhex('8d674523f12f500a'), 60))
        reader = BitReader(writer.to_bytes(), bit_count=60)
        self.assertEqual(reader.read_bits(3), 5)
        self.assertTrue(reader.read_bool())
        self.assertEqual(reader.read_bytes(4), bytes.fromhex('78563412'))
        self.assertEqual(reader.read_packed_int(), 255)
        self.assertEqual(reader.read_bits(8), 0xa5)
        self.assertEqual(reader.remaining, 0)

    def test_missing_and_duplicate_actual_class_are_rejected(self):
        for change in ('missing', 'duplicate'):
            report = literal_report()
            rows = report['roots']['classes']
            rows.clear() if change == 'missing' else rows.append(deepcopy(rows[0]))
            with self.subTest(change=change), self.assertRaises(ValueError):
                bind(report)

    def test_malformed_root_collections_are_fail_closed_value_errors(self):
        for collection in ('classes', 'drivers'):
            for value in (None, {}, 'not-a-list', 1):
                report = literal_report()
                report['roots'][collection] = value
                with self.subTest(collection=collection, value=value), self.assertRaises(ValueError):
                    bind(report)

    def test_missing_duplicate_and_wrong_selected_driver_are_rejected(self):
        for change in ('missing', 'duplicate', 'wrong'):
            report = literal_report()
            rows = report['roots']['drivers']
            if change == 'missing':
                rows.clear()
            elif change == 'duplicate':
                rows.append(deepcopy(rows[0]))
            else:
                rows[0]['address'] += 0x1000
            with self.subTest(change=change), self.assertRaises(ValueError):
                bind(report)

    def test_wrong_class_driver_or_nonmatching_class_weak_key_layout_is_rejected(self):
        for field, value in (('class_name', 'BP_Other_C'), ('class_address', CLASS_ADDRESS+0x1000),
                             ('driver_address', DRIVER_ADDRESS+0x1000), ('class_key', '2100000001000000')):
            report = literal_report()
            report['driver_class_exports'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                bind(report)

    def test_zero_or_inconsistent_root_weak_key_is_rejected(self):
        for root in ('classes', 'drivers'):
            report = literal_report()
            report['roots'][root][0]['key'] = '0000000000000000'
            with self.subTest(root=root), self.assertRaises(ValueError):
                bind(report)
        report = literal_report()
        report['roots']['classes'][0].update(serial=0, key=None)
        with self.assertRaises(ValueError):
            bind(report)

    def test_missing_and_duplicate_driver_class_exports_are_rejected(self):
        for value in (None, [], [literal_report()['driver_class_exports'][0]]*2):
            report = literal_report()
            report['driver_class_exports'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                bind(report)

    def test_report_source_and_completion_qualification_are_required(self):
        for field, value in (('status', 'metadata_export_partial'), ('client_sha256', 'a'*64),
                             ('kind', 'other')):
            report = literal_report()
            report[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                bind(report)
        report = literal_report()
        report['roots']['selected_roots_rechecked'] = False
        with self.assertRaises(ValueError):
            bind(report)
        with self.assertRaises(ValueError):
            bind(source_sha256='b'*64)
        for path in ('../report.json', '/report.json', 'C:/report.json', 'work\\report.json'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                bind(source_relative_path=path)

    def test_unexported_or_native_invoked_layout_is_rejected(self):
        for field, value in (('layout_status', 'missing'), ('native_getter_invoked', True),
                             ('native_getter_invoked', None)):
            report = literal_report()
            report['driver_class_exports'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                bind(report)

    def test_missing_duplicate_or_null_descriptor_command_is_rejected(self):
        for change in ('missing', 'duplicate', 'null_descriptor'):
            report = literal_report()
            commands = report['driver_class_exports'][0]['layout']['commands']
            if change == 'missing':
                commands.pop(0)
            elif change == 'duplicate':
                commands.append(deepcopy(commands[0]))
            else:
                commands[0]['descriptor_address'] = 0
            with self.subTest(change=change), self.assertRaises(ValueError):
                bind(report)

    def test_observed_command_index_cannot_alias_integer_through_bool_or_float(self):
        for value in (True, 1.0):
            report = literal_report()
            command(report)['command_index'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                bind(report, index=1)

    def test_container_terminal_invalid_handle_label_and_parent_are_rejected(self):
        for field, value in (('dispatch_opcode', 0), ('dispatch_opcode', 1),
                             ('dispatch_opcode', True), ('relative_handle', 0),
                             ('relative_handle', True), ('parent_index', 65535),
                             ('descriptor_name', ''), ('descriptor_name', None)):
            report = literal_report()
            command(report)[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                bind(report)

    def test_unknown_missing_or_unrechecked_hook_is_rejected(self):
        for field, value in (('target_rva', 0x10e8ec50), ('identity_rechecked', False),
                             ('inside_pinned_image', False), ('slot', 0x88),
                             ('status', 'foreign_target'), ('target_module_sha256', 'a'*64)):
            report = literal_report()
            observed = command(report)['property_serializer_hook']
            observed[field] = value
            if field == 'target_rva':
                observed['target_address'] = MODULE_BASE+value
            with self.subTest(field=field), self.assertRaises(ValueError):
                bind(report)
        report = literal_report()
        command(report).pop('property_serializer_hook')
        with self.assertRaises(ValueError):
            bind(report)

    def test_method_addresses_must_agree_on_pinned_module_base(self):
        for field in ('target_address', 'vtable_address'):
            report = literal_report()
            command(report)['property_serializer_hook'][field] += 0x1000
            with self.subTest(field=field), self.assertRaises(ValueError):
                bind(report)

    def test_generic_numeric_requires_rechecked_leaf_and_exact_int_table(self):
        for change in ('absent_leaf', 'wrong_leaf', 'wrong_table', 'leaf_unrechecked', 'different_base'):
            report = literal_report()
            selected = command(report, 1)
            if change == 'absent_leaf':
                selected.pop('property_scalar_leaf_hook')
            elif change == 'wrong_leaf':
                leaf = selected['property_scalar_leaf_hook']
                leaf['target_rva'] += 1
                leaf['target_address'] += 1
            elif change == 'wrong_table':
                for field in ('property_serializer_hook', 'property_scalar_leaf_hook'):
                    selected[field]['vtable_rva'] += 8
                    selected[field]['vtable_address'] += 8
            elif change == 'leaf_unrechecked':
                selected['property_scalar_leaf_hook']['identity_rechecked'] = False
            else:
                selected['property_scalar_leaf_hook']['target_address'] += 0x1000
                selected['property_scalar_leaf_hook']['vtable_address'] += 0x1000
            with self.subTest(change=change), self.assertRaises(ValueError):
                bind(report, index=12)

    def test_writer_profile_value_and_object_contract_rejections_are_atomic(self):
        for index, value, options in ((7, 1, {}), (12, 258, {}),
                (12, 258, {'no_byteswap': False}), (19, 255, {}),
                (19, 255, {'export_mode':True, 'reference_resolved':True, 'exports_acknowledged':True}),
                (19, 1, {'export_mode':False, 'reference_resolved':True, 'exports_acknowledged':True})):
            writer = BitWriter()
            writer.write_bits(5, 3)
            before = writer.to_bytes(), writer.bit_count
            with self.subTest(index=index, options=options), self.assertRaises(ValueError):
                bind(index=index).write_value(writer, value, **options)
            self.assertEqual((writer.to_bytes(), writer.bit_count), before)

    def test_bound_writer_capacity_failure_preserves_previous_cursor(self):
        writer = BitWriter(maximum_bits=34)
        writer.write_bits(5, 3)
        before = writer.to_bytes(), writer.bit_count
        with self.assertRaises(ValueError):
            bind(index=12).write_value(writer, 258, no_byteswap=True)
        self.assertEqual((writer.to_bytes(), writer.bit_count), before)


if __name__ == '__main__':
    unittest.main()
