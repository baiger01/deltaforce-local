"""Bind scalar value writers to actual collected native command metadata.

This selects an explicit command in an existing class/driver layout. It emits
value bits only; relative handles, scopes, property-stream framing, initial
values, possession and gameplay Ready are not invented or sent here.
"""
from dataclasses import dataclass
import json

from native_actor_bootstrap import _address, _identity, _report, _source_pin
from dfserver.legacy_ds_scalar_serializers import (
    NativeScalarBinding, SHIPPING_SHA256, BOOL_SERIALIZER_RVA, INT32_SERIALIZER_RVA,
    INT32_SCALAR_LEAF_RVA, INT32_PROPERTY_VTABLE_RVA, OBJECT_SERIALIZER_RVA,
    write_bool_value, write_int32_value, write_resolved_object_reference,
)

IMAGE_SIZE = 536408064


@dataclass(frozen=True)
class ScalarCommandBinding:
    metadata_source_relative_path: str
    metadata_source_sha256: str
    class_name: str
    driver_address: int
    command_index: int
    descriptor_name: str
    relative_handle: int
    parent_index: int
    scalar_kind: str
    native_binding: NativeScalarBinding

    def write_value(self, writer, value, *, no_byteswap=None,
                    reference_resolved=None, exports_acknowledged=None, export_mode=None):
        if self.scalar_kind == 'bool':
            return write_bool_value(writer, value, binding=self.native_binding)
        if self.scalar_kind == 'int32':
            return write_int32_value(writer, value, binding=self.native_binding, no_byteswap=no_byteswap)
        if self.scalar_kind == 'object_reference':
            return write_resolved_object_reference(writer, value, binding=self.native_binding,
                export_mode=export_mode, reference_resolved=reference_resolved,
                exports_acknowledged=exports_acknowledged)
        raise ValueError('Unsupported scalar binding kind')


def _method(row, slot):
    if (type(row) is not dict or type(row.get('slot')) is not int or row['slot'] != slot or
            row.get('status') != 'observed_pinned_image_method' or
            row.get('inside_pinned_image') is not True or row.get('identity_rechecked') is not True or
            row.get('target_module_sha256') != SHIPPING_SHA256):
        raise ValueError('A rechecked source-selected method in the pinned image is required')
    target, table = _address(row.get('target_address')), _address(row.get('vtable_address'))
    rva, table_rva = row.get('target_rva'), row.get('vtable_rva')
    if (type(rva) is not int or not 0 <= rva < IMAGE_SIZE or
            type(table_rva) is not int or not 0 <= table_rva <= IMAGE_SIZE - slot - 8):
        raise ValueError('An observed method/table RVA within the pinned image is required')
    base = _address(target - rva)
    if table - base != table_rva:
        raise ValueError('Method and table observations disagree on their module base')
    return rva, table_rva, base


def bind_scalar_command(metadata_report, *, source_relative_path, source_sha256,
                        class_name, driver_address, command_index):
    """Select by actual class, driver and command index, never by a guessed type."""
    _source_pin(source_relative_path, source_sha256, verified=True)
    roots = _report(metadata_report, source_sha256)
    if type(class_name) is not str or type(command_index) is not int or not 0 <= command_index <= 65535:
        raise ValueError('An explicit class name and bounded actual command index are required')
    _address(driver_address)
    class_rows, driver_rows = roots.get('classes'), roots.get('drivers')
    if (type(class_rows) is not list or len(class_rows) > 512 or
            any(type(row) is not dict for row in class_rows) or
            type(driver_rows) is not list or len(driver_rows) > 512 or
            any(type(row) is not dict for row in driver_rows)):
        raise ValueError('Bounded rechecked class and driver collections are required')
    classes = [row for row in class_rows if row.get('name') == class_name]
    drivers = [row for row in driver_rows if row.get('address') == driver_address]
    if len(classes) != 1 or len(drivers) != 1:
        raise ValueError('Exactly one rechecked class and selected driver are required')
    klass, driver = classes[0], drivers[0]
    _identity(klass)
    _identity(driver)
    if klass['key'] is None:
        raise ValueError('An initialized native class weak key is required')
    report = json.loads(metadata_report)  # Already hash/duplicate/nonfinite checked by _report.
    rows = report.get('driver_class_exports')
    if type(rows) is not list or len(rows) > 512 or any(type(row) is not dict for row in rows):
        raise ValueError('Bounded existing class/driver exports are required')
    selected = [row for row in rows if row.get('class_address') == klass['address'] and
                row.get('class_name') == class_name and row.get('driver_address') == driver_address]
    if len(selected) != 1:
        raise ValueError('Exactly one existing class/driver layout is required')
    row = selected[0]
    _address(row.get('class_address'))
    _address(row.get('driver_address'))
    if (row.get('class_key') != klass['key'] or row.get('layout_status') != 'exported_existing' or
            row.get('native_getter_invoked') is not False):
        raise ValueError('The existing layout must bind the actual selected class key')
    layout = row.get('layout')
    commands = layout.get('commands') if type(layout) is dict else None
    if type(commands) is not list or len(commands) > 65536 or any(type(item) is not dict for item in commands):
        raise ValueError('A bounded actual command list is required')
    if any(type(item.get('command_index')) is not int or
           not 0 <= item['command_index'] <= 65535 for item in commands):
        raise ValueError('Actual command indices must be bounded integers')
    found = [item for item in commands if item.get('command_index') == command_index]
    if len(found) != 1:
        raise ValueError('Exactly one actual command is required')
    command = found[0]
    _address(command.get('descriptor_address'))
    handle, parent, label = command.get('relative_handle'), command.get('parent_index'), command.get('descriptor_name')
    if (type(handle) is not int or not 1 <= handle <= 65535 or
            type(parent) is not int or not 0 <= parent < 65535 or
            type(label) is not str or not 0 < len(label) <= 1024 or
            type(command.get('dispatch_opcode')) is not int or
            not 0 <= command['dispatch_opcode'] <= 255 or command['dispatch_opcode'] in (0, 1)):
        raise ValueError('A non-container scalar command with actual labels and handle is required')
    target, table, base = _method(command.get('property_serializer_hook'), 0x90)
    leaf = None
    if target == BOOL_SERIALIZER_RVA:
        kind = 'bool'
    elif target == OBJECT_SERIALIZER_RVA:
        kind = 'object_reference'
    elif target == INT32_SERIALIZER_RVA:
        leaf, leaf_table, leaf_base = _method(command.get('property_scalar_leaf_hook'), 0x88)
        if (leaf != INT32_SCALAR_LEAF_RVA or table != INT32_PROPERTY_VTABLE_RVA or
                leaf_table != table or leaf_base != base):
            raise ValueError('The generic numeric hook does not prove the signed-int32 leaf/type')
        kind = 'int32'
    else:
        raise ValueError('The observed native serializer has no recovered scalar subset')
    binding = NativeScalarBinding(SHIPPING_SHA256, target, scalar_leaf_target_rva=leaf,
                                  property_vtable_rva=table)
    return ScalarCommandBinding(source_relative_path, source_sha256, class_name, driver_address,
                                command_index, label, handle, parent, kind, binding)
