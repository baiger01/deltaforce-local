"""Sparse StoreHot image reader with original-source and current typed gates.

The exact original PE owns the field schema. A separately verified current
UDataTable/RowStruct identity is verified before any sparse row fields are read.
This module performs no process access or client calls.
"""

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import struct

import read_live_storehot_metadata as metadata
import read_keybox_rowmap as rowmap_source
import storehot_native_schema as schema_source
import probe_live_datatable_rowstruct_code as owner_source

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_REPORT = 'work/evidence/storehot-native-schema-bundle-20261005.json'
SCHEMA_SHA = 'efee3f77ddb3af1b2c561d00e10069e3ae00e63a41841440b1e3f0493fdc5dfe'
ROWMAP_ACCESSOR_RVA = 0x14b1630
MAX_ROWS = 4096
MAX_STRING_CHARS = 1024
MAX_STRING_CAPACITY = 16384
MAX_TOTAL_READ = 2 * 1024 * 1024
TARGET_ROWS = {'3': 10101004, '7': 10101008, '18': 10101019, '39': 10102002}
TARGET_TABS = frozenset(TARGET_ROWS.values())
STRING_FIELDS = {'IamgeSourceSmall': 160, 'IamgeSourceBig': 176,
                 'ImageSourceLogo': 192, 'MoviesRowName': 224, 'BGVideoName': 248}
ASSET_PATH = re.compile(r"(?:[A-Za-z][A-Za-z0-9_]*')?/(?:Game|Engine)/[A-Za-z0-9_./-]+(?:')?\Z")
VIDEO_NAME = re.compile(r'[A-Za-z0-9_./-]*\Z')


@dataclass(frozen=True)
class Contract:
    metadata: object
    rowmap_blocks: tuple
    schema_digest: str
    runtime_rowstruct_evidence: object = None


def load_contract(root=ROOT, source_pe=None):
    """Load exact source schema/owner evidence; runtime rechecks every code span."""
    root = Path(root)
    raw = (root / SCHEMA_REPORT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != SCHEMA_SHA:
        raise ValueError('StoreHot_source_schema_report_changed')
    schema = json.loads(raw)
    if (schema.get('source_pe_sha256') != metadata.SOURCE_PE
            or schema.get('native_struct_name') != metadata.TARGET
            or schema.get('native_struct_size') != 392
            or schema.get('field_count') != 28):
        raise ValueError('StoreHot_owned_native_schema_changed')
    fields = {f['name']: (f['kind'], f['member_offset']) for f in schema['fields']}
    if any(fields.get(name) != identity for name, identity in schema_source.IMAGE_FIELDS.items()):
        raise ValueError('StoreHot_target_field_type_or_offset_changed')
    source = metadata.load_contract(root)
    old = json.loads((root / metadata.SOURCE_FILES[0][0]).read_bytes())
    accessor = old['keybox_rowmap']
    if (accessor['rowmap_accessor_rva'] != ROWMAP_ACCESSOR_RVA
            or bytes.fromhex(accessor['rowmap_accessor_code_hex'])[:5] != bytes.fromhex('488d4130c3')):
        raise ValueError('source_RowMap_accessor_changed')
    blocks = tuple((old['fixed_code'][key]['rva'], bytes.fromhex(old['fixed_code'][key]['bytes']))
                   for key in ('datatable_lite_rows_primary', 'datatable_lite_rows_secondary'))
    blocks += ((ROWMAP_ACCESSOR_RVA, bytes.fromhex('488d4130c3')),)
    all_blocks = source.blocks + blocks
    for rva, expected in rowmap_source.CODE_WITNESSES:
        matches = [raw[rva - at:rva - at + len(expected)] for at, raw in all_blocks
                   if at <= rva and rva + len(expected) <= at + len(raw)]
        if not matches or any(raw != expected for raw in matches):
            raise ValueError('RowMap_generic_source_witness_changed')
    owner = owner_source.load_owner_contract(root, source_pe)
    if (owner.get('source_rowstruct_owner_verified') is not True
            or owner.get('RowStruct_member_offset') != 40
            or owner.get('RowStruct_field_type') != 'UScriptStruct *'
            or owner.get('type_class_global_rva') != 0x1e340a98):
        raise ValueError('StoreHot_UDataTable_RowStruct_source_owner_changed')
    source = metadata.Contract(source.blocks + blocks + owner['blocks'], source.codec,
                               source.source_hashes + ((SCHEMA_REPORT, SCHEMA_SHA),)
                               + owner['source_hashes'])
    return Contract(source, blocks, SCHEMA_SHA, {
        'rowstruct_member_offset': owner['RowStruct_member_offset'],
        'rowstruct_class_global_rva': owner['type_class_global_rva'],
        'source_rowstruct_owner_verified': True})


class Session:
    """Internal sparse-field session. Every observed typed byte is rechecked."""

    def __init__(self, read, base, codec, *, shared_watch=None):
        self.read = read
        self.shared_watch = shared_watch
        self.base = base
        self.codec = codec
        self.total = 0
        self.watched = {}
        self.readset = []

    def exact(self, address, size, role):
        metadata._base(address, size)
        if size > 1024 or self.total + size > MAX_TOTAL_READ:
            raise metadata._Stop('image_row_read_budget_exceeded')
        self.total += size
        raw = self.shared_watch(address, size, role) if self.shared_watch else self.read(address, size)
        if not isinstance(raw, bytes) or len(raw) != size:
            raise metadata._Stop('short_image_row_read')
        self.readset.append({'address': hex(address), 'size': size, 'role': role})
        return raw

    def watch(self, address, size, role):
        raw = self.exact(address, size, role)
        key = address, size
        if key in self.watched and self.watched[key] != raw:
            raise metadata._Stop('image_row_metadata_changed')
        self.watched[key] = raw
        return raw

    def pointer(self, address, role):
        pointer = struct.unpack('<Q', self.watch(address, 8, role))[0]
        metadata._base(pointer)
        return pointer

    def name(self, token):
        comparison, number = struct.unpack('<II', token)
        if number or comparison >= 0x80000000:
            raise metadata._Stop('unsupported_row_name_token')
        slot = metadata.names.POOL_RVA + 8 + (comparison >> 18) * 8
        if not 0 <= slot < slot + 8 <= metadata.MODULE_SIZE:
            raise metadata._Stop('row_name_pool_slot_out_of_bounds')
        block = self.pointer(self.base + slot, 'row_name_pool_block')
        if block & 1:
            raise metadata._Stop('unaligned_row_name_pool_block')
        offset = (comparison & 0x3ffff) * 2
        header = self.watch(block + offset, 2, 'row_name_header')
        value = struct.unpack('<H', header)[0]
        length, wide = value >> 6, bool(value & 1)
        amount = length * (2 if wide else 1)
        if not 1 <= length <= 192 or offset + 2 + amount > 0x80000:
            raise metadata._Stop('row_name_payload_out_of_native_block')
        chars = self.watch(block + offset + 2, amount, 'row_name_chars')
        decoded = self.codec.decode_config_name(header + chars, 0)
        if not decoded or not decoded.isascii() or not VIDEO_NAME.fullmatch(decoded):
            raise metadata._Stop('row_name_not_public_asset_syntax')
        return decoded

    def string(self, row, field, offset):
        header = self.watch(row + offset, 16, field + '_FString_header')
        pointer, length, capacity = struct.unpack('<Qii', header)
        if not 0 <= length <= MAX_STRING_CHARS or not length <= capacity <= MAX_STRING_CAPACITY:
            return {'status': 'invalid_FString_count_or_capacity'}
        if not length:
            return {'status': 'empty', 'value': ''}
        metadata._base(pointer, length * 2)
        body = b''.join(self.watch(pointer + at, min(1024, length * 2 - at), field + '_FString_chars')
                        for at in range(0, length * 2, 1024))
        if body[-2:] != bytes(2):
            return {'status': 'FString_missing_terminal_NUL'}
        try:
            text = body[:-2].decode('utf-16le', errors='strict')
        except UnicodeError:
            return {'status': 'FString_invalid_UTF16'}
        if not text:
            return {'status': 'empty', 'value': ''}
        if not text.isascii() or '\0' in text:
            return {'status': 'FString_not_public_asset_syntax'}
        grammar = ASSET_PATH if field in ('IamgeSourceSmall', 'IamgeSourceBig', 'ImageSourceLogo') else VIDEO_NAME
        if not grammar.fullmatch(text) or (text.count("'") not in (0, 2)):
            return {'status': 'FString_not_public_asset_syntax'}
        return {'status': 'captured', 'value': text}

    def finish(self):
        for (address, size), expected in self.watched.items():
            if self.exact(address, size, 'final_image_row_stability_recheck') != expected:
                raise metadata._Stop('image_rows_changed_final_results_discarded')


def _sparse_rows(session, table):
    """Internal algorithm, invoked only after a production runtime schema gate."""
    metadata._base(table, 0x68)
    vtable = session.pointer(table, 'selected_table_vtable')
    if not session.base <= vtable < vtable + 0x278 <= session.base + metadata.MODULE_SIZE:
        raise metadata._Stop('selected_table_vtable_outside_module')
    target = session.pointer(vtable + 0x270, 'selected_table_RowMap_accessor')
    if target != session.base + ROWMAP_ACCESSOR_RVA:
        raise metadata._Stop('selected_table_RowMap_accessor_identity_changed')
    header = session.watch(table + 0x30, 56, 'selected_RowMap_header')
    slots, count, capacity = struct.unpack_from('<Qii', header)
    bits, bit_count, bit_capacity = struct.unpack_from('<Qii', header, 0x20)
    free = struct.unpack_from('<i', header, 0x34)[0]
    if not 0 <= free <= count <= capacity <= MAX_ROWS or bit_count != count or not count <= bit_capacity <= MAX_ROWS:
        raise metadata._Stop('selected_RowMap_bounds_invalid')
    if not count:
        raise metadata._Stop('selected_RowMap_empty')
    metadata._base(slots, count * 24)
    amount = ((count + 31) // 32) * 4
    if bits:
        metadata._base(bits, amount)
        allocation = b''.join(session.watch(bits + at, min(1024, amount - at), 'selected_RowMap_allocation_bits')
                              for at in range(0, amount, 1024))
    elif amount <= 16:
        allocation = header[0x10:0x10 + amount]
    else:
        raise metadata._Stop('selected_RowMap_inline_allocation_bits_invalid')
    indices = [i for i in range(count) if allocation[i // 8] & (1 << (i % 8))]
    if len(indices) != count - free:
        raise metadata._Stop('selected_RowMap_allocated_count_mismatch')
    selected, names, observations, duplicate_tabs = {}, [], [], set()
    for index in indices:
        slot = session.watch(slots + index * 24, 16, 'selected_RowMap_key_and_value')
        key = session.name(slot[:8])
        names.append(key)
        row = struct.unpack_from('<Q', slot, 8)[0]
        metadata._base(row, 392)
        tabid = struct.unpack('<Q', session.watch(row + 16, 8, 'target_TabId_uint64'))[0]
        observations.append({'row_name': key, 'observed_TabId': tabid})
        if tabid in TARGET_TABS:
            if tabid in selected:
                duplicate_tabs.add(tabid)
            selected[tabid] = (key, row)
    # Native row keys are independent of zero-based export ordinals. Select
    # exact source TabIds, and verify their complete unique set before strings.
    missing = sorted(TARGET_TABS - selected.keys())
    if duplicate_tabs or missing:
        return {'status': 'typed_target_selection_rejected', 'rows': [],
                'reason': 'duplicate_source_target_TabId_no_image_fields_read' if duplicate_tabs
                          else 'missing_source_target_TabId_no_image_fields_read',
                'target_TabId_observations': observations,
                'missing_target_TabIds': missing, 'duplicate_target_TabIds': sorted(duplicate_tabs),
                'row_names': names, 'allocated_row_count': len(indices)}
    rows = [{'row_name': key, 'TabId': tabid,
             'fields': {field: session.string(row, field, offset) for field, offset in STRING_FIELDS.items()}}
            for tabid, (key, row) in selected.items()]
    return {'status': 'captured_image_fields', 'rows': rows,
            'target_TabId_observations': observations,
            'missing_target_TabIds': [], 'duplicate_target_TabIds': [],
            'row_names': names, 'allocated_row_count': len(indices)}


def _selected_rows(view, contract):
    """Verify the fresh typed owner before reading target scalars or strings."""
    owner = contract.runtime_rowstruct_evidence
    if (not isinstance(owner, dict) or owner.get('rowstruct_member_offset') != 40
            or owner.get('rowstruct_class_global_rva') != 0x1e340a98):
        raise metadata._Stop('runtime_RowStruct_owner_contract_not_closed')
    if view.nodes[0]['name'] != metadata.TARGET:
        raise metadata._Stop('selected_table_native_name_differs')
    session = Session(None, view.base, contract.metadata.codec, shared_watch=view.watch)
    class_type = session.pointer(view.base + owner['rowstruct_class_global_rva'],
                                 'source_UScriptStruct_UClass_singleton')
    rowstruct = session.pointer(view.table + owner['rowstruct_member_offset'],
                                'selected_table_RowStruct_typed_pointer')
    index, serial = view.object_identity(rowstruct, 'selected_RowStruct')
    rowstruct_name = view.name(session.watch(rowstruct + 0x1c, 8,
                                            'selected_RowStruct_name_token'), 'selected_RowStruct')
    if rowstruct_name != metadata.TARGET:
        raise metadata._Stop('selected_RowStruct_name_differs_no_rows_read')
    if session.pointer(rowstruct + 8, 'selected_RowStruct_Class') != class_type:
        raise metadata._Stop('selected_RowStruct_Class_differs_no_rows_read')
    class_index, class_serial = view.object_identity(class_type, 'selected_RowStruct_Class')
    class_name = view.name(session.watch(class_type + 0x1c, 8,
                                        'selected_RowStruct_Class_name_token'), 'selected_RowStruct_Class')
    nodes = [{'name': rowstruct_name, 'object_index': index, 'serial': serial}]
    outer = struct.unpack('<Q', session.watch(rowstruct + 0x10, 8,
                                             'selected_RowStruct_Outer'))[0]
    seen = {rowstruct}
    for _ in range(metadata.MAX_OUTERS):
        if not outer:
            break
        metadata._base(outer, 0x28)
        if outer in seen:
            raise metadata._Stop('selected_RowStruct_Outer_cycle')
        seen.add(outer)
        outer_index, outer_serial = view.object_identity(outer, 'selected_RowStruct_Outer')
        outer_name = view.name(session.watch(outer + 0x1c, 8,
                                            'selected_RowStruct_Outer_name_token'), 'selected_RowStruct_Outer')
        nodes.append({'name': outer_name, 'object_index': outer_index, 'serial': outer_serial})
        outer = struct.unpack('<Q', session.watch(outer + 0x10, 8,
                                                 'selected_RowStruct_Outer'))[0]
    else:
        if outer:
            raise metadata._Stop('selected_RowStruct_Outer_depth_limit')
    rows = _sparse_rows(session, view.table)
    return {**rows, 'runtime_RowStruct_metadata_nodes': nodes,
            'runtime_RowStruct_Class': {'name': class_name, 'object_index': class_index,
                                       'serial': class_serial},
            'runtime_RowStruct_identity_verified': True}


def capture(read, base, contract):
    """All source blocks precede heap reads; all selected results commit together."""
    owner = contract.runtime_rowstruct_evidence
    if not isinstance(owner, dict) or owner.get('source_rowstruct_owner_verified') is not True:
        return {'status': 'disabled', 'reason': 'runtime_RowStruct_identity_source_not_closed',
                'source_schema_sha256': contract.schema_digest,
                'runtime_rows_read': False, 'captured_bytes': 0, 'readset': [],
                'native_called': False, 'whole_row_bytes_read': False,
                'pc_cdn_fields_in_source_schema': False}
    report = metadata.capture(read, base, contract.metadata,
                              _selected_table_reader=lambda view: _selected_rows(view, contract))
    typed = report.pop('selected_table_extension', None)
    roles = [item['role'] for item in report['readset']]
    rows_read = 'target_TabId_uint64' in roles
    image_fields_read = any(role.endswith('_FString_header') for role in roles)
    report.update(source_schema_sha256=contract.schema_digest,
                  source_rowstruct_owner_verified=True,
                  runtime_RowStruct_identity_verified=False,
                  runtime_rows_read=rows_read, row_bytes_read=rows_read,
                  image_fields_read=image_fields_read, whole_row_bytes_read=False,
                  pc_cdn_fields_in_source_schema=False)
    if report['status'] == 'captured_metadata' and typed is not None:
        report.update(typed)
        if typed['status'] == 'typed_target_selection_rejected':
            report['status'] = 'captured_typed_diagnostic'
    return report
