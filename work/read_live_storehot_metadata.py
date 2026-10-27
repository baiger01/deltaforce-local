"""Bounded metadata for one freshly identified StoreHotRecommendation table.

The default path reads immutable configuration keys, one selected Content
record's proven fields, and selected table/Outer metadata. A reviewed internal
reader may extend that same stability transaction. No client calls are made.
"""

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct

import native_config_names as names
import read_keybox_manager_interface as manager_source
import read_keybox_config_map as map_source

ROOT = Path(__file__).resolve().parent.parent
SOURCE_PE = names.EXPECTED_PE
MODULE_SIZE = manager_source.MODULE_SIZE
MAX_ADDRESS = 0x800000000000
MAX_SLOTS = 4096
MAX_TABLES = 32
MAX_OUTERS = 8
MAX_TOTAL_READ = 2 * 1024 * 1024
TARGET = 'StoreHotRecommendation'
ALLOCATION_ACCESSOR_RVA = 0xd968d0
SOURCE_FILES = (
    ('work/native-client-tests/1790852498680017300/keybox-registration-readonly-185.json',
     '5d4acbe72d2ee450a31c8fcd29c9805947cab0531f727a70fa28744b65033182'),
    ('work/evidence/live-metadata-path-code-bundle-20261005-private.json',
     'fe152df0e49158194ec2f6f6c97578aa027a040a487c8f1a332b0be6a8c83b9d'),
    ('work/evidence/live-local-image-package-brush-bundle-20261005-private.json',
     '01f326632251d583a7db7eefa63929caceacc6ec9d7dc0a72612da1c97d35d09'),
)
CONTENT_WITNESSES = (
    (0xdc4c73, bytes.fromhex('80be0c02000002')),
    (0xdc4cc7, bytes.fromhex('6683be0e02000001')),
    (0xdc4cd6, bytes.fromhex('488b86f8010000')),
    (0xdc4ce6, bytes.fromhex('488d8ed8010000')),
    (0xdc4cf2, bytes.fromhex('ff1560917d1c')),
    (0xdc4d08, bytes.fromhex('48638ee0010000')),
    (0xdc4d20, bytes.fromhex('488b074885c0')),
)


@dataclass(frozen=True)
class Contract:
    blocks: tuple
    codec: object
    source_hashes: tuple


@dataclass(frozen=True)
class _SelectedTableView:
    base: int
    table: int
    nodes: tuple
    watch: object
    object_identity: object
    name: object


def load_contract(root=ROOT):
    reports = []
    for relative, expected in SOURCE_FILES:
        path = Path(root) / relative
        if not path.is_file() or not 0 < path.stat().st_size <= 2 * 1024 * 1024:
            raise ValueError('missing_source_evidence: ' + relative)
        with path.open('rb') as stream:
            raw = stream.read(2 * 1024 * 1024 + 1)
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('source_evidence_sha256_changed: ' + relative)
        report = json.loads(raw)
        if report.get('native_pe_sha256') != SOURCE_PE:
            raise ValueError('source_evidence_PE_changed: ' + relative)
        reports.append(report)
    old, path_report, local_report = reports
    codec = names.ConfigNameCodec(old)
    blocks = []
    for name in names.EXPECTED_CODE:
        b = old['fixed_code'][name]
        blocks.append((b['rva'], bytes.fromhex(b['bytes'])))
    for name in ('datatable_manager_get', 'datatable_manager_storage_helper',
                 'datatable_object_chunk_index', 'datatable_object_item_index',
                 'datatable_native_get_table', 'datatable_lite_content_binding',
                 'datatable_lite_content_table'):
        b = old['fixed_code'][name]
        blocks.append((b['rva'], bytes.fromhex(b['bytes'])))
    # The complete map-find function ends before its neighboring overload.
    b = old['fixed_code']['datatable_content_map_find']
    blocks.append((b['rva'], bytes.fromhex(b['bytes'])[:0xd4]))
    old_map = old['config_map']
    source_accessor = old['fixed_data']['datatable_content_data_accessor']
    if (old_map['allocation_accessor_rva'] != ALLOCATION_ACCESSOR_RVA
            or source_accessor['rva'] != map_source.ALLOCATION_ACCESSOR_RVA
            or bytes.fromhex(source_accessor['bytes']) != struct.pack('<Q', 0x140000000 + ALLOCATION_ACCESSOR_RVA)
            or bytes.fromhex(old_map['allocation_accessor_code_hex'])[:4] != bytes.fromhex('488b01c3')):
        raise ValueError('source_map_allocation_accessor_identity_changed')
    blocks.append((old_map['allocation_accessor_rva'],
                   bytes.fromhex(old_map['allocation_accessor_code_hex'])[:4]))
    old_manager = old['manager_interface']
    blocks.append((old_manager['target_rva'], bytes.fromhex(old_manager['target_code_hex'])))
    for report, group, name in ((path_report, None, None),
                                (local_report, 'local_predicate_functor', 'LocalImageFunctorBody')):
        b = report['code'] if group is None else report[group][name]
        code = bytes.fromhex(b['bytes'])
        if len(code) != b['size'] or hashlib.sha256(code).hexdigest() != b['sha256']:
            raise ValueError('source_code_span_digest_changed')
        blocks.append((b['rva'], code))
    for rva, expected in (*manager_source.CODE_WITNESSES, *map_source.CODE_WITNESSES,
                          *CONTENT_WITNESSES):
        found = [code[rva - start:rva - start + len(expected)] for start, code in blocks
                 if start <= rva and rva + len(expected) <= start + len(code)]
        if not found or any(raw != expected for raw in found):
            raise ValueError('source_field_witness_not_covered: ' + hex(rva))
    return Contract(tuple(blocks), codec, SOURCE_FILES)


class _Stop(ValueError):
    pass


def _base(address, size=1):
    if (type(address) is not int or type(size) is not int or size <= 0
            or address < 0x10000 or address + size > MAX_ADDRESS):
        raise _Stop('invalid_pointer_base_or_range')
    return address


def capture(read, base, contract, *, _selected_table_reader=None):
    """read(address, size) receives <=1024B, source-qualified requests only.

    A fresh key token is decoded; no historical token/index/heap address is used.
    All accumulated table metadata is discarded if any relevant field changes.
    """
    _base(base, MODULE_SIZE)
    result = {'status': 'skipped', 'target_configuration': TARGET,
              'native_pe_sha256': SOURCE_PE, 'row_bytes_read': False,
              'native_called': False, 'other_table_contents_read': False}
    total = 0
    readset = []
    watched = {}

    def exact(address, size, role):
        nonlocal total
        _base(address, size)
        if size > 1024 or total + size > MAX_TOTAL_READ:
            raise _Stop('bounded_read_budget_exceeded')
        total += size
        raw = read(address, size)
        if not isinstance(raw, bytes) or len(raw) != size:
            raise _Stop('short_metadata_read')
        readset.append({'address': hex(address), 'size': size, 'role': role})
        return raw

    def module(rva, size, role):
        if not 0 <= rva < rva + size <= MODULE_SIZE:
            raise _Stop('module_source_range_out_of_bounds')
        return exact(base + rva, size, role)

    def watch(address, size, role):
        raw = exact(address, size, role)
        key = (address, size)
        if key in watched and watched[key] != raw:
            raise _Stop('metadata_changed_during_capture')
        watched[key] = raw
        return raw

    def u64(address, role, observe=True):
        return struct.unpack('<Q', (watch if observe else exact)(address, 8, role))[0]

    def name(token, role):
        comparison, number = struct.unpack('<II', token)
        if number != 0 or comparison >= 0x80000000:
            raise _Stop('unsupported_numbered_metadata_name')
        pointer_rva = names.POOL_RVA + 8 + (comparison >> 18) * 8
        if not pointer_rva + 8 <= MODULE_SIZE:
            raise _Stop('name_pool_slot_outside_module')
        block = u64(base + pointer_rva, role + '_pool_block')
        _base(block)
        if block & 1:
            raise _Stop('unaligned_name_pool_block')
        address = block + (comparison & 0x3ffff) * 2
        header = watch(address, 2, role + '_name_header')
        value = struct.unpack('<H', header)[0]
        length, wide = value >> 6, bool(value & 1)
        if not 1 <= length <= 192:
            raise _Stop('metadata_name_length_out_of_bounds')
        payload_size = length * (2 if wide else 1)
        if (comparison & 0x3ffff) * 2 + 2 + payload_size > 0x80000:
            raise _Stop('metadata_name_payload_outside_native_block')
        chars = watch(address + 2, payload_size, role + '_name_chars')
        decoded = contract.codec.decode_config_name(header + chars, number)
        if not decoded or not decoded.isascii() or any(ord(c) < 32 for c in decoded):
            raise _Stop('metadata_name_not_public_path_syntax')
        return decoded

    def object_identity(obj, role):
        _base(obj, 0x28)
        index = struct.unpack('<i', watch(obj + 0x24, 4, role + '_object_index'))[0]
        header = watch(base + manager_source.ARRAY_RVA, 32, 'object_registry_header')
        count = struct.unpack_from('<i', header, 12)[0]
        chunks = struct.unpack_from('<Q', header, 24)[0]
        if not 0 <= index < count <= 2 * 1024 * 1024:
            raise _Stop('selected_object_index_out_of_bounds')
        _base(chunks)
        chunk_index, within = divmod(index, 65536)
        chunk = u64(chunks + chunk_index * 8, role + '_registry_chunk')
        _base(chunk)
        item = watch(chunk + within * 24, 24, role + '_registry_item')
        pointer, flags = struct.unpack_from('<QI', item)
        serial = struct.unpack_from('<i', item, 20)[0]
        # Ordinary objects are reached from a typed table/Outer pointer, not a
        # weak-key pair. The captured functor validates their index and flags;
        # serial0 remains a valid metadata state and the full item is rechecked.
        # The manager's separately sourced input weak key still requires>0.
        if pointer != obj or serial < 0 or flags & 0x30000000:
            result['rejected_selected_identity'] = {
                'role': role, 'object_index': index, 'pointer_matches': pointer == obj,
                'excluded_flags': flags & 0x30000000,
                'serial_state': 'positive' if serial > 0 else 'zero' if serial == 0 else 'negative'}
            if pointer != obj:
                raise _Stop('selected_object_registry_pointer_mismatch')
            if flags & 0x30000000:
                raise _Stop('selected_object_registry_flags_excluded')
            raise _Stop('selected_object_registry_serial_invalid')
        return index, serial

    try:
        if not contract.blocks:
            raise _Stop('empty_source_contract')
        for rva, code in contract.blocks:
            if (type(rva) is not int or not isinstance(code, bytes) or not code
                    or not 0 <= rva < rva + len(code) <= MODULE_SIZE):
                raise _Stop('module_source_range_out_of_bounds')
        # Every pinned code block is checked before any heap read.
        for rva, code in contract.blocks:
            for offset in range(0, len(code), 1024):
                expected = code[offset:offset + 1024]
                if module(rva + offset, len(expected), 'source_code_gate') != expected:
                    raise _Stop('source_code_changed_before_metadata_reads')
        if watch(base + manager_source.SELECTOR_RVA, 4, 'registry_selector') != bytes(4):
            raise _Stop('unsupported_object_registry_selector')
        # The observed common override gate selects ordinary GetTable behavior.
        # CMP at dc4bde is source-gated above; nonzero can bypass these fields.
        if watch(base + 0x1db35660, 1, 'content_gettable_override_gate') != b'\x00':
            raise _Stop('content_gettable_override_active')
        if u64(base + manager_source.OVERRIDE_RVA, 'manager_accessor_override'):
            raise _Stop('manager_accessor_override_active')
        weak = watch(base + manager_source.STORAGE_RVA, 16, 'manager_weak_reference')
        index, serial = struct.unpack_from('<ii', weak)
        array = watch(base + manager_source.ARRAY_RVA, 32, 'object_registry_header')
        count = struct.unpack_from('<i', array, 12)[0]
        chunks = struct.unpack_from('<Q', array, 24)[0]
        if not 0 <= index < count <= 2 * 1024 * 1024 or serial <= 0:
            raise _Stop('invalid_manager_weak_reference')
        _base(chunks)
        ci, ii = divmod(index, 65536)
        chunk = u64(chunks + ci * 8, 'manager_registry_chunk')
        _base(chunk)
        item = watch(chunk + ii * 24, 24, 'manager_registry_item')
        obj = struct.unpack_from('<Q', item)[0]
        flags = struct.unpack_from('<I', item, 8)[0]
        if struct.unpack_from('<i', item, 20)[0] != serial or flags & 0x30000000:
            raise _Stop('manager_registry_serial_or_flags_invalid')
        _base(obj, 0x1e0)
        vtable = u64(obj + 0x30, 'manager_interface_vtable')
        if not base <= vtable < vtable + 0x70 <= base + MODULE_SIZE:
            raise _Stop('manager_interface_vtable_outside_module')
        if u64(vtable + 0x68, 'manager_interface_gettable_slot') != base + 0xdbf7f0:
            raise _Stop('unsupported_manager_table_implementation')
        if u64(base + map_source.ALLOCATION_ACCESSOR_RVA, 'map_allocator') != base + ALLOCATION_ACCESSOR_RVA:
            raise _Stop('unsupported_map_allocation_accessor')
        header = watch(obj + 0x190, 80, 'immutable_configuration_map_header')
        slots, slot_count = struct.unpack_from('<Qi', header)
        free_count = struct.unpack_from('<i', header, 0x34)[0]
        buckets = struct.unpack_from('<Q', header, 0x40)[0]
        hash_size = struct.unpack_from('<i', header, 0x48)[0]
        if not 0 <= free_count < slot_count <= MAX_SLOTS:
            raise _Stop('configuration_slot_count_out_of_bounds_or_empty')
        _base(slots)
        if not 1 <= hash_size <= MAX_SLOTS or hash_size & (hash_size - 1):
            raise _Stop('configuration_hash_count_out_of_bounds')
        if buckets:
            _base(buckets)
            bucket_data = b''.join(watch(buckets + n, min(1024, hash_size * 4 - n),
                                        'immutable_configuration_hash_buckets')
                                  for n in range(0, hash_size * 4, 1024))
        elif hash_size == 1:
            bucket_data = header[0x38:0x3c]
        else:
            raise _Stop('invalid_configuration_bucket_base')
        seen, matches = set(), []
        live_count = slot_count - free_count
        for first in struct.unpack('<' + 'i' * hash_size, bucket_data):
            current = first
            while current != -1:
                if not 0 <= current < slot_count or current in seen or len(seen) >= live_count:
                    raise _Stop('configuration_hash_chain_invalid')
                seen.add(current)
                slot = watch(slots + current * 24, 24, 'immutable_configuration_key_slot')
                # Only configuration keys are decoded; other Content pointers are never followed.
                if name(slot[:8], 'configuration_key') == TARGET:
                    matches.append((current, slot))
                current = struct.unpack_from('<i', slot, 16)[0]
        if len(seen) != live_count or len(matches) != 1:
            raise _Stop('target_configuration_not_uniquely_identified')
        slot_index, slot = matches[0]
        content = struct.unpack_from('<Q', slot, 8)[0]
        _base(content, 0x218)
        state = watch(content + 0x20c, 1, 'selected_content_ready_state')
        if state != b'\x02':
            raise _Stop('selected_content_not_ready')
        table_count = struct.unpack('<H', watch(content + 0x20e, 2, 'selected_content_table_count'))[0]
        if not 1 <= table_count <= MAX_TABLES:
            raise _Stop('selected_content_table_count_out_of_bounds')
        combined = u64(content + 0x1f8, 'selected_content_combined_table')
        tables = watch(content + 0x1d8, 12, 'selected_content_table_array_pointer_and_count')
        table_array, amount = struct.unpack('<Qi', tables)
        if not 0 <= amount <= MAX_TABLES:
            raise _Stop('selected_content_table_array_bounds_invalid')
        selected, branch = (combined, 'combined_table') if table_count > 1 and combined else (0, 'first_nonnull_table')
        if not selected:
            _base(table_array)
            values = watch(table_array, amount * 8, 'selected_content_table_array') if amount else b''
            selected = next((value for value in struct.unpack('<' + 'Q' * amount, values) if value), 0)
        if not selected:
            raise _Stop('selected_content_has_no_table')
        nodes, node_seen = [], set()
        node = selected
        for depth in range(MAX_OUTERS):
            if node in node_seen:
                raise _Stop('selected_table_outer_cycle')
            node_seen.add(node)
            identity = object_identity(node, 'selected_table' if depth == 0 else 'selected_outer')
            class_pointer = u64(node + 8, 'selected_metadata_class')
            _base(class_pointer)
            outer = u64(node + 0x10, 'selected_metadata_outer')
            token = watch(node + 0x1c, 8, 'selected_metadata_name_token')
            decoded = name(token, 'selected_table' if depth == 0 else 'selected_outer')
            if any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_/.-' for c in decoded):
                raise _Stop('selected_metadata_name_not_asset_path_syntax')
            nodes.append({'name': decoded, 'object_index': identity[0], 'serial': identity[1]})
            if not outer:
                break
            _base(outer, 0x28)
            node = outer
        else:
            raise _Stop('selected_table_outer_depth_limit')
        extension = None
        if _selected_table_reader is not None:
            view = _SelectedTableView(base, selected, tuple(nodes), watch,
                                      object_identity, name)
            extension = _selected_table_reader(view)
        # Extension reads share this watch set, so all results commit together.
        for (address, size), original in watched.items():
            if exact(address, size, 'final_metadata_stability_recheck') != original:
                raise _Stop('metadata_changed_final_results_discarded')
        result.update(status='captured_metadata', configuration_slot=slot_index,
                      table_selection_branch=branch, table_count=table_count,
                      selected_table_name=nodes[0]['name'], outer_names=[n['name'] for n in nodes[1:]],
                      selected_metadata_nodes=nodes, source_code_rechecked=True,
                      container_and_serial_rechecked=True, path_formatter_called=False,
                      formatted_object_path_proven=False,
                      ordinary_metadata_zero_serial_allowed=True,
                      manager_input_weak_serial_nonzero_verified=True)
        if _selected_table_reader is not None:
            result['selected_table_extension'] = extension
    except (_Stop, ValueError, struct.error, UnicodeError, OSError) as exc:
        # Never retain partially captured names or unknown bytes on a failed gate.
        result.update(status='skipped', reason=str(exc) if isinstance(exc, _Stop) else 'bounded_read_or_decode_failed')
    result.update(captured_bytes=total, readset=readset,
                  source_evidence=[{'relative_path': p, 'sha256': s} for p, s in contract.source_hashes])
    return result
