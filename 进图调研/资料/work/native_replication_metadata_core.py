"""Bounded, read-only exports of existing native replication metadata.

The caller supplies the reader and independently identified class/driver roots.
No native producer is called, no table is created, and no process is opened here.
The exact table lookups are sourced from d8cbc0/d8caf0 and12b90c70; cache and
RepLayout layouts are pinned in work/evidence. These exports are metadata, not
an implementation of the property serializers or a working player spawn.
"""
from dataclasses import asdict
import hashlib
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'outputs/df-local-server'))
from dfserver.legacy_ds_class_net_cache import (  # noqa: E402
    ClassCacheGraph, decode_class_cache_snapshot,
)

MAX_ADDRESS = (1 << 47) - 1
MAX_SINGLE_READ = 8192
MAX_READ_BYTES = 64 * 1024 * 1024
MAX_READ_CALLS = 2_000_000
MAX_TABLE_SLOTS = 65536
MAX_BUCKETS = 131072
MAX_HASH_CHAIN = 128
MAX_LAYOUT_CMDS = 8192
MAX_LAYOUT_PARENTS = 2048


def span(address, size):
    if (type(address) is not int or type(size) is not int or
            not 0x10000 <= address <= MAX_ADDRESS or size <= 0 or
            address + size - 1 > MAX_ADDRESS):
        raise ValueError('Invalid user-mode metadata address range')


class MetadataSession:
    """One export budget shared by all metadata reads, with exact-byte results."""
    def __init__(self, read_exact, *, max_bytes=MAX_READ_BYTES, max_calls=MAX_READ_CALLS):
        if not callable(read_exact):
            raise ValueError('An explicit read-only backend is required')
        if (type(max_bytes) is not int or not 1 <= max_bytes <= MAX_READ_BYTES or
                type(max_calls) is not int or not 1 <= max_calls <= MAX_READ_CALLS):
            raise ValueError('Invalid metadata session budget')
        self.backend = read_exact
        self.max_bytes, self.max_calls = max_bytes, max_calls
        self.bytes_read, self.calls = 0, 0

    def read(self, address, size):
        span(address, size)
        if size > MAX_SINGLE_READ:
            raise ValueError('Metadata read exceeds the small-read bound')
        if self.bytes_read + size > self.max_bytes or self.calls >= self.max_calls:
            raise ValueError('Metadata session read budget exhausted')
        # Failed/partial requests still count toward the attempted-read budget.
        self.bytes_read += size
        self.calls += 1
        raw = self.backend(address, size)
        if type(raw) is not bytes or len(raw) != size:
            raise ValueError('Metadata backend returned incomplete or mutable bytes')
        return raw

    def array(self, address, size):
        if type(size) is not int or size < 0:
            raise ValueError('Invalid metadata array byte count')
        if size == 0:
            return b''
        span(address, size)
        return b''.join(self.read(address + at, min(MAX_SINGLE_READ, size - at))
                        for at in range(0, size, MAX_SINGLE_READ))

    def pointer(self, address):
        return struct.unpack('<Q', self.read(address, 8))[0]

    def stable(self, address, size):
        first = self.array(address, size)
        if self.array(address, size) != first:
            raise ValueError('Metadata changed while being read')
        return first


def lookup_weak_key_table(session, table_address, key, *, value_kind):
    """Native bucket/chain lookup only; never enumerate unused sparse-array slots.

    Cache entries are24 bytes with value+8/next+10. Layout entries are32 bytes
    with shared-pointer value+8/control+10/next+18. Only d86840's exact-key branch
    is used; its additional equivalence for two invalid weak references is not
    accepted as a binding to a selected live class. This never invokes the getter.
    """
    if type(key) is not bytes or len(key) != 8 or value_kind not in ('cache', 'layout'):
        raise ValueError('Exact weak-object key and known table kind are required')
    object_index, serial = struct.unpack('<iI', key)
    if object_index < 0 or serial == 0:
        raise ValueError('A nonnull selected-class weak key is required')
    stride, next_offset = (24, 0x10) if value_kind == 'cache' else (32, 0x18)
    header = session.stable(table_address, 0x50)
    data, count, capacity = struct.unpack_from('<Qii', header)
    free_count = struct.unpack_from('<i', header, 0x34)[0]
    buckets = struct.unpack_from('<i', header, 0x48)[0]
    if not 0 <= free_count <= count <= capacity <= MAX_TABLE_SLOTS:
        raise ValueError('Invalid existing weak-key table slot counts')
    if count == free_count:
        return None
    if not 1 <= buckets <= MAX_BUCKETS or buckets & (buckets - 1):
        raise ValueError('Weak-key bucket count is invalid or over budget')
    span(data, count * stride)
    bucket_storage = struct.unpack_from('<Q', header, 0x40)[0]
    if not bucket_storage:
        # Native inline allocator has eight bytes at+38; it can hold only two
        # uint32 bucket indices. Larger null storage is not a readable table.
        if buckets > 2:
            raise ValueError('Null external bucket storage exceeds inline capacity')
        bucket_storage = table_address + 0x38
    span(bucket_storage, buckets * 4)
    low, high = struct.unpack('<II', key)
    bucket_address = bucket_storage + ((low ^ high) & (buckets - 1)) * 4
    bucket = session.read(bucket_address, 4)
    index = struct.unpack('<i', bucket)[0]
    seen, selected = set(), None
    while index != -1:
        if len(seen) >= MAX_HASH_CHAIN:
            raise ValueError('Existing weak-key hash chain exceeds local bound')
        if not 0 <= index < count or index in seen:
            raise ValueError('Existing weak-key table has invalid or cyclic chain')
        seen.add(index)
        item = session.stable(data + index * stride, stride)
        if item[:8] == key:
            selected = {'slot_index': index, 'value_address': struct.unpack_from('<Q', item, 8)[0]}
            if value_kind == 'layout':
                selected['shared_control_address'] = struct.unpack_from('<Q', item, 0x10)[0]
            break
        index = struct.unpack_from('<i', item, next_offset)[0]
    if session.read(table_address, 0x50) != header or session.read(bucket_address, 4) != bucket:
        raise ValueError('Weak-key table changed during lookup')
    return selected


def export_cache_graph(session, leaf_address, *, expected_key=None):
    """Read existing cache nodes only, with exact used entries and stable headers."""
    nodes, seen, address = [], set(), leaf_address
    while address:
        if address in seen or len(nodes) >= 32:
            raise ValueError('Class-cache cycle or depth bound exceeded')
        seen.add(address)
        header = session.stable(address, 48)
        storage = struct.unpack_from('<Q', header, 0x20)[0]
        count, capacity = struct.unpack_from('<ii', header, 0x28)
        if not 0 <= count <= capacity <= 4096:
            raise ValueError('Existing class-cache array exceeds metadata bound')
        entries = session.stable(storage, count * 32) if count else b''
        node = decode_class_cache_snapshot(address=address, header=header, entry_bytes=entries)
        if session.read(address, 48) != header:
            raise ValueError('Class-cache header changed during field export')
        nodes.append(node)
        address = node.parent_address
    graph = ClassCacheGraph(leaf_address=leaf_address, snapshots=tuple(nodes))
    if expected_key is not None and graph.nodes[-1].opaque_object_key != expected_key:
        raise ValueError('Class-cache identity key disagrees with the selected class')
    return graph


def export_replayout(session, address):
    """Export command metadata without reading actual player property values.

    Parent descriptor/name and Cmd descriptor/handle are source-established;
    remaining record fields remain hashed without invented semantics.
    Cmd offsets are data/shadow offsets, NOT wire offsets or serializer IDs.
    Numeric handles are metadata from the actual records, not invented indices.
    """
    span(address, 0x60)
    header = session.stable(address + 0x40, 0x20)
    parents, parent_count, parent_capacity, cmds, cmd_count, cmd_capacity = struct.unpack('<QiiQii', header)
    if not 0 <= parent_count <= parent_capacity <= MAX_LAYOUT_PARENTS:
        raise ValueError('Existing RepLayout Parent array exceeds local bound')
    if not 0 <= cmd_count <= cmd_capacity <= MAX_LAYOUT_CMDS:
        raise ValueError('Existing RepLayout Cmd array exceeds local bound')
    parent_data = session.stable(parents, parent_count * 64) if parent_count else b''
    cmd_data = session.stable(cmds, cmd_count * 32) if cmd_count else b''
    if session.read(address + 0x40, 0x20) != header:
        raise ValueError('RepLayout array headers changed during export')
    parent_records = [{'parent_index': index,
        'descriptor_address': struct.unpack_from('<Q', parent_data, index * 64)[0],
        'name_token': parent_data[index*64+8:index*64+16].hex(),
        'record_sha256': hashlib.sha256(parent_data[index*64:index*64+64]).hexdigest()}
        for index in range(parent_count)]
    records = []
    for index in range(cmd_count):
        at = index * 32
        records.append({'command_index': index,
            'descriptor_address': struct.unpack_from('<Q', cmd_data, at)[0],
            'data_offset': struct.unpack_from('<i', cmd_data, at + 0xc)[0],
            'shadow_offset': struct.unpack_from('<i', cmd_data, at + 0x10)[0],
            'relative_handle': struct.unpack_from('<H', cmd_data, at + 0x14)[0],
            'parent_index': struct.unpack_from('<H', cmd_data, at + 0x16)[0],
            'dispatch_opcode': cmd_data[at + 0x1c],
            'dispatch_gate_byte': cmd_data[at + 0x1c],
            'record_sha256': hashlib.sha256(cmd_data[at:at+32]).hexdigest()})
    return {'layout_address': address, 'parent_count': parent_count, 'command_count': cmd_count,
            'parents_sha256': hashlib.sha256(parent_data).hexdigest(),
            'commands_sha256': hashlib.sha256(cmd_data).hexdigest(), 'commands': records, 'parents': parent_records,
            'parent_record_field_schema_recovered': False, 'property_serializer_schema_recovered': False}


def export_existing_driver_class(session, driver_address, class_key):
    """Read the two already-built driver tables for one independently bound class.

    Missing tables return explicit missing status; no allocation/native invocation
    fills them. The caller must separately prove the actual NetDriver/class roots.
    """
    if type(class_key) is not bytes or len(class_key) != 8:
        raise ValueError('An exact selected class weak-object key is required')
    span(driver_address, 0x480)
    manager = session.pointer(driver_address + 0x170)
    if manager:
        span(manager, 0x58)
    cache_result = lookup_weak_key_table(session, manager + 8, class_key, value_kind='cache') if manager else None
    layout_result = lookup_weak_key_table(session, driver_address + 0x430, class_key, value_kind='layout')
    result = {'class_key': class_key.hex(), 'driver_address': driver_address,
              'cache_status': 'missing', 'layout_status': 'missing',
              'native_getter_invoked': False, 'snapshot_atomic': False,
              'player_spawn_verified': False}
    if cache_result and cache_result['value_address']:
        graph = export_cache_graph(session, cache_result['value_address'], expected_key=class_key)
        result['cache_status'] = 'exported_existing'
        # Semantic fields only: do not persist uninitialized native padding.
        result['cache_nodes'] = [{**asdict(node), 'opaque_object_key': node.opaque_object_key.hex()}
                                 for node in graph.nodes]
        result['exclusive_index_maximum'] = graph.exclusive_index_maximum
    if layout_result and layout_result['value_address']:
        result['layout'] = export_replayout(session, layout_result['value_address'])
        result['layout_status'] = 'exported_existing'
    if session.pointer(driver_address + 0x170) != manager:
        raise ValueError('Driver cache-manager root changed during export')
    return result
