"""Bounded callback-only observation of the source-qualified Pawn interface.

The caller proves process/module ownership. No native getter, method, writer or
process API is invoked. A named template is metadata, not a spawned actor.
"""
import hashlib
import struct

from native_metadata_names import resolve_name
from native_metadata_objects import validate_object_record
from native_metadata_paths import object_path
from native_replication_metadata_core import span

SHIPPING_SHA256 = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
IMAGE_SIZE = 536408064
INTERFACE_SINGLETON_RVA = 0x1de5c898
DATA_ACCESSOR_CELL_RVA = 0x1d59de58
DATA_ACCESSOR_RVA = 0xd968d0
MAIN_VTABLE_RVA = 0x1a67a320
SECONDARY_VTABLE_RVA = 0x1a67c2e8
WRITER_RVA = 0x4e198f0
WRITER_PREFIX_SHA256 = '016de0d4825e1b9c26db8906255a2530ce7ee466fc4c864f4d5367a87c959649'
ADJUSTMENT = 0xa60
SLOT = 0x10
MAX_DEPTH = 32
MAX_INTERFACES = 128
MAX_READ_BYTES = 128 * 1024
MAX_READ_CALLS = 4096
SOURCE_PINS = {
    'interface_array': ('work/evidence/native-interface-class-array-branch.json',
                        '90d0abd7b529c2dfca619406dc61852cb53586d1c89da5e52821ac5de9fbae77'),
    'data_accessor': ('work/evidence/native-interface-array-data-accessor-prefix.json',
                      '0933231b202151ddb3838fe1649af01681ac2beb5304a25ad674de552d7a834f'),
    'pawn_writer': ('work/evidence/native-pawn-net-rep-interface-writer-source.json',
                    'f1fd2d3a03818d769d60e58d772f43aaa02ad4240e61e5836879e0670bff6c19'),
}


class ActorInterfaceMetadataError(ValueError):
    pass


class _Observation:
    def __init__(self, session, base):
        span(base, IMAGE_SIZE)
        if not callable(getattr(session, 'read', None)):
            raise ActorInterfaceMetadataError('Explicit metadata session required')
        self.session, self.base = session, base
        self.calls, self.bytes_read = 0, 0
        self.snapshots, self.records, self.descriptors = {}, {}, {}

    def read(self, address, size):
        span(address, size)
        if self.calls >= MAX_READ_CALLS or self.bytes_read + size > MAX_READ_BYTES:
            raise ActorInterfaceMetadataError('Actor interface observation budget exhausted')
        self.calls += 1
        self.bytes_read += size
        raw = self.session.read(address, size)
        if type(raw) is not bytes or len(raw) != size:
            raise ActorInterfaceMetadataError('Incomplete actor interface metadata')
        return raw

    def keep(self, address, size):
        raw = self.read(address, size)
        key = (address, size)
        if key in self.snapshots and raw != self.snapshots[key]:
            raise ActorInterfaceMetadataError('Actor interface metadata changed during observation')
        self.snapshots[key] = raw
        return raw

    def ptr(self, address):
        return struct.unpack('<Q', self.keep(address, 8))[0]

    def record(self, address, expected=None):
        record = validate_object_record(self.read, self.base, address)
        old = self.records.get(address)
        if old is not None and old != record:
            raise ActorInterfaceMetadataError('Actor interface object identity changed')
        if expected is not None:
            if (type(expected.get('object_index')) is not int or
                    type(expected.get('serial')) is not int or
                    expected['object_index'] != record.index or
                    (expected['serial'] != record.serial and not
                     (expected['serial'] == 0 and record.serial > 0))):
                raise ActorInterfaceMetadataError('Selected metadata identity no longer matches')
        self.records[address] = record
        return record

    def descriptor(self, address):
        if address in self.descriptors:
            return self.descriptors[address]
        self.record(address)
        token = self.keep(address + 0x1c, 8)
        row = {'address': address, 'name': resolve_name(self.read, self.base, token).display_text,
               'class': self.ptr(address + 8), 'parent': self.ptr(address + 0x48),
               'outer': self.ptr(address + 0x10)}
        self.descriptors[address] = row
        return row

    def class_identity(self, address):
        row = self.descriptor(address)
        cursor, seen = row['class'], set()
        while cursor:
            if cursor in seen or len(seen) >= MAX_DEPTH:
                raise ActorInterfaceMetadataError('Invalid metaclass ancestry')
            seen.add(cursor)
            meta = self.descriptor(cursor)
            if meta['name'] == 'Class':
                return row
            cursor = meta['parent']
        raise ActorInterfaceMetadataError('Interface metadata is not a Class')

    def finish(self):
        for address, old in tuple(self.records.items()):
            if validate_object_record(self.read, self.base, address) != old:
                raise ActorInterfaceMetadataError('Actor interface object identity changed')
        for (address, size), raw in tuple(self.snapshots.items()):
            if self.read(address, size) != raw:
                raise ActorInterfaceMetadataError('Actor interface metadata changed during observation')


def observe_actor_interface(session, module_base, candidate, klass):
    """Observe only a selected Pawn named-template's native interface binding.

    All metadata used by the native cast is rechecked before publishing. The
    observer is stricter than native first-match behavior: ambiguity is refused.
    Local caps are reader policy, not native table capacities. Caller identity
    and source-image qualification remain prerequisites.
    """
    if type(candidate) is not dict or type(klass) is not dict:
        raise ActorInterfaceMetadataError('Selected candidate and Class records required')
    if (candidate.get('name') != 'Default__BP_DFMCharacter_C' or
            klass.get('name') != 'BP_DFMCharacter_C' or
            candidate.get('class_address') != klass.get('address') or
            candidate.get('selection_kind') != 'name_class_outer_metadata_candidate'):
        raise ActorInterfaceMetadataError('Only the selected Pawn named template is supported')
    ob = _Observation(session, module_base)
    actor, actor_class = candidate.get('address'), klass.get('address')
    ob.record(actor, candidate)
    ob.record(actor_class, klass)
    actual = ob.class_identity(actor_class)
    if actual['name'] != klass['name'] or ob.ptr(actor + 8) != actor_class:
        raise ActorInterfaceMetadataError('Selected Pawn class binding changed')
    actor_name = resolve_name(ob.read, module_base, ob.keep(actor + 0x1c, 8)).display_text
    if actor_name != candidate['name']:
        raise ActorInterfaceMetadataError('Selected Pawn template name changed')
    if (ob.ptr(actor + 0x10) != candidate.get('outer_address') or
            actual['outer'] != candidate.get('class_outer_address')):
        raise ActorInterfaceMetadataError('Selected Pawn outer binding changed')
    for address, row in ((actor, candidate), (actor_class, klass)):
        if type(row.get('asset_path')) is not str or object_path(ob.read, module_base, address) != row['asset_path']:
            raise ActorInterfaceMetadataError('Selected Pawn metadata path changed')
    if ob.ptr(actor) != module_base + MAIN_VTABLE_RVA:
        raise ActorInterfaceMetadataError('Pawn main vtable does not match qualified constructor')
    if (ob.ptr(module_base + DATA_ACCESSOR_CELL_RVA) != module_base + DATA_ACCESSOR_RVA or
            ob.keep(module_base + DATA_ACCESSOR_RVA, 4) != bytes.fromhex('488b01c3')):
        raise ActorInterfaceMetadataError('Interface array data accessor is unsupported')
    iface = ob.ptr(module_base + INTERFACE_SINGLETON_RVA)
    if not iface:
        raise ActorInterfaceMetadataError('NetRepActorInterface singleton is not initialized')
    iface_row = ob.class_identity(iface)
    if iface_row['name'] != 'NetRepActorInterface':
        raise ActorInterfaceMetadataError('Interface singleton identity is incorrect')
    flags = struct.unpack('<I', ob.keep(iface + 0xd4, 4))[0]
    if not flags & (1 << 14) or not flags & (1 << 7):
        raise ActorInterfaceMetadataError('Unsupported native interface class flags')
    depth = struct.unpack('<i', ob.keep(iface + 0x38, 4))[0]
    if not 0 <= depth < MAX_DEPTH:
        raise ActorInterfaceMetadataError('Interface base-chain depth exceeds local bound')
    matches, classes, seen, total = [], [], set(), 0
    cursor = actor_class
    while cursor:
        if cursor in seen or len(seen) >= MAX_DEPTH:
            raise ActorInterfaceMetadataError('Pawn class ancestry is cyclic or over bound')
        seen.add(cursor)
        desc = ob.class_identity(cursor)
        header = ob.keep(cursor + 0x200, 12)
        data, count = struct.unpack('<Qi', header)
        if count < 0 or count > MAX_INTERFACES or total + count > MAX_INTERFACES:
            raise ActorInterfaceMetadataError('Implemented-interface count exceeds local bound')
        total += count
        entries = ob.keep(data, count * 16) if count else b''
        classes.append({'name': desc['name'], 'interface_count': count})
        for index in range(count):
            item = entries[index * 16:(index + 1) * 16]
            entry_iface, adjustment = struct.unpack_from('<Qi', item)
            if item[12] != 0:
                continue
            entry = ob.class_identity(entry_iface)
            entry_depth = struct.unpack('<i', ob.keep(entry_iface + 0x38, 4))[0]
            if not 0 <= entry_depth < MAX_DEPTH:
                raise ActorInterfaceMetadataError('Implemented interface base-chain depth is invalid')
            if depth > entry_depth:
                continue
            chain = ob.ptr(entry_iface + 0x30)
            if ob.ptr(chain + depth * 8) == iface + 0x30:
                matches.append({'declaring_class': desc['name'], 'declaring_class_address': cursor,
                                'interface_name': entry['name'], 'interface_address': entry_iface,
                                'entry_index': index, 'adjustment': adjustment})
        cursor = desc['parent']
    if len(matches) != 1:
        raise ActorInterfaceMetadataError('Missing or ambiguous native Pawn interface binding')
    match = matches[0]
    if match['adjustment'] != ADJUSTMENT:
        raise ActorInterfaceMetadataError('Observed interface adjustment differs from qualified constructor')
    secondary_object = actor + match['adjustment']
    secondary = ob.ptr(secondary_object)
    if secondary != module_base + SECONDARY_VTABLE_RVA:
        raise ActorInterfaceMetadataError('Observed secondary vtable differs from qualified constructor')
    target = ob.ptr(secondary + SLOT)
    if target != module_base + WRITER_RVA:
        raise ActorInterfaceMetadataError('Observed interface method differs from qualified writer')
    prefix = ob.keep(target, 32)
    if hashlib.sha256(prefix).hexdigest() != WRITER_PREFIX_SHA256:
        raise ActorInterfaceMetadataError('Observed interface method prefix differs from saved writer')
    # The final path checks include registry/Class/name/Outer chain stability.
    for address, row in ((actor, candidate), (actor_class, klass)):
        if object_path(ob.read, module_base, address) != row['asset_path']:
            raise ActorInterfaceMetadataError('Selected Pawn metadata path changed')
    ob.finish()
    return {
        'status': 'observed_source_qualified_native_interface',
        'interface_name': iface_row['name'], 'interface_address': iface,
        'candidate_address': actor, 'candidate_path': candidate['asset_path'],
        'class_address': actor_class, 'class_path': klass['asset_path'],
        'native_interface_gate_observed': True, 'binding': match,
        'main_vtable_rva': MAIN_VTABLE_RVA, 'secondary_vtable_rva': SECONDARY_VTABLE_RVA,
        'method_slot': SLOT, 'method_target_rva': WRITER_RVA,
        'method_code_prefix_bytes': 32, 'method_code_prefix_sha256': hashlib.sha256(prefix).hexdigest(),
        'method_code_prefix_hex': prefix.hex(), 'class_interfaces_observed': classes,
        'identity_rechecked': True, 'snapshot_atomic': False,
        'native_getter_called': False, 'native_method_executed': False,
        'replication_flags_value_observed': False, 'native_acceptance_verified': False,
        'spawn_verified': False, 'read_calls': ob.calls, 'read_bytes': ob.bytes_read,
        'shipping_sha256': SHIPPING_SHA256,
        'source_pins': {name: {'relative_path': pin[0], 'sha256': pin[1]} for name, pin in SOURCE_PINS.items()},
    }
