"""Read only existing GUID2/4/6 associations of a caller-qualified connection.

No process API, native getter, resolution, allocation, property or RPC read.
The caller must supply its original typed C/D identity recheck callback. A
matched weak reference proves an association, never Actor ownership or spawn.
"""
import hashlib
from pathlib import Path
import struct

import native_metadata_objects as objects
from native_replication_metadata_core import MetadataSession, span

ROOT = Path(__file__).resolve().parent.parent
SOURCE = 'work/evidence/map-entry-next-20261005/native-guid-object-lookup-source.json'
SOURCE_SHA256 = '647b9698e1f9343d69c5b98970078ca00ade9fd92c98e494c144338008a79c42'
GUIDS = (2, 4, 6)
LOOKUP_TARGET_RVA = 0x12BB8320
MAX_SLOTS, MAX_BUCKETS, MAX_CHAIN = 65536, 131072, 128
MAX_LOCAL_BYTES, MAX_LOCAL_CALLS = 128 * 1024, 4096
IMAGE_BYTES = 536408064


def qualified_guid_mapping_source_pins(root=ROOT):
    """Verify the exact offline source ledger and its small saved dependencies."""
    import json
    root = Path(root).resolve()
    path = root / SOURCE
    if not 0 < path.stat().st_size <= 65536:
        raise ValueError('GUID source ledger exceeds its fixed bound')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
        raise ValueError('GUID source ledger identity mismatch')
    data = json.loads(raw)
    pins = list(data['dependency_pins'])
    for row in data['roots']:
        pins += [{'path': row['asm_relative_path'], 'sha256': row['asm_sha256']},
                 {'path': row['code_relative_path'], 'sha256': row['file_sha256']}]
    for row in pins:
        source = (root / row['path']).resolve()
        if not source.is_relative_to((root / 'work/evidence').resolve()):
            raise ValueError('GUID source dependency escaped evidence directory')
        if not 0 < source.stat().st_size <= 1024 * 1024:
            raise ValueError('GUID source dependency exceeds local bound')
        if hashlib.sha256(source.read_bytes()).hexdigest() != row['sha256']:
            raise ValueError('GUID source dependency identity mismatch')
    return {'source_path': SOURCE, 'source_sha256': SOURCE_SHA256,
            'client_sha256': data['client_sha256'], 'fixed_dynamic_guids': list(GUIDS)}


def guid_mapping_source_pins(root=ROOT):
    """Return the launch seal without changing the existing summary API.

    Include this reader, its nine saved native dependencies, and the scoped GP
    bind-gate reader/ledger/dependencies used by this same opt-in observation.
    No metadata collection or process access occurs while building this seal.
    """
    import json
    root = Path(root).resolve()
    try:
        qualified_guid_mapping_source_pins(root)
        raw = (root / SOURCE).read_bytes()
        if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
            raise ValueError('GUID source ledger identity changed during sealing')
        data = json.loads(raw)
        pins = list(data['dependency_pins'])
        for row in data['roots']:
            pins += [{'path': row['asm_relative_path'], 'sha256': row['asm_sha256']},
                     {'path': row['code_relative_path'], 'sha256': row['file_sha256']}]
        relative = 'work/native_guid_object_metadata.py'
        result = {SOURCE: SOURCE_SHA256,
                  relative: hashlib.sha256((root / relative).read_bytes()).hexdigest()}
        result.update({row['path']: row['sha256'] for row in pins})
        from native_gp_bind_gate import qualified_gp_bind_gate_source_pins
        for relative, digest in qualified_gp_bind_gate_source_pins(root).items():
            if relative in result and result[relative] != digest:
                raise ValueError('GUID and GP bind-gate source seals disagree')
            result[relative] = digest
        from native_world_settings_context import qualified_world_settings_context_source_pins
        result.update(qualified_world_settings_context_source_pins(root))
        return result
    except OSError as error:
        raise ValueError('GUID source seal files are missing or unreadable') from error


class _Read:
    def __init__(self, session):
        if not isinstance(session, MetadataSession):
            raise ValueError('A shared bounded MetadataSession is required')
        self.session = session
        self.bytes = self.calls = 0
        self.facts = {}

    def read(self, address, size):
        span(address, size)
        if self.calls >= MAX_LOCAL_CALLS or self.bytes + size > MAX_LOCAL_BYTES:
            raise ValueError('GUID metadata local read budget exceeded')
        self.calls += 1
        self.bytes += size
        raw = self.session.read(address, size)
        if type(raw) is not bytes or len(raw) != size:
            raise ValueError('GUID metadata backend returned incomplete or mutable bytes')
        return raw

    def fact(self, address, size):
        raw = self.read(address, size)
        key = (address, size)
        if key in self.facts and self.facts[key] != raw:
            raise ValueError('GUID association metadata changed during observation')
        self.facts[key] = raw
        if self.read(address, size) != raw:
            raise ValueError('GUID association metadata changed during observation')
        return raw

    def pointer(self, address):
        pointer = struct.unpack('<Q', self.fact(address, 8))[0]
        span(pointer, 1)
        return pointer

    def recheck(self):
        for (address, size), expected in tuple(self.facts.items()):
            if self.read(address, size) != expected:
                raise ValueError('GUID association metadata changed during final recheck')


def _lookup(read, cache, header, guid):
    data = struct.unpack_from('<Q', header)[0]
    count = struct.unpack_from('<i', header, 8)[0]
    free = struct.unpack_from('<i', header, 0x34)[0]
    if not 0 <= free <= count <= MAX_SLOTS:
        raise ValueError('GUID table slot counts exceed local bounds')
    if count == free:
        return None
    buckets = struct.unpack_from('<i', header, 0x48)[0]
    if not 1 <= buckets <= MAX_BUCKETS or buckets & (buckets - 1):
        raise ValueError('GUID table hash bucket count is invalid')
    span(data, count * 56)
    storage = struct.unpack_from('<Q', header, 0x40)[0]
    if not storage:
        if buckets > 2:
            raise ValueError('GUID hash exceeds its inline storage')
        storage = cache + 0x38
    span(storage, buckets * 4)
    index = struct.unpack('<i', read.fact(storage + (guid & (buckets - 1)) * 4, 4))[0]
    seen = set()
    while index != -1:
        if len(seen) >= MAX_CHAIN or not 0 <= index < count or index in seen:
            raise ValueError('GUID hash chain is invalid, cyclic or over bound')
        seen.add(index)
        item = read.fact(data + index * 56, 56)
        if struct.unpack_from('<I', item)[0] == guid:
            return index, item[8:16]
        index = struct.unpack_from('<i', item, 0x30)[0]
    return None


def _existing_weak(read, module_base, key):
    index, serial = struct.unpack('<iI', key)
    if serial == 0 or index < 0:
        return {'status': 'weak_reference_unresolved', 'object_address': None}
    snapshot = objects._snapshot(read.fact, module_base, objects.DEFAULT_MAX_OBJECTS)
    if index >= snapshot.count:
        return {'status': 'weak_reference_unresolved', 'object_address': None}
    chunk_index, within = divmod(index, snapshot.entries_per_chunk)
    chunk = read.pointer(snapshot.chunks_address + 8 * chunk_index)
    entry = read.fact(chunk + 24 * within, 24)
    address = struct.unpack_from('<Q', entry)[0]
    flags = struct.unpack_from('<I', entry, 8)[0]
    observed_serial = struct.unpack_from('<I', entry, 0x14)[0]
    if not address or flags & objects.EXCLUDED_FLAGS or observed_serial != serial:
        return {'status': 'weak_reference_unresolved', 'object_address': None}
    span(address, objects.OBJECT_INDEX_OFFSET + 4)
    actual_index = struct.unpack('<i', read.fact(address + objects.OBJECT_INDEX_OFFSET, 4))[0]
    if actual_index != index:
        raise ValueError('GUID mapped object registry backreference mismatch')
    # The registry's zero-serial allowance does not apply to this native weak
    # reference: its serial was already required nonzero by10ecea20.
    objects._check_snapshot(read.fact, module_base, objects.DEFAULT_MAX_OBJECTS, snapshot)
    return {'status': 'existing_object_observed', 'object_address': address,
            'object_index': index, 'serial': serial,
            'weak_identity_initialized': True}


def observe_connection_guid_mappings(session, module_base, *, driver_address,
                                     connection_address, recheck_binding,
                                     additional_static_guids=()):
    """Publish one all-or-nothing metadata observation of the three fixed GUIDs.

    recheck_binding is the caller's original typed driver/connection identity
    closure; it must raise if those selections changed. The callback runs before
    and after, and the entire small pointer/hash/registry set is re-read after it.
    No class name, PlayerController role, GUID ownership or native acceptance is
    inferred from GUID numbers. Missing references are never resolved/created.
    """
    if not callable(recheck_binding):
        raise ValueError('The original typed binding recheck callback is required')
    if (type(additional_static_guids) is not tuple or len(additional_static_guids) > 8 or
            any(type(guid) is not int or not 3 <= guid <= 0xffffffff or not guid & 1
                for guid in additional_static_guids) or
            len(set(additional_static_guids)) != len(additional_static_guids)):
        raise ValueError('Additional observations require distinct bounded static GUIDs')
    for address in (module_base, driver_address, connection_address):
        span(address, 1)
    recheck_binding()
    read = _Read(session)
    if (read.pointer(driver_address + 0x98) != connection_address or
            read.pointer(connection_address + 0x58) != driver_address):
        raise ValueError('GUID observation requires the current primary connection')
    package_map = read.pointer(connection_address + 0x68)
    if read.pointer(package_map + 0x130) != connection_address:
        raise ValueError('PackageMap connection backlink mismatch')
    table = read.pointer(package_map)
    if not module_base <= table <= module_base + IMAGE_BYTES - 0x2d0:
        raise ValueError('PackageMap virtual table is outside the fixed image')
    if read.pointer(table + 0x2c8) != module_base + LOOKUP_TARGET_RVA:
        raise ValueError('PackageMap GUID lookup target is not source-qualified')
    cache = read.pointer(package_map + 0x310)
    if read.fact(cache + 0x152, 1) != b'\0':
        raise ValueError('PackageMap export-reference mode is unsupported')
    if read.fact(connection_address + 0xb4, 1)[0] & 1:
        raise ValueError('Internal-ACK reference profile is unsupported')
    header = read.fact(cache, 0x50)
    rows = []
    for guid in GUIDS + additional_static_guids:
        found = _lookup(read, cache, header, guid)
        result = ({'status': 'mapping_missing', 'object_address': None} if found is None
                  else _existing_weak(read, module_base, found[1]))
        rows.append({'guid': guid, **result,
                     'map_slot_index': None if found is None else found[0]})
    recheck_binding()
    read.recheck()
    return {'status': 'existing_guid_associations_observed',
            'driver_address': driver_address, 'connection_address': connection_address,
            'package_map_address': package_map, 'guid_cache_address': cache,
            'mappings': rows, 'fixed_dynamic_guids': list(GUIDS),
            **({'requested_static_guids': list(additional_static_guids)} if additional_static_guids else {}),
            'primary_connection_and_metadata_rechecked': True,
            'typed_root_qualification': 'caller_owned_recheck_callback',
            'native_getter_invoked': False, 'missing_reference_resolved': False,
            'native_getter_result_reproduced': False,
            'native_object_created': False, 'snapshot_atomic': False,
            'actor_role_or_ownership_inferred': False, 'native_spawn_verified': False,
            'read_bytes': read.bytes, 'read_calls': read.calls}
