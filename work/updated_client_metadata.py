"""Explicit relocation of qualified global cells for build 79fb7b10.

The historical pure algorithms remain byte-for-byte pinned. Only their proved
global-cell reads are translated; object addresses, metadata and values are not.
This does not qualify reflection offsets, RPCs or gameplay for the new build.
"""
import hashlib
import json
from pathlib import Path
import struct

import native_metadata_objects as objects
import native_metadata_names as names
import native_metadata_paths as paths

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA256 = '79fb7b105170141ed863331d36833a73062e66bf5291b2364fe3a64c18336203'
QUALIFICATION = 'work/evidence/updated-metadata-roots-79fb7b10-qualified.json'
QUALIFICATION_SHA256 = '73419a5fb8db36319de2af327a4924f689c5c564ff21128d111007ba0cdfdb16'
IMAGE_BYTES = 536408064
REFLECTION_PROOF = 'work/evidence/updated-replication-core-79fb7b10.json'
REFLECTION_PROOF_SHA256 = '762e8111b52e4bd4273489b0a9444adb2340c8a21fd6808cb23c1e1d6bb7cd58'
CACHE_INITIALIZATION_PROOF = 'work/research_updated_cache_initialization_79fb7b10.json'
CACHE_INITIALIZATION_SHA256 = '9f27a79bd5686c0d90dd3b30d983a3b9af86516de550b0936607c061dc00b6ac'
# Old cell, new cell, exact allowed read size. Array reads remain single cells.
CELLS = ((0x1e34ee5c, 0x1e34ee9c, 4), (0x1e34ee68, 0x1e34eea8, 8),
         (0x1db3a770, 0x1db3a770, 8), (0x1e318784, 0x1e3187c4, 4),
         (0x1e3187b4, 0x1e3187f4, 4), (0x1e3267ac, 0x1e3267ec, 1),
         (0x1e34ca90, 0x1e34cad0, 8))
ARRAYS = ((0x1e31878c, 0x1e3187cc, 10, 4),
          (0x1e326a88, 0x1e326ac8, 8192, 8))


def qualification_pins():
    raw = (ROOT / QUALIFICATION).read_bytes()
    if hashlib.sha256(raw).hexdigest() != QUALIFICATION_SHA256:
        raise ValueError('Updated metadata qualification SHA changed')
    evidence = json.loads(raw)
    if (evidence['shipping_sha256'] != SOURCE_SHA256 or
            evidence['proof_scope']['native_protocol_compatibility_verified'] is not False):
        raise ValueError('Unexpected updated metadata qualification scope')
    pins = {QUALIFICATION: QUALIFICATION_SHA256}
    selected = {f'work/native_metadata_{part}.py' for part in ('objects', 'names', 'paths')}
    for row in evidence['evidence_reports'] + evidence['source_pins']:
        if row['path'] not in selected and row not in evidence['evidence_reports']:
            continue
        path = (ROOT / row['path']).resolve(strict=True)
        if not path.is_relative_to(ROOT) or hashlib.sha256(path.read_bytes()).hexdigest() != row['sha256']:
            raise ValueError('Updated metadata qualification dependency changed')
        pins[row['path']] = row['sha256']
    if not selected <= pins.keys():
        raise ValueError('Missing qualified pure metadata dependency')
    raw = (ROOT / REFLECTION_PROOF).read_bytes()
    if hashlib.sha256(raw).hexdigest() != REFLECTION_PROOF_SHA256:
        raise ValueError('Updated reflection qualification changed')
    pins[REFLECTION_PROOF] = REFLECTION_PROOF_SHA256
    if hashlib.sha256((ROOT / CACHE_INITIALIZATION_PROOF).read_bytes()).hexdigest() != CACHE_INITIALIZATION_SHA256:
        raise ValueError('Updated cache initialization qualification changed')
    pins[CACHE_INITIALIZATION_PROOF] = CACHE_INITIALIZATION_SHA256
    pins['work/updated_client_metadata.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return pins


class UpdatedMetadata:
    def __init__(self, read_exact, module_base):
        if not callable(read_exact) or type(module_base) is not int or not 0 < module_base < 2**47 - IMAGE_BYTES:
            raise ValueError('Invalid updated metadata backend or base')
        self.pins = qualification_pins()
        self.backend, self.base = read_exact, module_base

    def _read(self, address, size):
        if type(address) is not int or type(size) is not int or not 0 < size <= 8192:
            raise ValueError('Invalid bounded updated metadata read')
        if self.base <= address < self.base + IMAGE_BYTES:
            rva = address - self.base
            for old, new, length in CELLS:
                if (rva, size) == (old, length):
                    return self.backend(self.base + new, size)
            for old, new, count, stride in ARRAYS:
                if old <= rva < old + count * stride and size == stride and (rva - old) % stride == 0:
                    return self.backend(self.base + new + rva - old, size)
            raise ValueError('Unqualified updated metadata image global read')
        return self.backend(address, size)

    def records(self, **options):
        return objects.iter_object_records(self._read, self.base, **options)

    def record(self, address):
        return objects.validate_object_record(self._read, self.base, address)

    def name(self, address):
        return names.object_name(self._read, self.base, address)

    def class_pointer(self, address):
        before = self.record(address)
        raw = self._read(address + 8, 8)
        if self._read(address + 8, 8) != raw or self.record(address) != before:
            raise ValueError('Updated metadata object class identity changed')
        return struct.unpack('<Q', raw)[0]

    def superclass(self, address):
        identity = self.record(address)
        raw = self._read(address + 0x48, 8)
        if self._read(address + 0x48, 8) != raw or self.record(address) != identity:
            raise ValueError('Updated superclass metadata changed')
        return struct.unpack('<Q', raw)[0]

    def path(self, address):
        value = paths.object_path(self._read, self.base, address)
        # Native GetPath appends high bytes differently from ToString; until
        # that separate formatting path is supported, only ASCII labels qualify.
        if not value.isascii() or '?' in value:
            raise ValueError('Updated metadata exact path requires unambiguous ASCII')
        return value

    def _field_hooks(self, address):
        raw = self._read(address, 8)
        table, = struct.unpack('<Q', raw)
        if not self.base <= table <= self.base + IMAGE_BYTES - 0x98:
            raise ValueError('Updated property vtable is outside the qualified image')
        result = {}
        for slot in (0x60, 0x88, 0x90):
            # Actual vtable addresses are already in the updated image coordinate
            # space, so they must not pass through historical global relocation.
            value = self.backend(table + slot, 8)
            if type(value) is not bytes or len(value) != 8:
                raise ValueError('Incomplete updated property vtable cell')
            target, = struct.unpack('<Q', value)
            if not self.base <= target < self.base + IMAGE_BYTES:
                raise ValueError('Updated property method is outside the qualified image')
            if self.backend(table + slot, 8) != value:
                raise ValueError('Updated property method changed during observation')
            result[hex(slot)] = dict(target_rva=target - self.base, function_called=False,
                                     executable_page_or_function_body_verified=False)
        if self._read(address, 8) != raw:
            raise ValueError('Updated property vtable changed during observation')
        return dict(field_vtable_rva=table - self.base, virtual_methods=result)

    def fields(self, class_address, *, virtual_methods=False):
        """Own FProperty metadata only; RepIndex is not a wire field handle.

        Caller must select this UClass from the complete typed descriptor scan.
        No inherited instance value or RPC parameter is read or synthesized.
        """
        if type(virtual_methods) is not bool:
            raise ValueError('Explicit property method observation policy required')
        identity = self.record(class_address)
        path = self.path(class_address)
        head = self._read(class_address + 0x70, 8)
        current, = struct.unpack('<Q', head)
        seen, saved, rows = set(), [], []
        while current:
            if current in seen or len(seen) >= 2048:
                raise ValueError('Updated property chain cycle or policy bound')
            seen.add(current)
            raw = self._read(current + 0x18, 0x40)
            label = str(names.object_name(self._read, self.base, current, field_representation=0))
            if not label.isascii() or '?' in label:
                raise ValueError('Updated property label requires unambiguous ASCII')
            array_dim, element_size = struct.unpack_from('<ii', raw, 0x24)
            flags_low, = struct.unpack_from('<I', raw, 0x30)
            rep_index, = struct.unpack_from('<H', raw, 0x38)
            offset, = struct.unpack_from('<i', raw, 0x3c)
            if not (1 <= array_dim <= 65536 and 0 <= element_size <= 1048576 and 0 <= offset < 16777216):
                raise ValueError('Updated property metadata exceeds bounded reader policy')
            rows.append(dict(name=label, storage_offset=offset, array_dim=array_dim,
                             element_size=element_size, flags_low32=flags_low, rep_index=rep_index))
            if virtual_methods:
                rows[-1].update(self._field_hooks(current))
            saved.append((current, raw))
            current, = struct.unpack_from('<Q', raw)
        for address, raw in saved:
            if self._read(address + 0x18, 0x40) != raw:
                raise ValueError('Updated property metadata changed during read')
        if virtual_methods:
            for (address, _), row in zip(saved, rows):
                if self._field_hooks(address) != {key: row[key] for key in ('field_vtable_rva', 'virtual_methods')}:
                    raise ValueError('Updated property method binding changed after export')
        if (self._read(class_address + 0x70, 8) != head or
                self.record(class_address) != identity or self.path(class_address) != path):
            raise ValueError('Updated selected class changed during property export')
        return rows

    def class_setup(self, address):
        """Observed setup cells, not an inference from a zero RepIndex."""
        identity = self.record(address)
        flags = self._read(address + 0xd4, 4)
        guard = self._read(address + 0x78, 8)
        headers = self._read(address + 0x110, 0x30)
        arrays = {}
        for offset, name in ((0, 'class_reps'), (0x10, 'net_functions'), (0x20, 'net_properties')):
            storage, count, capacity = struct.unpack_from('<Qii', headers, offset)
            if not 0 <= count <= capacity <= 65536 or count and not storage:
                raise ValueError('Updated class setup arrays exceed metadata policy')
            arrays[name] = dict(count=count, capacity=capacity, storage_present=bool(storage))
        if (self._read(address + 0xd4, 4) != flags or self._read(address + 0x78, 8) != guard
                or self._read(address + 0x110, 0x30) != headers or self.record(address) != identity):
            raise ValueError('Updated class setup metadata changed')
        return dict(class_flags=struct.unpack('<I', flags)[0], setup_guard_raw=guard.hex(),
                    arrays=arrays, setup_invoked=False)

    def functions(self, class_address):
        """Own net UFunction declarations; no arguments or function body is read."""
        identity = self.record(class_address)
        head = self._read(class_address + 0x58, 8)
        current, = struct.unpack('<Q', head)
        seen, saved, result, type_cache = set(), [], [], {}
        while current:
            if current in seen or len(seen) >= 4096:
                raise ValueError('Updated UObject child metadata cycle or policy bound')
            seen.add(current)
            record = self.record(current)
            initial_kind = self.class_pointer(current)
            if initial_kind not in type_cache:
                kind, kinds, is_function, bindings = initial_kind, set(), False, []
                while kind:
                    if kind in kinds or len(kinds) >= 64:
                        raise ValueError('Updated function descriptor type ancestry cycle')
                    kinds.add(kind)
                    class_record, path = self.record(kind), self.path(kind)
                    parent = None if path == '/Script/CoreUObject.Function' else self.superclass(kind)
                    bindings.append((kind, class_record, path, parent))
                    if parent is None:
                        is_function = True
                        break
                    kind = parent
                type_cache[initial_kind] = is_function, bindings
            is_function = type_cache[initial_kind][0]
            following = self._read(current + 0x28, 8)
            flags = parent = None
            if is_function:
                flags = self._read(current + 0xc0, 4)
                parent = self._read(current + 0x48, 8)
                value, = struct.unpack('<I', flags)
                if value & 0x40:
                    result.append(dict(name=str(self.name(current)), path=self.path(current),
                        function_flags=value, super_function_present=bool(struct.unpack('<Q', parent)[0]),
                        parameters_read=False, function_called=False))
            saved.append((current, record, following, flags, parent))
            current, = struct.unpack('<Q', following)
        for at, record, following, flags, parent in saved:
            if (self.record(at) != record or self._read(at + 0x28, 8) != following
                    or flags is not None and (self._read(at + 0xc0, 4) != flags or self._read(at + 0x48, 8) != parent)):
                raise ValueError('Updated function descriptor metadata changed')
        for _, bindings in type_cache.values():
            for address, record, path, parent in bindings:
                if (self.record(address) != record or self.path(address) != path
                        or parent is not None and self.superclass(address) != parent):
                    raise ValueError('Updated function class ancestry changed')
        if self.record(class_address) != identity or self._read(class_address + 0x58, 8) != head:
            raise ValueError('Updated class function chain changed')
        return result
