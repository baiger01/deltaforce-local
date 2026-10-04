"""Source-pinned object-registry metadata reads; no process or native-call API.

Sources are recorded in work/evidence/native-object-registry-metadata-reader.json.
The caller owns read_exact and must reject unavailable/unreadable memory. Values
are read at the proved global cells, never guessed from the default UE layout.
"""
from dataclasses import dataclass, replace
import struct
from typing import Callable, Iterator

ReadExact = Callable[[int, int], bytes]
REGISTRY_RVA = 0x1E34EE48
COUNT_RVA = REGISTRY_RVA + 0x14
CHUNKS_RVA = REGISTRY_RVA + 0x20
POINTER_DECODER_RVA = 0x1DB3A770
OUTER_SELECTOR_RVA = 0x1E318784
INNER_SELECTORS_RVA = 0x1E31878C
PARAMETER_RVA = 0x1E3187B4
ENTRY_SIZE = 24
MAX_BATCH_BYTES = 8192  # Reader policy; batches contain whole 24-byte entries.
OBJECT_INDEX_OFFSET = 0x24
EXCLUDED_FLAGS = 0x30000000
DEFAULT_MAX_OBJECTS = 1_000_000
ABSOLUTE_MAX_OBJECTS = 2_000_000  # Reader policy, not a native capacity.
_U64_MAX = (1 << 64) - 1


class ObjectMetadataError(ValueError):
    """Incomplete, unsupported, inconsistent or over-budget metadata."""


@dataclass(frozen=True)
class ObjectRecord:
    index: int
    object_address: int
    serial: int


@dataclass(frozen=True)
class _Snapshot:
    count: int
    chunks_address: int
    decoder_address: int
    outer_selector: int
    inner_selector: int | None
    parameter: int | None
    entries_per_chunk: int


def _address(base: int, offset: int = 0) -> int:
    if (type(base) is not int or type(offset) is not int or
            base <= 0 or offset < 0 or base > _U64_MAX - offset):
        raise ObjectMetadataError('invalid_metadata_address')
    return base + offset


def _read(read_exact: ReadExact, address: int, size: int) -> bytes:
    _address(address, size - 1)
    data = read_exact(address, size)
    if not isinstance(data, bytes) or len(data) != size:
        raise ObjectMetadataError('read_exact_returned_incomplete_metadata')
    return data


def _u32(read_exact: ReadExact, address: int) -> int:
    return struct.unpack('<I', _read(read_exact, address, 4))[0]


def _u64(read_exact: ReadExact, address: int) -> int:
    return struct.unpack('<Q', _read(read_exact, address, 8))[0]


def _chunk_divisor(outer: int, inner: int | None, parameter: int | None) -> int:
    """Exact signed-IDIV divisor in d60500/d60d00 for nonnegative indices.

    Outer 1..10 selects a different global inner-selector cell, not a different
    arithmetic formula. The inner selector and parameter must therefore be read.
    Native zero-divisor branches are rejected rather than executed.
    """
    if not 1 <= outer <= 10:
        return 0x10000
    if inner is None or parameter is None:
        raise ObjectMetadataError('missing_native_chunk_parameters')
    p = parameter & 0xFFFFFFFF
    if inner == 0:
        n = (p + 2) & 0x3F
    elif inner == 1:
        n = (p ^ 0xFFFFFFFC) & 0x3F
    elif inner == 2:
        n = (p & 0x32) | 0x0D
    elif inner == 3:
        n = (p ^ 0xFFFFFFF6) & 0x3F
    elif inner == 5:
        n = (p & 0x0D) | 0x32
    elif inner == 6:
        n = (p & 0x3A) | 5
    elif inner == 7:
        n = ((p & 7) << 3) | 1
    elif inner == 8:
        n = (p & 0x39) | 6
    elif inner in (9, 10):
        n = (p ^ 0x10) & 0x3F
    elif inner == 11:
        n = ((p ^ inner) & 0x3F) + 0x40
    elif inner == 12:
        n = ((p ^ 0x0E) & 0x3F) + 0x40
    elif inner == 13:
        n = ((p + 0x0E) & 0x3F) + 0x40
    elif inner == 14:
        n = ((p + 0x0F) & 0x3F) + 0x40
    elif inner == 15:
        n = ((p ^ 0x0D) & 0x3F) + 0x40
    elif inner == 16:
        n = ((p ^ inner) & 0x3F) + 0x40
    elif inner == 17:
        n = ((p & 0x25) | 0x1A) + 0x40
    elif inner == 18:
        n = ((p & 0x22) | 0x1D) + 0x40
    elif inner == 19:
        n = ((p ^ 0xFFFFFFEB) & 0x3F) + 0x40
    elif inner == 20:
        n = ((p ^ 0x11) & 0x3F) + 0x40
    else:
        raise ObjectMetadataError('native_chunk_divisor_would_be_zero')
    divisor = n << 10
    if divisor <= 0:
        raise ObjectMetadataError('native_chunk_divisor_would_be_zero')
    return divisor


def _snapshot(read_exact: ReadExact, module_base: int, max_objects: int) -> _Snapshot:
    _address(module_base)
    if type(max_objects) is not int or not 0 <= max_objects <= ABSOLUTE_MAX_OBJECTS:
        raise ObjectMetadataError('invalid_object_count_budget')
    count = struct.unpack('<i', _read(read_exact, _address(module_base, COUNT_RVA), 4))[0]
    if count < 0 or count > max_objects:
        raise ObjectMetadataError('object_count_exceeds_budget_or_is_negative')
    chunks = _u64(read_exact, _address(module_base, CHUNKS_RVA))
    decoder = _u64(read_exact, _address(module_base, POINTER_DECODER_RVA))
    if decoder:
        raise ObjectMetadataError('pointer_decoder_required: native callback is not invoked')
    outer = _u32(read_exact, _address(module_base, OUTER_SELECTOR_RVA))
    inner = parameter = None
    if 1 <= outer <= 10:
        inner = _u32(read_exact, _address(module_base, INNER_SELECTORS_RVA + 4*(outer-1)))
        parameter = _u32(read_exact, _address(module_base, PARAMETER_RVA))
    divisor = _chunk_divisor(outer, inner, parameter)
    if count and not chunks:
        raise ObjectMetadataError('nonempty_registry_has_null_chunk_table')
    return _Snapshot(count, chunks, decoder, outer, inner, parameter, divisor)


def _check_snapshot(read_exact: ReadExact, module_base: int, max_objects: int,
                    snapshot: _Snapshot, *, minimum_count: int | None = None) -> int:
    """Allow bounded append-only count growth, never a changed registry layout.

    Existing source getters require index<count, not equality with an older
    count. Growth therefore leaves the initial index range valid. The caller
    carries the returned count as its next minimum to reject observed shrinkage.
    The original snapshot remains the fixed iteration and chunk-layout boundary.
    """
    observed = _snapshot(read_exact, module_base, max_objects)
    floor = snapshot.count if minimum_count is None else max(snapshot.count, minimum_count)
    if observed.count < floor or replace(observed, count=snapshot.count) != snapshot:
        raise ObjectMetadataError('registry_header_or_chunk_parameters_changed')
    return observed.count


def _entry(read_exact: ReadExact, snapshot: _Snapshot, index: int) -> tuple[int, int, int]:
    if type(index) is not int or not 0 <= index < snapshot.count:
        raise ObjectMetadataError('object_index_outside_registry')
    chunk_index, within = divmod(index, snapshot.entries_per_chunk)
    chunk = _u64(read_exact, _address(snapshot.chunks_address, 8*chunk_index))
    if not chunk:
        raise ObjectMetadataError('null_object_chunk')
    data = _read(read_exact, _address(chunk, ENTRY_SIZE*within), ENTRY_SIZE)
    return (struct.unpack_from('<Q', data)[0],
            struct.unpack_from('<I', data, 8)[0],
            struct.unpack_from('<I', data, 0x14)[0])


def _slot_state(pointer: int, flags: int, serial: int) -> dict:
    """Diagnostic categories only: no object addresses or raw identity values."""
    return {'pointer_state': 'non_null' if pointer else 'null',
            'flag_state': 'excluded' if flags & EXCLUDED_FLAGS else 'not_excluded',
            'serial_state': 'initialized' if serial else 'uninitialized'}


def _changed_slot_error(context: dict) -> ObjectMetadataError:
    error = ObjectMetadataError('object_slot_changed_during_metadata_read')
    error.metadata_failure_context = context
    return error


def _batch_change_context(first: int, amount: int, original: bytes, repeated: bytes) -> dict:
    changes, changed_count = [], 0
    for offset in range(amount):
        start = ENTRY_SIZE*offset
        before, after = original[start:start+ENTRY_SIZE], repeated[start:start+ENTRY_SIZE]
        if before == after:
            continue
        changed_count += 1
        if len(changes) >= 8:
            continue
        fields = [label for label, lo, hi in (
            ('object_pointer', 0, 8), ('flags', 8, 12),
            ('auxiliary_words', 12, 20), ('serial', 20, 24)) if before[lo:hi] != after[lo:hi]]
        values = lambda row: (struct.unpack_from('<Q', row)[0],
                              struct.unpack_from('<I', row, 8)[0],
                              struct.unpack_from('<I', row, 20)[0])
        changes.append({'object_index': first+offset, 'changed_fields': fields,
                        'before': _slot_state(*values(before)), 'after': _slot_state(*values(after))})
    return {'phase': 'registry_batch_recheck', 'index_range': [first, first+amount],
            'first_changed_object_index': changes[0]['object_index'],
            'changed_slot_count': changed_count, 'changes': changes,
            'changes_truncated': changed_count > len(changes),
            'batch_records_yielded': False}


def iter_object_records(read_exact: ReadExact, module_base: int, *,
                        max_objects: int = DEFAULT_MAX_OBJECTS,
                        scan_metadata: dict | None = None,
                        start_index: int = 0,
                        stop_index: int | None = None) -> Iterator[ObjectRecord]:
    """Iterate the initial registry range or an explicit frozen subrange.

    Caller must exhaust the iterator and discard accumulated results on errors.
    This is not an atomic snapshot or a complete global inventory. Bounded count
    growth is allowed while every other header/chunk parameter remains stable;
    newly appended entries are not scanned. Observed count shrinkage, changed
    chunk pointers or changed batch bytes are rejected. Callers still recheck
    every selected class/descriptor/outer/driver identity. Records contain no
    names, class guesses, or object payload. An optional empty metadata sink is
    filled only after successful exhaustion; it never reports a global inventory.
    """
    if scan_metadata is not None and (type(scan_metadata) is not dict or scan_metadata):
        raise ObjectMetadataError('scan_metadata_requires_empty_dict')
    if (type(start_index) is not int or start_index < 0 or
            (stop_index is not None and
             (type(stop_index) is not int or stop_index < start_index))):
        raise ObjectMetadataError('invalid_explicit_registry_index_range')
    snapshot = _snapshot(read_exact, module_base, max_objects)
    stop = snapshot.count if stop_index is None else stop_index
    if start_index > stop or stop > snapshot.count:
        raise ObjectMetadataError('explicit_registry_index_range_outside_snapshot')
    observed_count = snapshot.count
    first = start_index
    while first < stop:
        observed_count = _check_snapshot(read_exact, module_base, max_objects, snapshot,
                                         minimum_count=observed_count)
        chunk_index, within = divmod(first, snapshot.entries_per_chunk)
        table_entry = _address(snapshot.chunks_address, 8*chunk_index)
        chunk = _u64(read_exact, table_entry)
        if not chunk:
            raise ObjectMetadataError('null_object_chunk')
        amount = min(MAX_BATCH_BYTES//ENTRY_SIZE, stop-first,
                     snapshot.entries_per_chunk-within)
        block_address = _address(chunk, ENTRY_SIZE*within)
        block_bytes = ENTRY_SIZE*amount
        original = _read(read_exact, block_address, block_bytes)
        candidates = []
        for offset in range(amount):
            at = ENTRY_SIZE*offset
            pointer = struct.unpack_from('<Q', original, at)[0]
            flags = struct.unpack_from('<I', original, at+8)[0]
            serial = struct.unpack_from('<I', original, at+0x14)[0]
            if not pointer or flags & EXCLUDED_FLAGS:
                continue
            index = first+offset
            actual_index = struct.unpack('<i', _read(
                read_exact, _address(pointer, OBJECT_INDEX_OFFSET), 4
            ))[0]
            if actual_index != index:
                raise ObjectMetadataError('object_slot_backreference_mismatch')
            candidates.append(ObjectRecord(index, pointer, serial))
        observed_count = _check_snapshot(read_exact, module_base, max_objects, snapshot,
                                         minimum_count=observed_count)
        if _u64(read_exact, table_entry) != chunk:
            raise ObjectMetadataError('object_chunk_pointer_changed_during_metadata_read')
        repeated = _read(read_exact, block_address, block_bytes)
        if repeated != original:
            raise _changed_slot_error(_batch_change_context(first, amount, original, repeated))
        # No item is yielded until the whole batch passed its second metadata read.
        yield from candidates
        first += amount
    observed_count = _check_snapshot(read_exact, module_base, max_objects, snapshot,
                                     minimum_count=observed_count)
    if scan_metadata is not None:
        scan_metadata.update(initial_count=snapshot.count, final_observed_count=observed_count,
            entries_per_chunk=snapshot.entries_per_chunk, maximum_count=max_objects,
            initial_index_range=[start_index, stop],
            source_scope=('initial_bounded_registry_entries' if start_index == 0 and stop_index is None
                          else 'explicit_bounded_registry_entries'), initial_range_exhausted=True,
            complete_global_inventory=False, snapshot_atomic=False)


def validate_object_record(read_exact: ReadExact, module_base: int, object_address: int, *,
                           max_objects: int = DEFAULT_MAX_OBJECTS) -> ObjectRecord:
    """Return a stable live registry identity, even before weak-key allocation.

    A zero serial does not invalidate the registry object: source10ea1680 creates
    a serial lazily when the object's first weak key is made. This reader never
    performs that allocation. Ordinary pointer/flags/index checks still apply.
    """
    snapshot = _snapshot(read_exact, module_base, max_objects)
    index = struct.unpack('<i', _read(
        read_exact, _address(object_address, OBJECT_INDEX_OFFSET), 4
    ))[0]
    pointer, flags, serial = _entry(read_exact, snapshot, index)
    if pointer != object_address or flags & EXCLUDED_FLAGS:
        raise ObjectMetadataError('object_slot_not_live_or_identity_mismatch')
    _check_snapshot(read_exact, module_base, max_objects, snapshot)
    repeated = _entry(read_exact, snapshot, index)
    if repeated != (pointer, flags, serial):
        changed = [label for label, before, after in zip(
            ('object_pointer', 'flags', 'serial'), (pointer, flags, serial), repeated) if before != after]
        raise _changed_slot_error({'phase': 'single_object_identity_recheck',
            'object_index': index, 'changed_fields': changed,
            'before': _slot_state(pointer, flags, serial), 'after': _slot_state(*repeated)})
    return ObjectRecord(index, pointer, serial)


def weak_object_key(read_exact: ReadExact, module_base: int, object_address: int, *,
                    max_objects: int = DEFAULT_MAX_OBJECTS) -> bytes:
    """Return an already-created key; never allocate a missing native serial."""
    record = validate_object_record(read_exact, module_base, object_address,
                                    max_objects=max_objects)
    if record.serial == 0:
        raise ObjectMetadataError('object_has_no_native_weak_key')
    return struct.pack('<iI', record.index, record.serial)
