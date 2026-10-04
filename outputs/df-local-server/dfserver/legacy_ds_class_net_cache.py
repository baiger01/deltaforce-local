"""Bounded offline snapshots of the exact native class-cache field layout.

Source: work/evidence/native-class-cache-producer*.json and the pinned
ReadFieldHeaderAndPayload12864bf0. This module has no process API, class loader,
name resolver, field serializer, RPC definition or game-class default. The
caller supplies header/entry bytes and each cache's actual address from an
independently identified class. Arbitrary synthetic bytes are not game schemas.

The field table is built at runtime, inherits a parent interval and uses 32-byte
entries. Descriptor representation 0/1 selects different native paths; it is
not a complete property type or serializer enum. In particular, ordinary field
envelopes cannot replace the separate RepLayout property command stream.
"""

from dataclasses import dataclass
import struct

from .legacy_ds_actor_fields import NormalClassFieldProfile
from .legacy_ds_bit_archive import UINT32_MAX


HEADER_BYTES = 0x30
ENTRY_BYTES = 32
MAX_FIELDS_PER_CACHE = 4096
MAX_TOTAL_FIELDS = 16384
MAX_PARENT_DEPTH = 32
UINT64_MAX = (1 << 64) - 1


def _address(value, *, nonzero=False):
    if type(value) is not int or not int(nonzero) <= value <= UINT64_MAX:
        raise ValueError('Invalid explicit cache or descriptor address')
    return value


def _range(address, size):
    _address(address, nonzero=True)
    if address + size - 1 > UINT64_MAX:
        raise ValueError('Class-cache snapshot address range exceeds uint64')


@dataclass(frozen=True)
class CacheSnapshotLimits:
    max_fields_per_cache: int = MAX_FIELDS_PER_CACHE
    max_total_fields: int = MAX_TOTAL_FIELDS
    max_parent_depth: int = MAX_PARENT_DEPTH

    def __post_init__(self):
        for value, minimum, maximum in (
                (self.max_fields_per_cache, 0, MAX_FIELDS_PER_CACHE),
                (self.max_total_fields, 0, MAX_TOTAL_FIELDS),
                (self.max_parent_depth, 1, MAX_PARENT_DEPTH)):
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError('Invalid local class-cache snapshot limit')


DEFAULT_LIMITS = CacheSnapshotLimits()


def _limits(limits):
    if not isinstance(limits, CacheSnapshotLimits):
        raise ValueError('An explicit CacheSnapshotLimits is required')
    # A subclass must not be able to replace the snapshot boundary checks.
    CacheSnapshotLimits.__post_init__(limits)


@dataclass(frozen=True)
class CachedField:
    descriptor_address: int
    descriptor_representation: int
    rep_index: int
    checksum: int
    incompatible: bool
    declaring_cache_address: int


@dataclass(frozen=True)
class ClassCacheSnapshot:
    address: int
    index_start: int
    parent_address: int
    opaque_object_key: bytes
    aggregate_checksum: int
    field_storage_address: int
    field_capacity: int
    fields: tuple


def decode_class_cache_snapshot(*, address, header, entry_bytes, limits=DEFAULT_LIMITS):
    """Decode one exact supplied header and its used entries; never read pointers.

    Padding is ignored because the producer does not initialize all entry bytes.
    Descriptor names/types must be recovered separately; no field name is inferred.
    """
    _limits(limits)
    _range(address, HEADER_BYTES)
    if not isinstance(header, bytes) or len(header) != HEADER_BYTES:
        raise ValueError('An exact 48-byte class-cache header is required')
    if not isinstance(entry_bytes, bytes):
        raise ValueError('Immutable class-cache entry bytes are required')
    start = struct.unpack_from('<I', header, 0)[0]
    parent = struct.unpack_from('<Q', header, 8)[0]
    storage = struct.unpack_from('<Q', header, 0x20)[0]
    count, capacity = struct.unpack_from('<ii', header, 0x28)
    if parent == address:
        raise ValueError('A class cache cannot inherit itself')
    if not 0 <= count <= limits.max_fields_per_cache or capacity < count:
        raise ValueError('Invalid or over-budget class-cache field count/capacity')
    if capacity > MAX_FIELDS_PER_CACHE or start + count > limits.max_total_fields:
        raise ValueError('Class-cache interval exceeds local snapshot bound')
    if count and not storage:
        raise ValueError('Nonempty class cache has null field storage')
    if count:
        _range(storage, count * ENTRY_BYTES)
    if len(entry_bytes) != count * ENTRY_BYTES:
        raise ValueError('Class-cache entry data does not match its exact count')
    fields = []
    for ordinal in range(count):
        at = ordinal * ENTRY_BYTES
        descriptor = struct.unpack_from('<Q', entry_bytes, at)[0]
        representation = entry_bytes[at + 8]
        index, checksum = struct.unpack_from('<II', entry_bytes, at + 0x10)
        incompatible = entry_bytes[at + 0x18]
        if representation not in (0, 1) or incompatible not in (0, 1):
            raise ValueError('Unsupported class-cache descriptor representation or flag')
        if index != start + ordinal:
            raise ValueError('Class-cache field index disagrees with native interval order')
        fields.append(CachedField(descriptor, representation, index, checksum,
                                  bool(incompatible), address))
    return ClassCacheSnapshot(address, start, parent, header[0x10:0x18],
        struct.unpack_from('<I', header, 0x18)[0], storage, capacity, tuple(fields))


class ClassCacheGraph:
    """Verified interval structure for one caller-identified leaf and its parents.

    The extra wire value start+count has no matching table entry. Field lookup
    rejects it although bounded integer framing can represent it. This object
    proves snapshot structure only, never actual class identity or serializers.
    """
    def __init__(self, *, leaf_address, snapshots, limits=DEFAULT_LIMITS):
        _limits(limits)
        _address(leaf_address, nonzero=True)
        if not isinstance(snapshots, tuple) or not snapshots or len(snapshots) > limits.max_parent_depth:
            raise ValueError('A bounded nonempty tuple of exact class-cache snapshots is required')
        by_address = {}
        for node in snapshots:
            if not isinstance(node, ClassCacheSnapshot):
                raise ValueError('An exact decoded ClassCacheSnapshot is required')
            # Revalidate constructed dataclass instances; public constructors are
            # not a certificate that these bytes came from the game.
            _validate_node(node, limits)
            if node.address in by_address:
                raise ValueError('Duplicate class-cache address')
            by_address[node.address] = node
        chain, visited, address = [], set(), leaf_address
        while address:
            if address in visited:
                raise ValueError('Class-cache parent cycle')
            if address not in by_address:
                raise ValueError('Class-cache parent snapshot is missing')
            if len(chain) >= limits.max_parent_depth:
                raise ValueError('Class-cache parent depth exceeds local bound')
            visited.add(address)
            node = by_address[address]
            chain.append(node)
            address = node.parent_address
        if len(visited) != len(by_address):
            raise ValueError('Unrelated snapshots are outside this class parent chain')
        ordered = tuple(reversed(chain))
        expected_start = 0
        fields = {}
        for node in ordered:
            if node.index_start != expected_start:
                raise ValueError('Class-cache inherited interval is not contiguous')
            for field in node.fields:
                fields[field.rep_index] = field
            expected_start += len(node.fields)
        if expected_start > limits.max_total_fields or expected_start + 1 > UINT32_MAX:
            raise ValueError('Class-cache exclusive index maximum exceeds supported bound')
        self._nodes = ordered
        self._fields = fields
        self._maximum = expected_start + 1

    @property
    def nodes(self):
        return self._nodes

    @property
    def exclusive_index_maximum(self):
        return self._maximum

    def normal_field_profile(self):
        return NormalClassFieldProfile(self._maximum, False)

    def field_for_index(self, index):
        if type(index) is not int or index not in self._fields:
            raise ValueError('RepIndex has no declared field in this class-cache chain')
        return self._fields[index]

    def require_compatible_descriptor(self, index):
        """Return an existing descriptor; its serializer/body is still unknown."""
        field = self.field_for_index(index)
        if field.incompatible or field.descriptor_address == 0:
            raise ValueError('Field descriptor is null or marked incompatible')
        return field


def _validate_node(node, limits):
    _range(node.address, HEADER_BYTES)
    _address(node.parent_address)
    _address(node.field_storage_address)
    if (type(node.index_start) is not int or not 0 <= node.index_start <= limits.max_total_fields or
            not isinstance(node.fields, tuple) or len(node.fields) > limits.max_fields_per_cache or
            node.index_start + len(node.fields) > limits.max_total_fields):
        raise ValueError('Invalid class-cache snapshot interval')
    if (type(node.field_capacity) is not int or
            not len(node.fields) <= node.field_capacity <= MAX_FIELDS_PER_CACHE or
            node.fields and node.field_storage_address == 0):
        raise ValueError('Invalid class-cache snapshot capacity/storage')
    if node.fields:
        _range(node.field_storage_address, len(node.fields) * ENTRY_BYTES)
    if (not isinstance(node.opaque_object_key, bytes) or len(node.opaque_object_key) != 8 or
            type(node.aggregate_checksum) is not int or not 0 <= node.aggregate_checksum <= UINT32_MAX):
        raise ValueError('Invalid class-cache key/checksum snapshot')
    for ordinal, field in enumerate(node.fields):
        if not isinstance(field, CachedField):
            raise ValueError('Invalid class-cache field record')
        _address(field.descriptor_address)
        if (type(field.descriptor_representation) is not int or field.descriptor_representation not in (0, 1) or
                type(field.rep_index) is not int or field.rep_index != node.index_start + ordinal or
                type(field.checksum) is not int or not 0 <= field.checksum <= UINT32_MAX or
                type(field.incompatible) is not bool or
                type(field.declaring_cache_address) is not int or field.declaring_cache_address != node.address):
            raise ValueError('Class-cache field record disagrees with its declaring interval')
