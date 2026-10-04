"""Restricted false-branch NetGUID export format, with no object resolver.

ReceiveNetGUIDBunch12bc5540 reads a one-bit discriminator, then the false
branch reads an unaligned signed int32 count and invokes GUID_reader with
depth0 while GUIDCache+152 is true. Sources are saved in
work/evidence/native-guid-export-receive-complete.json and
work/evidence/native-post-join-guid-transform-full-roots.json; the combined
verified summary is work/evidence/native-guid-export-envelope.json.

This subset accepts caller-supplied static odd GUIDs>=3 with flags1 or5:
recursive outer reference, FString, and optional raw uint32 checksum.
Only a null outer has GUID0 and no flags. GUID1/default paths, non-path
references, unknown flag bits and the true discriminator are unsupported.
Counts0..2048, total-node/data limits and conflict rejection are stricter
local policies. Native may alter bookkeeping before rejecting bad data;
this module instead rolls back every failed read/write.

Strings/checksums use the recovered non-byte-swapped profile. FString
rules are shared with the control field codec; Chinese is UTF-16LE, not
UTF-8 narrow data. No CRC is calculated and no GUID/path is invented.
Parsing or writing exports does not prove that the client has resolved
them, and this module creates neither registry/world objects nor packets.
"""

from dataclasses import dataclass

from .legacy_ds_bit_archive import BitReader, BitWriter, UINT32_MAX
from .legacy_ds_control_fields import (
    DEFAULT_MAX_STRING_UNITS, decode_string, encode_string,
)


MAX_EXPORTS = 2048
MAX_EXPORT_DEPTH = 16
MAX_EXPORT_NODES = 2048
MAX_EXPORT_BYTES = 8192


class UnsupportedGuidExportProfile(ValueError):
    """The input uses a native export branch outside this recovered subset."""


@dataclass(frozen=True)
class GuidExportNode:
    guid: int
    path: str
    outer: 'GuidExportNode | None' = None
    checksum: int | None = None


@dataclass(frozen=True)
class GuidExportLimits:
    max_exports: int = MAX_EXPORTS
    max_depth: int = MAX_EXPORT_DEPTH
    max_nodes: int = MAX_EXPORT_NODES
    max_bytes: int = MAX_EXPORT_BYTES
    max_path_units: int = DEFAULT_MAX_STRING_UNITS

    def __post_init__(self):
        for name, low, high in (
            ('max_exports', 0, MAX_EXPORTS),
            ('max_depth', 0, MAX_EXPORT_DEPTH),
            ('max_nodes', 0, MAX_EXPORT_NODES),
            ('max_bytes', 1, MAX_EXPORT_BYTES),
            ('max_path_units', 1, DEFAULT_MAX_STRING_UNITS),
        ):
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ValueError('Invalid local GUID-export bound: ' + name)


DEFAULT_LIMITS = GuidExportLimits()


def _limits(value):
    if not isinstance(value, GuidExportLimits):
        raise ValueError('Explicit GUID-export limits are required')
    value.__post_init__()


def _static_guid(value):
    if (type(value) is not int or not 3 <= value <= UINT32_MAX or
            not value & 1):
        raise UnsupportedGuidExportProfile('Only caller-supplied static odd GUIDs>=3 are supported')


def _checksum(value):
    if value is not None and (type(value) is not int or not 0 <= value <= UINT32_MAX):
        raise ValueError('Checksum must be an explicit uint32 or omitted')


class _Definitions:
    """Per-operation validation only; this is not a client GUID dictionary."""

    def __init__(self, limits):
        self.limits = limits
        self.nodes = 0
        self.definitions = {}

    def depth(self, depth):
        # Native12bbb3ee/3fb checks depth BEFORE reading even a null GUID.
        if depth > self.limits.max_depth:
            raise ValueError('GUID-export nesting exceeds the local/native depth bound')

    def node(self):
        # Count occurrences, including repeated recursive definitions.
        self.nodes += 1
        if self.nodes > self.limits.max_nodes:
            raise ValueError('GUID exports exceed the local total-node bound')

    def remember(self, node):
        definition = (node.outer.guid if node.outer is not None else 0,
                      node.path, node.checksum)
        previous = self.definitions.get(node.guid)
        if previous is not None and previous != definition:
            raise ValueError('Conflicting definitions for one exported GUID')
        self.definitions[node.guid] = definition


def write_guid_exports(writer, exports, *, limits=DEFAULT_LIMITS, force_unicode=False):
    """Append a false-branch export prefix atomically; return appended bits.

    exports must be a tuple of GuidExportNode objects. A checksum of None
    emits flags1; an explicit uint32, including zero, emits flags5. Every
    recursive outer is another complete path definition or None (packed0).
    Paths are explicit strings, not checked for actual asset existence.
    Canonical encoder strings reject embedded NULs per encode_string.
    """
    if not isinstance(writer, BitWriter):
        raise ValueError('A native bit writer is required')
    _limits(limits)
    if (not isinstance(exports, tuple) or len(exports) > limits.max_exports or
            type(force_unicode) is not bool):
        raise ValueError('Invalid bounded export tuple or Unicode flag')
    checks = _Definitions(limits)
    staged = BitWriter(maximum_bits=limits.max_bytes * 8)
    staged.write_bool(False)
    # Receive12bc55b6/5624: int32 count, NOT SerializeIntPacked or alignment.
    staged.write_bits(len(exports), 32)

    def node(value, depth):
        checks.depth(depth)
        if value is None:
            # GUID_reader12bbb469/46b returns NULL without reading flags.
            staged.write_packed_int(0)
            return
        if not isinstance(value, GuidExportNode) or not isinstance(value.path, str):
            raise ValueError('An explicit GUID path node is required')
        _static_guid(value.guid)
        _checksum(value.checksum)
        checks.node()
        staged.write_packed_int(value.guid)
        staged.write_bits(1 if value.checksum is None else 5, 8)
        # Native12bbb65a ->recursive outer,672 ->FString,677 ->checksum gate.
        node(value.outer, depth + 1)
        staged.write_bytes(encode_string(value.path, force_unicode=force_unicode,
                                        max_units=limits.max_path_units))
        if value.checksum is not None:
            staged.write_bits(value.checksum, 32)
        checks.remember(value)

    for value in exports:
        if value is None:
            raise UnsupportedGuidExportProfile('Top-level exports must be static path nodes')
        node(value, 0)
    # A single capacity-checked append leaves the caller untouched on failure.
    writer.write_payload(staged.to_bytes(), staged.bit_count)
    return staged.bit_count


def read_guid_exports(reader, *, limits=DEFAULT_LIMITS):
    """Consume one export prefix atomically and return immutable path nodes.

    Subsequent actor fields remain unread. The private reader's exact bit
    count enforces max_bytes relative to the caller's current cursor, not
    relative to the complete input archive. No partial nodes are returned
    and the caller cursor is unchanged for every failed parse.
    """
    if not isinstance(reader, BitReader):
        raise ValueError('A native bit reader is required')
    _limits(limits)
    start = reader.position
    try:
        # Copy only a bounded bit slice; parsing advances the private cursor.
        # Standard primitives then reject each read before crossing this bound.
        bits = min(reader.remaining, limits.max_bytes * 8)
        data = reader.read_payload(bits)
        reader.position = start
        staged = BitReader(data, bit_count=bits)
        if staged.read_bool():
            raise UnsupportedGuidExportProfile('The true NetGUID-export discriminator is unsupported')
        count = int.from_bytes(staged.read_bytes(4), 'little', signed=True)
        if not 0 <= count <= limits.max_exports:
            raise ValueError('GUID-export count is outside the local nonnegative bound')
        checks = _Definitions(limits)

        def node(depth):
            checks.depth(depth)
            guid = staged.read_packed_int()
            if guid == 0:
                return None
            _static_guid(guid)
            checks.node()
            flags = staged.read_bits(8)
            if flags not in (1, 5):
                raise UnsupportedGuidExportProfile('Only path flags1/5 are recovered for this export subset')
            outer = node(depth + 1)
            header = staged.read_bytes(4)
            string_count = int.from_bytes(header, 'little', signed=True)
            if string_count == -(1 << 31) or abs(string_count) > limits.max_path_units:
                raise ValueError('GUID-export FString exceeds the local unit bound')
            payload = staged.read_bytes(abs(string_count) * (2 if string_count < 0 else 1))
            path, _ = decode_string(header + payload, max_units=limits.max_path_units)
            checksum = staged.read_bits(32) if flags == 5 else None
            value = GuidExportNode(guid, path, outer, checksum)
            checks.remember(value)
            return value

        result = []
        for _ in range(count):
            value = node(0)  # Receive12bc5703 explicitly passes depth0.
            if value is None:
                raise UnsupportedGuidExportProfile('Top-level exports must be static path nodes')
            result.append(value)
    except Exception:
        reader.position = start
        raise
    reader.position = start + staged.position
    return tuple(result)

