"""Pinned legacy Weapon FastArray framing, with delegated struct bodies.

This draft deliberately supplies no component field index or WeaponPair value
serializer. Each item body must come from a separately qualified native struct
codec. Raw bit slices carry no length in this native format. No packets are sent.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct

from dfserver.legacy_ds_bit_archive import BitReader, BitWriter

CLIENT_SHA256 = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
ROOT = Path(__file__).resolve().parent.parent
BASE = 'work/evidence/map-system-audit-20261018/'
SOURCE_PINS = {
    'native-owning-weapon-custom-delta-receive.json':
        '2c8d26a210b435f0295075cb09ca698587caff6ab4cc80061a6a0d58ce4b1cd8',
    'native-owning-weapon-fastarray-serializer-core.json':
        'cdf461af48a80dbd0af48868406826d2eec0b8dfa31e3551388e69a0f9b446fc',
    'native-owning-weapon-fastarray-header-and-baseclass.json':
        '6c494f4d5b9c2328bc6a0e05f5fae449f0e7d5f691b1420b7fa5e42323dbc9b0',
}
MAX_ENTRIES = 2048  # Native header checks at 1d1dbf1 and 1d1dc85.


@dataclass(frozen=True)
class LegacyWeaponArrayBinding:
    client_sha256: str
    receive_property_rva: int
    array_serializer_rva: int
    header_reader_rva: int
    archive_network_version: int
    no_byteswap: bool
    delta_struct_serialization: bool


QUALIFIED_BINDING = LegacyWeaponArrayBinding(CLIENT_SHA256, 0x12DB8CB0,
    0x2296B70, 0x1D1DAB0, 13, True, False)


def source_binding():
    """Validate local offline reports, without touching the installed game."""
    instructions = {}
    for name, digest in SOURCE_PINS.items():
        raw = (ROOT/BASE/name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('Changed native weapon FastArray source')
        document = json.loads(raw)
        if document['client_sha256'] != CLIENT_SHA256:
            raise ValueError('Changed native weapon client build')
        instructions.update({i['rva']: i for f in document['functions'] for i in f['instructions']})
    for rva, opcode in {
        '0x12db8d3f': '44887e4e', '0x22978c7': '41807f4e00',
        '0x2297dd0': 'e8db5ca8ff', '0x1d1dbf1': '81fa00080000',
        '0x1d1dc85': '81f900080000', '0x2297e52': '41b804000000',
        '0x2297cc5': 'ff5010', '0x2298173': 'ff5010',
    }.items():
        if instructions.get(rva, {}).get('bytes') != opcode:
            raise ValueError('Changed native weapon instruction oracle')
    return QUALIFIED_BINDING


def _binding(binding):
    if type(binding) is not LegacyWeaponArrayBinding or binding != QUALIFIED_BINDING:
        raise ValueError('The exact normal version13 legacy Weapon FastArray binding is required')


@dataclass(frozen=True)
class RawWeaponPairBits:
    payload: bytes
    bit_count: int


@dataclass(frozen=True)
class WeaponFastArrayDelta:
    array_replication_key: int
    base_replication_key: int
    deleted_ids: tuple
    changed_items: tuple


def _pair(value):
    if (type(value) is not RawWeaponPairBits or type(value.payload) is not bytes or
            type(value.bit_count) is not int or not 1 <= value.bit_count <= 32768 or
            len(value.payload) != (value.bit_count+7)//8 or
            int.from_bytes(value.payload, 'little') >> value.bit_count):
        raise ValueError('An exact bounded, zero-padded native WeaponPair bit slice is required')
    return value


def _id(value):
    # Nonnegative replication IDs are this writer's local allocation policy.
    if type(value) is not int or not 0 <= value < 1 << 31:
        raise ValueError('A nonnegative int32 FastArray replication ID is required')


def _delta(delta):
    if (type(delta) is not WeaponFastArrayDelta or
            any(type(v) is not int or not -(1 << 31) <= v < 1 << 31
                for v in (delta.array_replication_key, delta.base_replication_key)) or
            type(delta.deleted_ids) is not tuple or type(delta.changed_items) is not tuple or
            len(delta.deleted_ids) > MAX_ENTRIES or len(delta.changed_items) > MAX_ENTRIES):
        raise ValueError('A bounded native FastArray delta header is required')
    seen = set()
    for value in delta.deleted_ids:
        _id(value)
        if value in seen:
            raise ValueError('Duplicate FastArray replication ID')
        seen.add(value)
    for item in delta.changed_items:
        if type(item) is not tuple or len(item) != 2:
            raise ValueError('A replication ID and native WeaponPair bit slice are required')
        value, payload = item
        _id(value)
        _pair(payload)
        if value in seen:
            raise ValueError('Changed/deleted FastArray replication IDs overlap')
        seen.add(value)


def write_legacy_weapon_array_payload(writer, delta, *, binding):
    """Append boolFalse, four raw int32s, deleted IDs, ID/body changes atomically.

    The bool is the version>=11 ReceiveCustomDeltaProperty prefix. Selecting it
    false chooses the source-supported whole-struct mode on the first receive.
    The caller must not switch an already initialized optimized array to legacy.
    ClassNetCache field framing is intentionally outside this payload codec.
    """
    _binding(binding)
    _delta(delta)
    if type(writer) is not BitWriter:
        raise ValueError('A native bit writer is required')
    staged = BitWriter(maximum_bits=writer.maximum_bits)
    staged.write_bool(False)
    staged.write_bytes(struct.pack('<iiii', delta.array_replication_key,
        delta.base_replication_key, len(delta.deleted_ids), len(delta.changed_items)))
    for value in delta.deleted_ids:
        staged.write_bytes(struct.pack('<i', value))
    for value, payload in delta.changed_items:
        staged.write_bytes(struct.pack('<i', value))
        staged.write_payload(payload.payload, payload.bit_count)
    writer.write_payload(staged.to_bytes(), staged.bit_count)
    return staged.bit_count


def read_legacy_weapon_array_payload(reader, *, read_pair, binding):
    """Delegate native item boundaries to a separately qualified struct reader."""
    _binding(binding)
    if type(reader) is not BitReader:
        raise ValueError('A native bit reader is required')
    if reader.read_bool():
        raise ValueError('DeltaStruct serialization is outside this legacy codec')
    key, base, deletes, changes = struct.unpack('<iiii', reader.read_bytes(16))
    if not 0 <= deletes <= MAX_ENTRIES or not 0 <= changes <= MAX_ENTRIES:
        raise ValueError('Native FastArray count bound exceeded')
    deleted = tuple(struct.unpack('<i', reader.read_bytes(4))[0] for _ in range(deletes))
    if changes and not callable(read_pair):
        raise ValueError('A qualified WeaponPair struct reader is required')
    items = []
    for _ in range(changes):
        identity, = struct.unpack('<i', reader.read_bytes(4))
        before = reader.position
        value = _pair(read_pair(reader))
        if reader.position-before != value.bit_count:
            raise ValueError('WeaponPair reader consumed a different bit count')
        items.append((identity, value))
    result = WeaponFastArrayDelta(key, base, deleted, tuple(items))
    _delta(result)
    return result
