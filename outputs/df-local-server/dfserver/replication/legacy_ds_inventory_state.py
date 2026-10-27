"""Pinned inventory initialization, space values and legacy custom-delta prefix.

Property selection, container geometry, item features and account policy belong
to qualified callers. This module produces value bits and sends no packets.
"""
from dfserver._paths import SERVER_ROOT
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct

from dfserver.transport.native.legacy_ds_bit_archive import BitReader, BitWriter
from dfserver.replication.legacy_ds_inventory_items import SHIPPING_SHA256, CONTRACT_SHA256, InventoryWireProfile, read_standard_fast_array, write_standard_fast_array

CLIENT_SHA256 = SHIPPING_SHA256
SCHEMA_SHA256 = 'c0ff0436a36ee6e1c0e66c7a69039a4f3375eabe9308353116dcc23a41e63ad7'
SCHEMA_RELATIVE_PATH = 'protocol/portable-map-spawn/inventory-schema.json'
MAX_SPACES = 64  # Local payload bounds; no native allocation-limit claim.
MAX_GRIDS_PER_SPACE = 64


@dataclass(frozen=True)
class InventoryStateProfile:
    client_sha256: str
    schema_sha256: str
    archive_network_version: int
    no_byteswap: bool
    delta_struct_mode: bool


@dataclass(frozen=True)
class InventorySpaceGrid:
    grid_id: int
    start_x: int
    start_y: int
    length: int
    height: int
    logic_half_unit_x: int
    logic_half_unit_y: int


@dataclass(frozen=True)
class InventorySpace:
    space_type: int
    server_update_count: int
    grids: tuple[InventorySpaceGrid, ...]


@dataclass(frozen=True)
class InventoryManagerRepData:
    initialized: bool
    startup_value: int
    startup_equipment_value: int
    current_value: int
    gain_value: int
    currency_value: int
    consume_value: int
    pickup_currency: int
    spaces: tuple[InventorySpace, ...]


def _schema(root=None):
    root = Path(root) if root is not None else SERVER_ROOT
    try:
        raw = (root/SCHEMA_RELATIVE_PATH).read_bytes()
    except OSError as error:
        raise ValueError('Inventory schema source is unavailable') from error
    if hashlib.sha256(raw).hexdigest() != SCHEMA_SHA256:
        raise ValueError('Inventory schema source changed')
    value = json.loads(raw)
    if (value.get('client_sha256') != CLIENT_SHA256 or
            value.get('kind') != 'source_qualified_current_inventory_schema' or
            value['repdata']['empty_spaces_total_bits'] != 480 or
            value['space']['grid_wire_bits'] != 176 or
            value['fast_array']['legacy_prefix_value'] is not False):
        raise ValueError('Unexpected inventory wire contract')
    return value


def inventory_state_source_pins(server_root=None):
    _schema(server_root)
    return {SCHEMA_RELATIVE_PATH: SCHEMA_SHA256}


def _qualify(archive, profile, archive_type):
    if (type(archive) is not archive_type or type(profile) is not InventoryStateProfile or
            type(profile.archive_network_version) is not int or profile.archive_network_version != 13 or
            profile.client_sha256 != CLIENT_SHA256 or profile.schema_sha256 != SCHEMA_SHA256 or
            profile.no_byteswap is not True or profile.delta_struct_mode is not False):
        raise ValueError('The pinned version13 no-byteswap legacy inventory profile is required')
    return _schema()


def _int(value, bits):
    if type(value) is not int or not -(1 << (bits-1)) <= value < 1 << (bits-1):
        raise ValueError('Inventory scalar outside signed native width')
    return value


def _spaces(spaces, schema):
    if type(spaces) is not tuple or len(spaces) > MAX_SPACES:
        raise ValueError('Inventory space count exceeds local bound')
    types = {v['value'] for v in schema['enums'][0]['values']}
    seen = set()
    for space in spaces:
        if (type(space) is not InventorySpace or type(space.space_type) is not int or
                space.space_type not in types or space.space_type in seen):
            raise ValueError('An explicit unique native EAttachPosition space is required')
        seen.add(space.space_type)
        _int(space.server_update_count, 32)
        if type(space.grids) is not tuple or len(space.grids) > MAX_GRIDS_PER_SPACE:
            raise ValueError('Inventory grid count exceeds local bound')
        ids = set()
        for grid in space.grids:
            if type(grid) is not InventorySpaceGrid:
                raise ValueError('Typed inventory grids required')
            for value in (grid.grid_id, grid.start_x, grid.start_y, grid.length, grid.height):
                _int(value, 32)
            for value in (grid.logic_half_unit_x, grid.logic_half_unit_y):
                _int(value, 8)
            if grid.grid_id in ids:
                raise ValueError('Local grid IDs must be unique within one space')
            ids.add(grid.grid_id)


def _write_spaces(writer, spaces):
    writer.write_bytes(struct.pack('<i', len(spaces)))
    for space in spaces:
        writer.write_bytes(struct.pack('<3i', space.space_type, space.server_update_count, len(space.grids)))
        for grid in space.grids:
            writer.write_bytes(struct.pack('<5i2b', grid.grid_id, grid.start_x, grid.start_y,
                grid.length, grid.height, grid.logic_half_unit_x, grid.logic_half_unit_y))


def _read_spaces(reader):
    count, = struct.unpack('<i', reader.read_bytes(4))
    if not 0 <= count <= MAX_SPACES:
        raise ValueError('Inventory space count exceeds local bound')
    spaces = []
    for _ in range(count):
        kind, update, grid_count = struct.unpack('<3i', reader.read_bytes(12))
        if not 0 <= grid_count <= MAX_GRIDS_PER_SPACE:
            raise ValueError('Inventory grid count exceeds local bound')
        grids = tuple(InventorySpaceGrid(*struct.unpack('<5i2b', reader.read_bytes(22))) for _ in range(grid_count))
        spaces.append(InventorySpace(kind, update, grids))
    return tuple(spaces)


def write_inventory_spaces(writer, spaces, *, profile):
    """LootObjRepData/BoxRepData space value grammar; no outer handle."""
    schema = _qualify(writer, profile, BitWriter)
    _spaces(spaces, schema)
    stage = BitWriter(maximum_bits=writer.maximum_bits)
    _write_spaces(stage, spaces)
    writer.write_payload(stage.to_bytes(), stage.bit_count)
    return stage.bit_count


def read_inventory_spaces(reader, *, profile):
    schema = _qualify(reader, profile, BitReader)
    before = reader.position
    try:
        spaces = _read_spaces(reader)
        _spaces(spaces, schema)
        return spaces
    except ValueError:
        reader.position = before
        raise


def write_inventory_repdata(writer, value, *, profile):
    """Serialize FInvMgrRepData at the current cursor, without byte alignment."""
    schema = _qualify(writer, profile, BitWriter)
    if type(value) is not InventoryManagerRepData or type(value.initialized) is not bool:
        raise ValueError('Explicit typed initialization data required')
    amounts = (value.startup_value, value.startup_equipment_value, value.current_value,
        value.gain_value, value.currency_value, value.consume_value)
    for amount in amounts:
        _int(amount, 64)
    _int(value.pickup_currency, 32)
    _spaces(value.spaces, schema)
    stage = BitWriter(maximum_bits=writer.maximum_bits)
    stage.write_bytes(struct.pack('<i6qi', int(value.initialized), *amounts, value.pickup_currency))
    _write_spaces(stage, value.spaces)
    writer.write_payload(stage.to_bytes(), stage.bit_count)
    return stage.bit_count


def read_inventory_repdata(reader, *, profile):
    schema = _qualify(reader, profile, BitReader)
    before = reader.position
    try:
        initialized, *values = struct.unpack('<i6qi', reader.read_bytes(56))
        spaces = _read_spaces(reader)
        _spaces(spaces, schema)
        return InventoryManagerRepData(bool(initialized), *values, spaces)
    except ValueError:
        reader.position = before
        raise


def _item_profile():
    return InventoryWireProfile(CLIENT_SHA256, CONTRACT_SHA256, False, True)


def write_inventory_custom_delta(writer, delta, *, profile):
    """Version13 false bit followed by the standard FastArray payload.

    Caller must qualify an array with no previously negotiated optimized state.
    ClassNetCache field framing is outside this function.
    """
    _qualify(writer, profile, BitWriter)
    stage = BitWriter(maximum_bits=writer.maximum_bits)
    stage.write_bool(False)
    write_standard_fast_array(stage, delta, profile=_item_profile())
    writer.write_payload(stage.to_bytes(), stage.bit_count)
    return stage.bit_count


def read_inventory_custom_delta(reader, *, profile):
    _qualify(reader, profile, BitReader)
    before = reader.position
    try:
        if reader.read_bool():
            raise ValueError('Optimized item delta struct branch is outside this codec')
        return read_standard_fast_array(reader, profile=_item_profile())
    except ValueError:
        reader.position = before
        raise
