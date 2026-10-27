"""Bounded standard FastArray/full-item receive grammar for the pinned client.

Only a single-count item with empty arrays and absent optional blocks is
supported. This codec does not choose item layouts, classify item features,
resolve objects, choose RepLayout handles, or establish the active delta mode.
The caller must qualify those facts separately before using these value bits.
"""
from dfserver._paths import SERVER_ROOT
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import struct

from dfserver.transport.native.legacy_ds_bit_archive import BitReader, BitWriter

SHIPPING_SHA256 = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
CONTRACT_SHA256 = 'f7c1dbc2fc359d2340125a2601babaec28d2e0d4bb9c3b75db84e8b55afa378d'
CONTRACT_RELATIVE_PATH = 'protocol/portable-map-spawn/inventory-item-wire-contract.json'
MINIMAL_ITEM_BITS = 810
MAX_NATIVE_ARRAY_COUNT = 2048


@dataclass(frozen=True)
class InventoryWireProfile:
    client_sha256: str
    source_sha256: str
    delta_struct_mode: bool
    no_byteswap: bool


@dataclass(frozen=True)
class InventoryItemLocation:
    """Raw location bytes supplied by a separately qualified inventory layout."""
    x: int
    y: int
    length: int
    height: int
    rotated: bool
    grid_index: int


@dataclass(frozen=True)
class MinimalInventoryItem:
    category: int
    sequence: int
    item_gid: int
    attach_position: int
    location: InventoryItemLocation
    modified_timestamp: float
    last_update_reason: int
    temp_last_search_uin: int
    is_raw_bound: bool
    bind_player_id: int
    item_state: int
    using_player_uin: int
    cooldown_start_time: float
    is_in_container: bool
    owner_player_id: int
    fallout_type: int
    is_wanted_item: bool
    item_count: int = 1
    item_num_max: int = 1

    @property
    def template_id(self):
        return self.category * 10000 + self.sequence


@dataclass(frozen=True)
class InventoryFastArrayElement:
    element_id: int
    item: MinimalInventoryItem


@dataclass(frozen=True)
class InventoryFastArrayDelta:
    array_replication_key: int
    base_replication_key: int
    deleted_ids: tuple[int, ...]
    changed: tuple[InventoryFastArrayElement, ...]


def _load_contract(server_root=None):
    root = Path(server_root) if server_root is not None else SERVER_ROOT
    try:
        raw = (root/CONTRACT_RELATIVE_PATH).read_bytes()
    except OSError as error:
        raise ValueError('The inventory wire source contract is unavailable') from error
    if hashlib.sha256(raw).hexdigest() != CONTRACT_SHA256:
        raise ValueError('The inventory wire source contract changed')
    contract = json.loads(raw)
    if (contract.get('kind') != 'bounded_native_inventory_full_item_receive_wire_contract' or
            contract.get('minimal_full_item_receive_bits') != MINIMAL_ITEM_BITS or
            len(contract.get('minimal_full_item_receive_operations', ())) != 43):
        raise ValueError('The inventory wire source contract is outside the qualified subset')
    return contract


def inventory_source_pins(server_root=None):
    """Verify the shipped source contract and expose it to runtime source pins."""
    _load_contract(server_root)
    return {CONTRACT_RELATIVE_PATH: CONTRACT_SHA256}


def _qualify(archive, profile, archive_type):
    if not isinstance(archive, archive_type) or not isinstance(profile, InventoryWireProfile):
        raise ValueError('A native bit archive and explicit inventory profile are required')
    if (type(profile.client_sha256) is not str or type(profile.source_sha256) is not str or
            profile.client_sha256 != SHIPPING_SHA256 or profile.source_sha256 != CONTRACT_SHA256 or
            profile.delta_struct_mode is not False or profile.no_byteswap is not True):
        raise ValueError('The pinned standard full-item no-byteswap profile is required')
    return _load_contract()


def _integer(value, bits, label, *, signed=False):
    low, high = (-(1 << (bits-1)), (1 << (bits-1))-1) if signed else (0, (1 << bits)-1)
    if type(value) is not int or not low <= value <= high:
        raise ValueError('Invalid '+label)
    return value


_FLOAT_FIELDS = frozenset(('ModifyTimeStamp', 'CoolDownStartTime'))
_BOOL_FIELDS = frozenset(('ItemSpaceLocation.bRotated', 'bIsRawBinded', 'IsInContainer', 'bIsWantedItem'))


def _values(item):
    if not isinstance(item, MinimalInventoryItem) or not isinstance(item.location, InventoryItemLocation):
        raise ValueError('A typed minimal inventory item and explicit location are required')
    if (type(item.item_count) is not int or type(item.item_num_max) is not int or
            item.item_count != 1 or item.item_num_max != 1):
        raise ValueError('Absent optional stack data qualifies only native count/max defaults of one')
    loc = item.location
    return {'ItemId.Category': item.category, 'ItemId.Sequence': item.sequence, 'ItemGid': item.item_gid,
        'AttachPosition': item.attach_position, 'ItemSpaceLocation.X': loc.x, 'ItemSpaceLocation.Y': loc.y,
        'ItemSpaceLocation.Length': loc.length, 'ItemSpaceLocation.Height': loc.height,
        'ItemSpaceLocation.bRotated': loc.rotated, 'ItemSpaceLocation.GridIndex': loc.grid_index,
        'ModifyTimeStamp': item.modified_timestamp, 'LastUpdateReason': item.last_update_reason,
        'TempLastSearchUin': item.temp_last_search_uin, 'bIsRawBinded': item.is_raw_bound,
        'BindPlayerId': item.bind_player_id, 'ItemState': item.item_state, 'UsingPlayerUin': item.using_player_uin,
        'CoolDownStartTime': item.cooldown_start_time, 'IsInContainer': item.is_in_container,
        'OwnerPlayerId': item.owner_player_id, 'FalloutType': item.fallout_type, 'bIsWantedItem': item.is_wanted_item}


def _write_item(writer, item, contract):
    values = _values(item)
    before = writer.bit_count
    for operation in contract['minimal_full_item_receive_operations']:
        name, bits = operation['name'], operation['bits']
        if 'minimal_branch_value' in operation:
            writer.write_bits(0, bits)
        elif name in _FLOAT_FIELDS:
            value = values[name]
            if type(value) not in (int, float) or not math.isfinite(value):
                raise ValueError('A finite '+name+' is required')
            try:
                encoded = struct.pack('<f', value)
            except (OverflowError, struct.error) as error:
                raise ValueError('A float32 '+name+' is required') from error
            if not math.isfinite(struct.unpack('<f', encoded)[0]):
                raise ValueError('A finite float32 '+name+' is required')
            writer.write_bytes(encoded)
        elif name in _BOOL_FIELDS:
            if type(values[name]) is not bool:
                raise ValueError('A boolean '+name+' is required')
            writer.write_bits(int(values[name]), bits)
        else:
            value = _integer(values[name], bits, name, signed=name == 'FalloutType')
            writer.write_bits(value & ((1 << bits)-1), bits)
    if writer.bit_count-before != MINIMAL_ITEM_BITS:
        raise ValueError('The native minimal inventory width changed')


def _read_item(reader, contract):
    values = {}
    for operation in contract['minimal_full_item_receive_operations']:
        name, bits = operation['name'], operation['bits']
        value = reader.read_bits(bits)
        if 'minimal_branch_value' in operation:
            if value:
                raise ValueError('Nonempty arrays or optional item blocks exceed the qualified subset: '+name)
        elif name in _FLOAT_FIELDS:
            value = struct.unpack('<f', value.to_bytes(4, 'little'))[0]
            if not math.isfinite(value):
                raise ValueError('Nonfinite native inventory scalar')
            values[name] = value
        elif name in _BOOL_FIELDS:
            values[name] = bool(value)
        else:
            values[name] = value-(1 << bits) if name == 'FalloutType' and value & (1 << (bits-1)) else value
    v = values
    return MinimalInventoryItem(v['ItemId.Category'], v['ItemId.Sequence'], v['ItemGid'], v['AttachPosition'],
        InventoryItemLocation(*(v['ItemSpaceLocation.'+name] for name in ('X','Y','Length','Height','bRotated','GridIndex'))),
        v['ModifyTimeStamp'], v['LastUpdateReason'], v['TempLastSearchUin'], v['bIsRawBinded'],
        v['BindPlayerId'], v['ItemState'], v['UsingPlayerUin'], v['CoolDownStartTime'], v['IsInContainer'],
        v['OwnerPlayerId'], v['FalloutType'], v['bIsWantedItem'])


def write_minimal_item(writer, item, *, profile):
    """Append 810 value bits atomically, without adding an outer property handle."""
    contract = _qualify(writer, profile, BitWriter)
    staged = BitWriter(maximum_bits=MINIMAL_ITEM_BITS)
    _write_item(staged, item, contract)
    writer.write_payload(staged.to_bytes(), staged.bit_count)
    return staged.bit_count


def read_minimal_item(reader, *, profile):
    contract = _qualify(reader, profile, BitReader)
    before = reader.position
    try:
        return _read_item(reader, contract)
    except ValueError:
        reader.position = before
        raise


def _validate_delta(delta):
    if not isinstance(delta, InventoryFastArrayDelta):
        raise ValueError('A typed standard inventory FastArray delta is required')
    _integer(delta.array_replication_key, 32, 'array replication key', signed=True)
    _integer(delta.base_replication_key, 32, 'base replication key', signed=True)
    if (type(delta.deleted_ids) is not tuple or type(delta.changed) is not tuple or
            len(delta.deleted_ids) > MAX_NATIVE_ARRAY_COUNT or len(delta.changed) > MAX_NATIVE_ARRAY_COUNT):
        raise ValueError('Native FastArray counts must be bounded by 2048')
    for element_id in delta.deleted_ids:
        _integer(element_id, 31, 'deleted FastArray element ID')
    for element in delta.changed:
        if not isinstance(element, InventoryFastArrayElement):
            raise ValueError('A typed changed FastArray element is required')
        _integer(element.element_id, 31, 'changed FastArray element ID')
    changed_ids = tuple(element.element_id for element in delta.changed)
    if (len(set(delta.deleted_ids)) != len(delta.deleted_ids) or len(set(changed_ids)) != len(changed_ids) or
            set(delta.deleted_ids).intersection(changed_ids)):
        raise ValueError('FastArray element IDs must be unique and not both deleted and changed')


def write_standard_fast_array(writer, delta, *, profile):
    """Append the standard full-element branch, never a delta-struct branch."""
    contract = _qualify(writer, profile, BitWriter)
    _validate_delta(delta)
    staged = BitWriter()
    staged.write_bytes(struct.pack('<4i', delta.array_replication_key, delta.base_replication_key,
                                    len(delta.deleted_ids), len(delta.changed)))
    for element_id in delta.deleted_ids:
        staged.write_bytes(struct.pack('<i', element_id))
    for element in delta.changed:
        staged.write_bytes(struct.pack('<i', element.element_id))
        _write_item(staged, element.item, contract)
    writer.write_payload(staged.to_bytes(), staged.bit_count)
    return staged.bit_count


def read_standard_fast_array(reader, *, profile):
    contract = _qualify(reader, profile, BitReader)
    before = reader.position
    try:
        key, base, deletes, changes = struct.unpack('<4i', reader.read_bytes(16))
        if not 0 <= deletes <= MAX_NATIVE_ARRAY_COUNT or not 0 <= changes <= MAX_NATIVE_ARRAY_COUNT:
            raise ValueError('Native FastArray counts exceed the qualified bound')
        deleted_ids = tuple(struct.unpack('<i', reader.read_bytes(4))[0] for _ in range(deletes))
        changed = tuple(InventoryFastArrayElement(struct.unpack('<i', reader.read_bytes(4))[0],
                            _read_item(reader, contract)) for _ in range(changes))
        result = InventoryFastArrayDelta(key, base, deleted_ids, changed)
        _validate_delta(result)
        return result
    except ValueError:
        reader.position = before
        raise
