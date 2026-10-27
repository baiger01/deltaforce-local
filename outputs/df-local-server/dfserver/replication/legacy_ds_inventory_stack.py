"""Explicit optional native stack values over the pinned full-item grammar.

The single item GID is preserved. Other optional item features are unsupported;
callers must qualify them separately before using this bounded value codec.
"""
from dfserver._paths import SERVER_ROOT
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct

from dfserver.transport.native.legacy_ds_bit_archive import BitReader, BitWriter
from dfserver.replication.legacy_ds_inventory_items import MinimalInventoryItem, InventoryWireProfile, InventoryFastArrayDelta, InventoryFastArrayElement, SHIPPING_SHA256, CONTRACT_SHA256, write_minimal_item, read_minimal_item, MAX_NATIVE_ARRAY_COUNT
from dfserver.replication.legacy_ds_inventory_state import InventoryStateProfile, SCHEMA_SHA256, inventory_state_source_pins

STACK_CONTRACT_SHA256 = 'bdb1676c3df6afaf371a7495aa88aedfb957e6d75a41ab938b6eb4a31eae6773'
STACK_CONTRACT_RELATIVE_PATH = 'protocol/portable-map-spawn/inventory-stack-contract.json'
STACK_SELECTOR_OFFSET = 632
MINIMAL_SUFFIX_BITS = 177


@dataclass(frozen=True)
class InventoryStackData:
    item_count: int
    item_num_max: int
    contain_player_ids: tuple[int, ...]
    contain_nums: tuple[int, ...]


@dataclass(frozen=True)
class StackedInventoryItem:
    item: MinimalInventoryItem
    stack: InventoryStackData

    @property
    def item_gid(self):
        return self.item.item_gid

    @property
    def template_id(self):
        return self.item.template_id


def inventory_stack_source_pins(server_root=None):
    root = Path(server_root) if server_root is not None else SERVER_ROOT
    try:
        raw = (root/STACK_CONTRACT_RELATIVE_PATH).read_bytes()
    except OSError as error:
        raise ValueError('Native inventory stack source is unavailable') from error
    if hashlib.sha256(raw).hexdigest() != STACK_CONTRACT_SHA256:
        raise ValueError('Native inventory stack source changed')
    contract = json.loads(raw)
    if (contract.get('kind') != 'source_qualified_native_inventory_optional_stack_contract' or
            contract.get('client_sha256') != SHIPPING_SHA256 or
            contract.get('minimal_contract_sha256') != CONTRACT_SHA256 or
            contract.get('selector_minimal_bit_offset') != STACK_SELECTOR_OFFSET):
        raise ValueError('Unqualified inventory stack source')
    return {STACK_CONTRACT_RELATIVE_PATH: STACK_CONTRACT_SHA256}


def _qualify(archive, profile, archive_type):
    if (type(archive) is not archive_type or type(profile) is not InventoryStateProfile or
            profile.client_sha256 != SHIPPING_SHA256 or profile.schema_sha256 != SCHEMA_SHA256 or
            type(profile.archive_network_version) is not int or profile.archive_network_version != 13 or
            profile.no_byteswap is not True or profile.delta_struct_mode is not False):
        raise ValueError('Pinned version13 normal legacy inventory binding required')
    inventory_stack_source_pins()
    inventory_state_source_pins()
    return InventoryWireProfile(SHIPPING_SHA256, CONTRACT_SHA256, False, True)


def _number(value, bits, *, signed=False):
    low = -(1 << (bits-1)) if signed else 0
    high = (1 << (bits-1))-1 if signed else (1 << bits)-1
    if type(value) is not int or not low <= value <= high:
        raise ValueError('Native inventory stack scalar outside width')


def _stack(value):
    if (type(value) is not InventoryStackData or type(value.item_count) is not int or
            type(value.item_num_max) is not int or not 1 <= value.item_count <= value.item_num_max < 1 << 31 or
            value.item_num_max <= 1):
        raise ValueError('Explicit positive count and maximum greater than one required')
    for values, bits, signed in ((value.contain_player_ids,64,False),(value.contain_nums,32,True)):
        if type(values) is not tuple or len(values) > MAX_NATIVE_ARRAY_COUNT:
            raise ValueError('Native stack array exceeds local bound')
        for item in values:
            _number(item,bits,signed=signed)


def _copy_bits(reader, writer, count):
    while count:
        width = min(count,64)
        writer.write_bits(reader.read_bits(width),width)
        count -= width


def _write_item(writer, value, item_profile):
    if type(value) is MinimalInventoryItem:
        write_minimal_item(writer,value,profile=item_profile)
        return
    if type(value) is not StackedInventoryItem or type(value.item) is not MinimalInventoryItem:
        raise ValueError('Explicit minimal or stacked native inventory item required')
    _stack(value.stack)
    minimal = BitWriter()
    write_minimal_item(minimal,value.item,profile=item_profile)
    source = BitReader(minimal.to_bytes(),bit_count=minimal.bit_count)
    _copy_bits(source,writer,STACK_SELECTOR_OFFSET)
    if source.read_bool():
        raise ValueError('The base native minimal selector changed')
    writer.write_bool(True)
    stack = value.stack
    writer.write_bytes(struct.pack('<3i',stack.item_count,stack.item_num_max,len(stack.contain_player_ids)))
    for item in stack.contain_player_ids:
        writer.write_bytes(struct.pack('<Q',item))
    writer.write_bytes(struct.pack('<i',len(stack.contain_nums)))
    for item in stack.contain_nums:
        writer.write_bytes(struct.pack('<i',item))
    _copy_bits(source,writer,MINIMAL_SUFFIX_BITS)


def _read_item(reader, item_profile):
    minimal = BitWriter()
    _copy_bits(reader,minimal,STACK_SELECTOR_OFFSET)
    present = reader.read_bool()
    minimal.write_bool(False)
    stack = None
    if present:
        count,maximum,num_ids = struct.unpack('<3i',reader.read_bytes(12))
        if not 0 <= num_ids <= MAX_NATIVE_ARRAY_COUNT:
            raise ValueError('Native stack ID count exceeds local bound')
        ids = tuple(struct.unpack('<Q',reader.read_bytes(8))[0] for _ in range(num_ids))
        num_counts, = struct.unpack('<i',reader.read_bytes(4))
        if not 0 <= num_counts <= MAX_NATIVE_ARRAY_COUNT:
            raise ValueError('Native stack number count exceeds local bound')
        nums = tuple(struct.unpack('<i',reader.read_bytes(4))[0] for _ in range(num_counts))
        stack = InventoryStackData(count,maximum,ids,nums)
        _stack(stack)
    _copy_bits(reader,minimal,MINIMAL_SUFFIX_BITS)
    value = read_minimal_item(BitReader(minimal.to_bytes(),bit_count=minimal.bit_count),profile=item_profile)
    return value if stack is None else StackedInventoryItem(value,stack)


def write_inventory_item(writer, item, *, profile):
    item_profile = _qualify(writer,profile,BitWriter)
    stage = BitWriter(maximum_bits=writer.maximum_bits)
    _write_item(stage,item,item_profile)
    writer.write_payload(stage.to_bytes(),stage.bit_count)
    return stage.bit_count


def read_inventory_item(reader, *, profile):
    item_profile = _qualify(reader,profile,BitReader)
    before = reader.position
    try:
        return _read_item(reader,item_profile)
    except ValueError:
        reader.position = before
        raise


def _delta(delta):
    if type(delta) is not InventoryFastArrayDelta:
        raise ValueError('Typed native inventory FastArray required')
    for key in (delta.array_replication_key,delta.base_replication_key):
        _number(key,32,signed=True)
    if (type(delta.deleted_ids) is not tuple or type(delta.changed) is not tuple or
            len(delta.deleted_ids)>MAX_NATIVE_ARRAY_COUNT or len(delta.changed)>MAX_NATIVE_ARRAY_COUNT):
        raise ValueError('Native inventory FastArray count exceeds 2048')
    ids = list(delta.deleted_ids)
    for element in delta.changed:
        if type(element) is not InventoryFastArrayElement:
            raise ValueError('Typed FastArray element required')
        ids.append(element.element_id)
    for identity in ids:
        _number(identity,31)
    if len(ids) != len(set(ids)):
        raise ValueError('Repeated or overlapping FastArray element IDs')


def write_inventory_custom_delta(writer, delta, *, profile):
    """One false version13 prefix, raw FastArray header, exact single/stack items."""
    item_profile = _qualify(writer,profile,BitWriter)
    _delta(delta)
    stage = BitWriter(maximum_bits=writer.maximum_bits)
    stage.write_bool(False)
    stage.write_bytes(struct.pack('<4i',delta.array_replication_key,delta.base_replication_key,
        len(delta.deleted_ids),len(delta.changed)))
    for identity in delta.deleted_ids:
        stage.write_bytes(struct.pack('<i',identity))
    for element in delta.changed:
        stage.write_bytes(struct.pack('<i',element.element_id))
        _write_item(stage,element.item,item_profile)
    writer.write_payload(stage.to_bytes(),stage.bit_count)
    return stage.bit_count


def read_inventory_custom_delta(reader, *, profile):
    item_profile = _qualify(reader,profile,BitReader)
    before = reader.position
    try:
        if reader.read_bool():
            raise ValueError('Unqualified optimized item delta branch')
        key,base,deletes,changes = struct.unpack('<4i',reader.read_bytes(16))
        if not 0 <= deletes <= MAX_NATIVE_ARRAY_COUNT or not 0 <= changes <= MAX_NATIVE_ARRAY_COUNT:
            raise ValueError('Native inventory FastArray count exceeds 2048')
        deleted = tuple(struct.unpack('<i',reader.read_bytes(4))[0] for _ in range(deletes))
        changed = tuple(InventoryFastArrayElement(struct.unpack('<i',reader.read_bytes(4))[0],
            _read_item(reader,item_profile)) for _ in range(changes))
        value = InventoryFastArrayDelta(key,base,deleted,changed)
        _delta(value)
        return value
    except ValueError:
        reader.position = before
        raise
