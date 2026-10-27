"""Pinned native optional keychain spaces, preserving ordinary/stack item bits."""
from dfserver._paths import SERVER_ROOT
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct

from dfserver.transport.native.legacy_ds_bit_archive import BitReader, BitWriter
from dfserver.replication.legacy_ds_inventory_items import MinimalInventoryItem, InventoryFastArrayDelta, InventoryFastArrayElement, SHIPPING_SHA256, MAX_NATIVE_ARRAY_COUNT
from dfserver.replication import legacy_ds_inventory_stack as stack_codec

CONTRACT_PATH='protocol/portable-map-spawn/inventory-keychain-contract.json'
CONTRACT_SHA256='92dfcab25d5b1323ae686191280ae044c8eb8270d3a15f3d134a961d8005b44e'
SELECTOR_OFFSET=637
SUFFIX_BITS=172


@dataclass(frozen=True)
class InventoryKeychainSpace:
    index: int
    length: int
    base_count: int
    total_locked: tuple[int,...]
    unlocked: tuple[int,...]


@dataclass(frozen=True)
class KeychainInventoryItem:
    item: MinimalInventoryItem
    spaces: tuple[InventoryKeychainSpace,...]

    @property
    def item_gid(self):
        return self.item.item_gid

    @property
    def template_id(self):
        return self.item.template_id


def inventory_keychain_source_pins(server_root=None):
    root=Path(server_root) if server_root is not None else SERVER_ROOT
    try:
        raw=(root/CONTRACT_PATH).read_bytes()
    except OSError as error:
        raise ValueError('Native keychain contract unavailable') from error
    if hashlib.sha256(raw).hexdigest()!=CONTRACT_SHA256:
        raise ValueError('Native keychain source changed')
    value=json.loads(raw)
    if (value.get('kind')!='source_qualified_native_inventory_keychain_contract' or
            value.get('client_sha256')!=SHIPPING_SHA256 or value.get('selector_minimal_bit_offset')!=SELECTOR_OFFSET):
        raise ValueError('Unqualified native keychain contract')
    return {CONTRACT_PATH:CONTRACT_SHA256}


def _spaces(values):
    if type(values) is not tuple or len(values)>64:
        raise ValueError('Bounded native keychain spaces required')
    seen=set()
    for value in values:
        if type(value) is not InventoryKeychainSpace:
            raise ValueError('Typed keychain space required')
        for byte in (value.index,value.length,value.base_count):
            stack_codec._number(byte,8)
        if value.index in seen:
            raise ValueError('Repeated native keychain space index')
        seen.add(value.index)
        for array in (value.total_locked,value.unlocked):
            if type(array) is not tuple or len(array)>MAX_NATIVE_ARRAY_COUNT:
                raise ValueError('Native keychain byte array exceeds local bound')
            for byte in array:
                stack_codec._number(byte,8)


def _write(writer,value,profile):
    if type(value) is not KeychainInventoryItem:
        stack_codec.write_inventory_item(writer,value,profile=profile)
        return
    if type(value.item) is not MinimalInventoryItem:
        raise ValueError('Only the source-qualified single keychain item is supported')
    _spaces(value.spaces)
    minimal=BitWriter()
    stack_codec.write_inventory_item(minimal,value.item,profile=profile)
    source=BitReader(minimal.to_bytes(),bit_count=minimal.bit_count)
    stack_codec._copy_bits(source,writer,SELECTOR_OFFSET)
    if source.read_bool():
        raise ValueError('Changed native keychain selector')
    writer.write_bool(True)
    writer.write_bytes(struct.pack('<i',len(value.spaces)))
    for space in value.spaces:
        writer.write_bytes(bytes((space.index,space.length,space.base_count)))
        for array in (space.total_locked,space.unlocked):
            writer.write_bytes(struct.pack('<i',len(array)))
            writer.write_bytes(bytes(array))
    stack_codec._copy_bits(source,writer,SUFFIX_BITS)


def _read(reader,profile):
    start=reader.position
    # Stack changes the following selector offsets. Stack-bearing items use the
    # already qualified stack codec; the actual keychain template has max one.
    reader.read_bits(632)
    has_stack=reader.read_bool()
    if has_stack:
        reader.position=start
        return stack_codec.read_inventory_item(reader,profile=profile)
    reader.read_bits(4)
    present=reader.read_bool()
    reader.position=start
    if not present:
        return stack_codec.read_inventory_item(reader,profile=profile)
    minimal=BitWriter()
    stack_codec._copy_bits(reader,minimal,SELECTOR_OFFSET)
    reader.read_bool()
    minimal.write_bool(False)
    count,=struct.unpack('<i',reader.read_bytes(4))
    if not 0<=count<=64:
        raise ValueError('Native keychain space count exceeds local bound')
    spaces=[]
    for _ in range(count):
        index,length,base=reader.read_bytes(3)
        arrays=[]
        for _ in range(2):
            size,=struct.unpack('<i',reader.read_bytes(4))
            if not 0<=size<=MAX_NATIVE_ARRAY_COUNT:
                raise ValueError('Native keychain byte count exceeds local bound')
            arrays.append(tuple(reader.read_bytes(size)))
        spaces.append(InventoryKeychainSpace(index,length,base,*arrays))
    _spaces(tuple(spaces))
    stack_codec._copy_bits(reader,minimal,SUFFIX_BITS)
    item=stack_codec.read_inventory_item(BitReader(minimal.to_bytes(),bit_count=minimal.bit_count),profile=profile)
    return KeychainInventoryItem(item,tuple(spaces))


def write_inventory_item(writer,item,*,profile):
    stack_codec._qualify(writer,profile,BitWriter)
    inventory_keychain_source_pins()
    stage=BitWriter(maximum_bits=writer.maximum_bits)
    _write(stage,item,profile)
    writer.write_payload(stage.to_bytes(),stage.bit_count)
    return stage.bit_count


def read_inventory_item(reader,*,profile):
    stack_codec._qualify(reader,profile,BitReader)
    inventory_keychain_source_pins()
    start=reader.position
    try:
        return _read(reader,profile)
    except ValueError:
        reader.position=start
        raise


def write_inventory_custom_delta(writer,delta,*,profile):
    stack_codec._qualify(writer,profile,BitWriter)
    inventory_keychain_source_pins()
    stack_codec._delta(delta)
    stage=BitWriter(maximum_bits=writer.maximum_bits)
    stage.write_bool(False)
    stage.write_bytes(struct.pack('<4i',delta.array_replication_key,delta.base_replication_key,len(delta.deleted_ids),len(delta.changed)))
    for identity in delta.deleted_ids:
        stage.write_bytes(struct.pack('<i',identity))
    for element in delta.changed:
        stage.write_bytes(struct.pack('<i',element.element_id))
        _write(stage,element.item,profile)
    writer.write_payload(stage.to_bytes(),stage.bit_count)
    return stage.bit_count


def read_inventory_custom_delta(reader,*,profile):
    stack_codec._qualify(reader,profile,BitReader)
    inventory_keychain_source_pins()
    start=reader.position
    try:
        if reader.read_bool():
            raise ValueError('Unqualified optimized inventory delta')
        key,base,deletes,changes=struct.unpack('<4i',reader.read_bytes(16))
        if not 0<=deletes<=MAX_NATIVE_ARRAY_COUNT or not 0<=changes<=MAX_NATIVE_ARRAY_COUNT:
            raise ValueError('Native item count exceeds local bound')
        deleted=tuple(struct.unpack('<i',reader.read_bytes(4))[0] for _ in range(deletes))
        changed=tuple(InventoryFastArrayElement(struct.unpack('<i',reader.read_bytes(4))[0],_read(reader,profile)) for _ in range(changes))
        value=InventoryFastArrayDelta(key,base,deleted,changed)
        stack_codec._delta(value)
        return value
    except ValueError:
        reader.position=start
        raise
