"""Explicit native durability/armor float blocks; no account-state defaults."""
from dfserver._paths import SERVER_ROOT
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import struct

from dfserver.transport.native.legacy_ds_bit_archive import BitReader, BitWriter
from dfserver.replication.legacy_ds_inventory_items import InventoryFastArrayDelta, InventoryFastArrayElement, SHIPPING_SHA256, MAX_NATIVE_ARRAY_COUNT
from dfserver.replication import legacy_ds_inventory_stack as stack_codec
from dfserver.replication import legacy_ds_inventory_keychain as base_codec

CONTRACT_PATH='protocol/portable-map-spawn/inventory-condition-contract.json'
CONTRACT_SHA256='d716ec5d9c1aa296f7751d3bc5df6657612d92b04dfbdc2eb91ce2c66a8a7e44'


@dataclass(frozen=True)
class ConditionInventoryItem:
    item: object
    durability: tuple[float,float] | None
    armor_health: tuple[float,float] | None

    @property
    def item_gid(self):
        return self.item.item_gid

    @property
    def template_id(self):
        return self.item.template_id


def inventory_condition_source_pins(server_root=None):
    root=Path(server_root) if server_root is not None else SERVER_ROOT
    try:
        raw=(root/CONTRACT_PATH).read_bytes()
    except OSError as error:
        raise ValueError('Native condition contract unavailable') from error
    if hashlib.sha256(raw).hexdigest()!=CONTRACT_SHA256:
        raise ValueError('Native condition source changed')
    value=json.loads(raw)
    if (value.get('kind')!='native_inventory_explicit_condition_blocks_contract' or value.get('client_sha256')!=SHIPPING_SHA256 or
            value['durability']['minimal_selector_bit_offset']!=633 or value['armor_health']['minimal_selector_bit_offset']!=634):
        raise ValueError('Unqualified native condition source')
    return {CONTRACT_PATH:CONTRACT_SHA256}


def _pair(value):
    if value is None:
        return
    if (type(value) is not tuple or len(value)!=2 or any(type(v) not in (float,int) or not math.isfinite(v) for v in value)
            or not 0<=value[0]<=value[1] or not value[1]>0):
        raise ValueError('Explicit finite current/positive maximum condition required')
    try:
        floats=struct.unpack('<2f',struct.pack('<2f',*value))
    except (OverflowError,struct.error) as error:
        raise ValueError('Condition exceeds native float32') from error
    if not all(math.isfinite(v) for v in floats):
        raise ValueError('Condition exceeds finite native float32')


def _prefix_end(reader):
    reader.read_bits(632)
    if reader.read_bool():
        reader.read_bytes(8)
        for size in (8,4):
            count,=struct.unpack('<i',reader.read_bytes(4))
            if not 0<=count<=MAX_NATIVE_ARRAY_COUNT:
                raise ValueError('Native stack condition-prefix array exceeds bound')
            reader.read_bytes(count*size)
    return reader.position


def _write(writer,value,profile):
    if type(value) is not ConditionInventoryItem:
        base_codec.write_inventory_item(writer,value,profile=profile)
        return
    for pair in (value.durability,value.armor_health):
        _pair(pair)
    stage=BitWriter()
    base_codec.write_inventory_item(stage,value.item,profile=profile)
    source=BitReader(stage.to_bytes(),bit_count=stage.bit_count)
    prefix=_prefix_end(source)
    source.position=0
    stack_codec._copy_bits(source,writer,prefix)
    for pair in (value.durability,value.armor_health):
        if source.read_bool():
            raise ValueError('Base item already contains an unqualified condition block')
        writer.write_bool(pair is not None)
        if pair is not None:
            writer.write_bytes(struct.pack('<2f',*pair))
    stack_codec._copy_bits(source,writer,source.remaining)


def _read(reader,profile):
    start=reader.position
    prefix=_prefix_end(reader)-start
    reader.position=start
    minimal=BitWriter()
    stack_codec._copy_bits(reader,minimal,prefix)
    pairs=[]
    removed=0
    for _ in range(2):
        present=reader.read_bool()
        pair=struct.unpack('<2f',reader.read_bytes(8)) if present else None
        _pair(pair)
        pairs.append(pair)
        removed+=64 if present else 0
        minimal.write_bool(False)
    # Preserve the rest of the bounded slice. The base reader consumes exactly
    # one item, including its variable keychain block; following items stay unread.
    stack_codec._copy_bits(reader,minimal,reader.remaining)
    source=BitReader(minimal.to_bytes(),bit_count=minimal.bit_count)
    value=base_codec.read_inventory_item(source,profile=profile)
    reader.position=start+source.position+removed
    return ConditionInventoryItem(value,*pairs) if any(p is not None for p in pairs) else value


def write_inventory_item(writer,item,*,profile):
    stack_codec._qualify(writer,profile,BitWriter)
    inventory_condition_source_pins()
    stage=BitWriter(maximum_bits=writer.maximum_bits)
    _write(stage,item,profile)
    writer.write_payload(stage.to_bytes(),stage.bit_count)
    return stage.bit_count


def read_inventory_item(reader,*,profile):
    stack_codec._qualify(reader,profile,BitReader)
    inventory_condition_source_pins()
    start=reader.position
    try:
        return _read(reader,profile)
    except ValueError:
        reader.position=start
        raise


def write_inventory_custom_delta(writer,delta,*,profile):
    stack_codec._qualify(writer,profile,BitWriter)
    inventory_condition_source_pins()
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
    inventory_condition_source_pins()
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
