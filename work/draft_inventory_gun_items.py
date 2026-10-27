"""Draft GunDesc optional block over frozen native inventory codecs.

This module is intentionally outside the service. It preserves the enclosing
stack/condition/keychain payload and selects generic network-v13 legacy delta.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct
import sys

import draft_inventory_gun_desc as desc_codec

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT/'outputs/df-local-server'
SPLICE_CONTRACT = 'work/evidence/map-system-audit-20261018/native-economy-gun-desc-inventory-splice-contract-draft.json'
SPLICE_SHA = '554df32a233979c95b82ee3f8c34744e90150a75d70df42a6f7e329fe9e76e48'
if str(SERVER) not in sys.path:
    sys.path.insert(0, str(SERVER))

from dfserver.legacy_ds_bit_archive import BitReader, BitWriter
from dfserver.legacy_ds_inventory_items import InventoryFastArrayDelta, InventoryFastArrayElement, MAX_NATIVE_ARRAY_COUNT
from dfserver import legacy_ds_inventory_stack as stack_codec
from dfserver import legacy_ds_inventory_condition as condition_codec

FROZEN_MODULES = {
    'dfserver/legacy_ds_inventory_condition.py': '9c4ec64ce8cd92756004d54ba4e0b1caeeb7cfaef7dbebbdb5b212d2c2414bf1',
    'dfserver/legacy_ds_inventory_stack.py': '6ac206926fbed1f0eb9dcf8d65e64eeebe946e97bd9dfa9ead3c65ceeaa0fb8c',
    'dfserver/legacy_ds_inventory_keychain.py': 'da80f0674ef6830a9ca5f5d4aa7bd57493ce24953bbbf756a6dcd0d5aa4920bc',
    'dfserver/legacy_ds_inventory_items.py': '1a3e7de23f0842d436f9410ec84ab1ca405dbf875aca59987c38c3426bee4429',
}


@dataclass(frozen=True)
class GunInventoryItem:
    item: object
    description: desc_codec.GunDescription

    @property
    def item_gid(self):
        return self.item.item_gid

    @property
    def template_id(self):
        return self.item.template_id


def source_pins():
    pins = desc_codec.source_pins()
    raw = (ROOT/SPLICE_CONTRACT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != SPLICE_SHA:
        raise ValueError('Changed inventory GunDesc splice contract')
    splice = json.loads(raw)
    if splice['kind'] != 'offline_inventory_gun_desc_splice_subset_contract_v1':
        raise ValueError('Unsupported inventory GunDesc splice contract')
    pins[SPLICE_CONTRACT] = SPLICE_SHA
    for relative, digest in splice['source_pins'].items():
        if hashlib.sha256((ROOT/relative).read_bytes()).hexdigest() != digest:
            raise ValueError('Changed inventory GunDesc splice source '+relative)
        pins[relative] = digest
    for relative, digest in FROZEN_MODULES.items():
        if hashlib.sha256((SERVER/relative).read_bytes()).hexdigest() != digest:
            raise ValueError('Frozen native inventory codec changed '+relative)
        pins['outputs/df-local-server/'+relative] = digest
    pins.update({'outputs/df-local-server/'+key: value
        for key, value in condition_codec.inventory_condition_source_pins().items()})
    pins['work/draft_inventory_gun_items.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return pins


def _gun_selector(reader):
    reader.read_bits(632)
    if reader.read_bool():
        reader.read_bytes(8)
        for width in (8, 4):
            count, = struct.unpack('<i', reader.read_bytes(4))
            if not 0 <= count <= MAX_NATIVE_ARRAY_COUNT:
                raise ValueError('Unbounded native stack prefix array')
            reader.read_bytes(count*width)
    for _ in range(2):
        if reader.read_bool():
            reader.read_bytes(8)
    return reader.position


def _identity(value):
    root = value.description.rows[0]
    if (root.item_id, root.gid) != (value.template_id, value.item_gid):
        raise ValueError('GunDesc root differs from original inventory identity')


def _write(writer, value, profile):
    if type(value) is not GunInventoryItem:
        condition_codec.write_inventory_item(writer, value, profile=profile)
        return
    raw = desc_codec.encode(value.description)
    _identity(value)
    stage = BitWriter(maximum_bits=writer.maximum_bits)
    condition_codec.write_inventory_item(stage, value.item, profile=profile)
    source = BitReader(stage.to_bytes(), bit_count=stage.bit_count)
    prefix = _gun_selector(source)
    source.position = 0
    stack_codec._copy_bits(source, writer, prefix)
    if source.read_bool():
        raise ValueError('Base item already has an unqualified GunDesc block')
    writer.write_bool(True)
    writer.write_bytes(raw)
    stack_codec._copy_bits(source, writer, source.remaining)


def _read_payload(reader):
    parts = []

    def take(size):
        value = reader.read_bytes(size)
        parts.append(value)
        if sum(map(len, parts)) > desc_codec.MAX_PAYLOAD:
            raise ValueError('Unbounded GunDesc payload')
        return value

    count, = struct.unpack('<B', take(1))
    if not 1 <= count <= desc_codec.MAX_ROWS:
        raise ValueError('Unbounded GunDesc row array')
    take(count*68)
    ids, values, zero_owner = struct.unpack('<iii', take(12))
    if (ids, values, zero_owner) != (0, 0, 1):
        raise ValueError('Unsupported GunDesc attributes or nonzero owner')
    count, = struct.unpack('<i', take(4))
    if not 0 <= count <= desc_codec.MAX_AMMO:
        raise ValueError('Unbounded GunDesc ammo array')
    for _ in range(count):
        header = take(32)
        player_count, = struct.unpack_from('<i', header, 28)
        if not 0 <= player_count <= desc_codec.MAX_CONTAIN_PLAYERS:
            raise ValueError('Unbounded GunDesc ammo owner array')
        take(player_count*8)
        take(4)
    take(36)
    take(72)
    raw = b''.join(parts)
    return desc_codec.decode(raw), len(raw)*8


def _read(reader, profile):
    start = reader.position
    prefix = _gun_selector(reader)-start
    if not reader.read_bool():
        reader.position = start
        return condition_codec.read_inventory_item(reader, profile=profile)
    description, removed = _read_payload(reader)
    tail = reader.position
    minimal = BitWriter()
    reader.position = start
    stack_codec._copy_bits(reader, minimal, prefix)
    minimal.write_bool(False)
    reader.position = tail
    stack_codec._copy_bits(reader, minimal, reader.remaining)
    source = BitReader(minimal.to_bytes(), bit_count=minimal.bit_count)
    value = condition_codec.read_inventory_item(source, profile=profile)
    reader.position = start+source.position+removed
    result = GunInventoryItem(value, description)
    _identity(result)
    return result


def write_inventory_item(writer, item, *, profile):
    stack_codec._qualify(writer, profile, BitWriter)
    source_pins()
    stage = BitWriter(maximum_bits=writer.maximum_bits)
    _write(stage, item, profile)
    writer.write_payload(stage.to_bytes(), stage.bit_count)
    return stage.bit_count


def read_inventory_item(reader, *, profile):
    stack_codec._qualify(reader, profile, BitReader)
    source_pins()
    start = reader.position
    try:
        return _read(reader, profile)
    except ValueError:
        reader.position = start
        raise


def write_inventory_custom_delta(writer, delta, *, profile):
    stack_codec._qualify(writer, profile, BitWriter)
    source_pins()
    stack_codec._delta(delta)
    stage = BitWriter(maximum_bits=writer.maximum_bits)
    stage.write_bool(False)
    stage.write_bytes(struct.pack('<4i', delta.array_replication_key, delta.base_replication_key,
        len(delta.deleted_ids), len(delta.changed)))
    for identity in delta.deleted_ids:
        stage.write_bytes(struct.pack('<i', identity))
    for element in delta.changed:
        stage.write_bytes(struct.pack('<i', element.element_id))
        _write(stage, element.item, profile)
    writer.write_payload(stage.to_bytes(), stage.bit_count)
    return stage.bit_count


def read_inventory_custom_delta(reader, *, profile):
    stack_codec._qualify(reader, profile, BitReader)
    source_pins()
    start = reader.position
    try:
        if reader.read_bool():
            raise ValueError('Unsupported network-v13 optimized delta branch')
        array_key, base_key, delete_count, change_count = struct.unpack('<4i', reader.read_bytes(16))
        if not 0 <= delete_count <= MAX_NATIVE_ARRAY_COUNT or not 0 <= change_count <= MAX_NATIVE_ARRAY_COUNT:
            raise ValueError('Unbounded native inventory delta arrays')
        deleted = tuple(struct.unpack('<i', reader.read_bytes(4))[0] for _ in range(delete_count))
        changed = tuple(InventoryFastArrayElement(struct.unpack('<i', reader.read_bytes(4))[0], _read(reader, profile))
            for _ in range(change_count))
        result = InventoryFastArrayDelta(array_key, base_key, deleted, changed)
        stack_codec._delta(result)
        return result
    except ValueError:
        reader.position = start
        raise
