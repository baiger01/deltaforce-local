"""Produce one ordinary owning inventory addition after a finite world transfer.

The caller supplies its actual ACK-committed key/items, queues the update after
the previous owning delivery, and advances that baseline only on its exact ACK.
This helper cannot reset the runtime key, queue packets, or commit a cursor.
"""
from dataclasses import dataclass
import hashlib
import json

from dfserver.legacy_ds_actor_fields import (ClassFieldEnvelope, NormalClassFieldProfile,
    build_class_field_content)
from dfserver.legacy_ds_bit_archive import BitWriter
from dfserver.legacy_ds_default_subobject import DefaultSubobjectUpdate
from dfserver.legacy_ds_inventory_items import InventoryFastArrayDelta
from dfserver.legacy_ds_inventory_gun import write_inventory_custom_delta
from dfserver.legacy_ds_inventory_state import SCHEMA_SHA256
import portable_finite_loot as finite
import portable_loot_box_codec as boxes
import portable_world_item_move_request as requests


@dataclass(frozen=True)
class InventoryMoveProjection:
    update: DefaultSubobjectUpdate
    expected_array_key: int
    array_key_after_ack: int
    authoritative_items: tuple
    command_gid: int


def source_pins():
    pins = requests.source_pins()
    pins.update(finite.source_pins())
    raw = (requests.ROOT / requests.CAPTURE).read_bytes()
    if hashlib.sha256(raw).hexdigest() != requests.PINS[requests.CAPTURE]:
        raise ValueError('The actual owning inventory metadata source changed')
    owner, = [row for row in json.loads(raw)['owners'] if row['scope'] == 'InventoryManager']
    field, = [row for node in owner['existing_driver_class']['cache_nodes'] for row in node['fields']
        if row['descriptor_name'] == 'RepItemArray']
    if (field['rep_index'], field['descriptor_representation']) != (7, 0) or field['incompatible']:
        raise ValueError('The actual owning inventory ItemArray receiver changed')
    relative = 'work/portable_world_inventory_delta.py'
    pins[relative] = hashlib.sha256((requests.ROOT / relative).read_bytes()).hexdigest()
    return pins


def project_addition(receipt, *, recipient_scope, pawn_guid, inventory_component_guid,
        committed_array_key, committed_items, authoritative_items):
    source_pins()
    if type(receipt) is not finite.TransferReceipt or recipient_scope != (receipt.match_id, receipt.player_id):
        raise ValueError('The exact current recipient transfer receipt is required')
    if type(committed_array_key) is not int or not 1 <= committed_array_key < (1 << 31) - 1:
        raise ValueError('The actual ACK-committed owning inventory key is required')
    boxes.validate_items(committed_items)
    boxes.validate_items(authoritative_items)
    element = receipt.destination_element
    if (any(existing.element_id == element.element_id or
            existing.item.item_gid == receipt.item_gid for existing in committed_items) or
            element.item.item_gid != receipt.item_gid or
            authoritative_items != committed_items + (element,)):
        raise ValueError('The authoritative whole-move state differs from this exact owning baseline')
    writer = BitWriter(maximum_bits=8192)
    next_key = committed_array_key + 1
    write_inventory_custom_delta(writer,
        InventoryFastArrayDelta(next_key, committed_array_key, (), (element,)), profile=boxes.PROFILE)
    block = build_class_field_content((ClassFieldEnvelope(7, writer.to_bytes(), writer.bit_count),),
        profile=NormalClassFieldProfile(53, False))
    update = DefaultSubobjectUpdate(pawn_guid, inventory_component_guid, 'InventoryManager',
        SCHEMA_SHA256, block.payload, block.payload_bit_count, False)
    return InventoryMoveProjection(update, committed_array_key, next_key,
        authoritative_items, receipt.cmd_gid)
